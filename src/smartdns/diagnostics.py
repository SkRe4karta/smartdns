"""Read-only administrator projections. Credentials are deliberately absent."""

from __future__ import annotations

import ipaddress
import time
from typing import Any

from .db import Database


def overview(db: Database, days: int) -> dict[str, Any]:
    since = int(time.time()) - days * 86400
    with db.connect(readonly=True) as c:
        buckets = [
            dict(r)
            for r in c.execute(
                "SELECT bucket AS at,SUM(total) total,SUM(blocked) blocked,SUM(proxied) proxied,"
                "SUM(errors) errors FROM dns_buckets WHERE bucket>=? GROUP BY bucket ORDER BY bucket",
                (since,),
            )
        ]
        users = c.execute("SELECT COUNT(*) FROM accounts WHERE status='active'").fetchone()[0]
        active = c.execute(
            "SELECT COUNT(DISTINCT account_id) FROM dns_buckets WHERE bucket>=?", (since,)
        ).fetchone()[0]
        recent = [
            dict(r)
            for r in c.execute(
                "SELECT e.id,e.at,a.login username,e.client_ip,e.domain,e.qtype,e.result,e.rcode,e.reason,"
                "e.elapsed_ms,e.key_version,e.transport FROM dns_events e LEFT JOIN accounts a ON a.id=e.account_id "
                "WHERE e.result='error' ORDER BY e.id DESC LIMIT 10"
            )
        ]
        latency = c.execute(
            "SELECT AVG(elapsed_ms) FROM dns_events WHERE at>=? AND account_id!=''",
            (max(since, int(time.time()) - 86400),),
        ).fetchone()[0]
    return {
        "buckets": buckets,
        "totals": {k: sum(r[k] for r in buckets) for k in ("total", "blocked", "proxied", "errors")},
        "users": users,
        "active_users": active,
        "mean_dns_ms": round(latency, 2) if latency is not None else None,
        "recent_errors": recent,
    }


def events(
    db: Database,
    *,
    account_id: str | None = None,
    ip: str | None = None,
    result: str | None = None,
    transport: str | None = None,
    rcode: str | None = None,
    since: int | None = None,
    until: int | None = None,
    cursor: int | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    clauses = ["e.at>=?"]
    values: list[Any] = [max(since or 0, int(time.time()) - 86400)]
    if ip:
        ip = str(ipaddress.ip_address(ip))
    for column, value in [
        ("account_id", account_id),
        ("client_ip", ip),
        ("result", result),
        ("transport", transport),
        ("rcode", rcode),
    ]:
        if value is not None:
            clauses.append("e." + column + "=?")
            values.append(value)
    for column, operator, bound in [("at", "<=", until), ("id", "<", cursor)]:
        if bound is not None:
            clauses.append("e." + column + operator + "?")
            values.append(bound)
    with db.connect(readonly=True) as c:
        rows = [
            dict(r)
            for r in c.execute(
                "SELECT e.*,a.login username FROM dns_events e LEFT JOIN accounts a ON a.id=e.account_id WHERE "  # noqa: S608 -- columns/operators are local constants; all inputs are bound
                + " AND ".join(clauses)
                + " ORDER BY e.id DESC LIMIT ?",
                (*values, limit + 1),
            )
        ]
    more = len(rows) > limit
    return {"events": rows[:limit], "next_cursor": rows[limit - 1]["id"] if more else None}


def networks(db: Database, account_id: str, days: int) -> list[dict[str, Any]]:
    with db.connect(readonly=True) as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT ip,MIN(first_seen) first_seen,MAX(last_seen) last_seen,SUM(total) total,SUM(errors) errors "
                "FROM network_buckets WHERE account_id=? AND bucket>=? GROUP BY ip ORDER BY last_seen DESC LIMIT 200",
                (account_id, int(time.time()) - days * 86400),
            )
        ]
