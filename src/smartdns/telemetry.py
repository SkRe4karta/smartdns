from __future__ import annotations

import asyncio
import time
from typing import Any

from .db import Database


class Recorder:
    """Bounded, batched telemetry; query serving never waits for a database writer."""

    def __init__(self, db: Database):
        self.db = db
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=5000)
        self.dropped = 0
        self.write_errors = 0
        self.last_flush: int | None = None

    def record(self, **event: Any) -> None:
        for key in ("client_ip", "transport", "key_version", "rcode", "reason"):
            event.setdefault(key, None)
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    def status(self) -> dict[str, Any]:
        return {
            "queued": self.queue.qsize(),
            "dropped": self.dropped,
            "write_errors": self.write_errors,
            "last_flush": self.last_flush,
        }

    def flush(self, rows: list[dict[str, Any]]) -> None:
        now = int(time.time())
        with self.db.connect() as db:
            # A query finishing during deletion must not resurrect the deleted user's history.
            db.execute("BEGIN IMMEDIATE")
            active_ids = {row[0] for row in db.execute("SELECT id FROM accounts")}
            rows = [row for row in rows if not row["account_id"] or row["account_id"] in active_ids]
            db.executemany(
                "INSERT INTO dns_events(account_id,at,domain,qtype,result,service_id,exit_id,elapsed_ms,"
                "client_ip,transport,key_version,rcode,reason) VALUES(:account_id,:at,:domain,:qtype,:result,"
                ":service_id,:exit_id,:elapsed_ms,:client_ip,:transport,:key_version,:rcode,:reason)",
                rows,
            )
            for row in rows:
                if row["account_id"]:
                    db.execute(
                        "INSERT INTO dns_buckets VALUES(?,?,1,?,?,?) ON CONFLICT(account_id,bucket) "
                        "DO UPDATE SET total=total+1,blocked=blocked+excluded.blocked,"
                        "proxied=proxied+excluded.proxied,errors=errors+excluded.errors",
                        (
                            row["account_id"],
                            row["at"] // 300 * 300,
                            int(row["result"] == "blocked"),
                            int(row["result"] == "proxied"),
                            int(row["result"] == "error"),
                        ),
                    )
                    db.execute("UPDATE accounts SET last_dns=? WHERE id=?", (row["at"], row["account_id"]))
                if row["client_ip"]:
                    db.execute(
                        "INSERT INTO network_buckets VALUES(?,?,?,?,?,1,?) "
                        "ON CONFLICT(account_id,ip,bucket) DO UPDATE SET "
                        "first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),"
                        "total=total+1,errors=errors+excluded.errors",
                        (
                            row["account_id"],
                            row["client_ip"],
                            row["at"] // 300 * 300,
                            row["at"],
                            row["at"],
                            int(row["result"] == "error"),
                        ),
                    )
            db.execute("DELETE FROM dns_events WHERE at<?", (now - 86400,))
            db.execute("DELETE FROM dns_buckets WHERE bucket<?", (now - 7 * 86400,))
            db.execute("DELETE FROM network_buckets WHERE bucket<?", (now - 7 * 86400,))
            db.execute("DELETE FROM dns_events WHERE id < (SELECT MAX(id)-500000 FROM dns_events)")
        self.last_flush = now

    async def run(self) -> None:
        last_cleanup = 0.0
        while True:
            await asyncio.sleep(0.5)
            rows: list[dict[str, Any]] = []
            while not self.queue.empty() and len(rows) < 1000:
                rows.append(self.queue.get_nowait())
            if rows or not last_cleanup or time.monotonic() - last_cleanup >= 60:
                try:
                    await asyncio.to_thread(self.flush, rows)
                    last_cleanup = time.monotonic()
                except Exception:
                    self.write_errors += 1
                    self.dropped += len(rows)
