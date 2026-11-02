from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import subprocess
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from .catalog import Catalog
from .config import Settings
from .db import Database
from .security import ACCOUNT_RE, EXIT_RE, normalize_domain, public_ip, public_ipv4


def atomic(path: Path, content: str) -> bool:
    if path.exists() and path.read_text() == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    return True


class HostAdapter:
    def __init__(self, root: Path, *, enabled: bool = True, settings: Settings | None = None) -> None:
        self.root, self.enabled = root, enabled
        self.stats_socket = Path("/run/haproxy/smartdns-admin.sock")
        self.sources = Path("/etc/haproxy/smartdns-sources.acl")
        self.origins = Path("/etc/haproxy/smartdns-origins.acl")
        self.config_file = Path("/etc/haproxy/haproxy.cfg")
        self.service = "haproxy"
        self.nft_table = "smartdns"
        if settings:
            self.stats_socket = settings.haproxy_socket
            self.nft_table = settings.nft_table
        self.current_sources: set[str] | None = None
        self.current_expiries: dict[str, int] | None = None

    @staticmethod
    def run(args: list[str], **kwargs: Any) -> str:
        result = subprocess.run(args, text=True, capture_output=True, check=True, timeout=20, **kwargs)
        return result.stdout

    def runtime(self, command: str) -> str:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(str(self.stats_socket))
            sock.sendall((command + "\n").encode())
            sock.shutdown(socket.SHUT_WR)
            data = b""
            while part := sock.recv(65536):
                data += part
        return data.decode()

    def preview(self, patterns: list[str]) -> None:
        if not patterns or len(patterns) > 100_000:
            raise ValueError("Invalid origin rules")
        for pattern in patterns:
            if not pattern.startswith("^") or not pattern.endswith("$"):
                raise ValueError("Invalid origin pattern")
            prefix = r"^([a-z0-9-]+\.)*" if pattern.startswith(r"^([a-z0-9-]+\.)*") else "^"
            name = pattern[len(prefix) : -1].replace(r"\.", ".").replace(r"\-", "-")
            normalize_domain(name)
            if prefix + re.escape(name) + "$" != pattern:
                raise ValueError("Untrusted origin expression")
        if not self.enabled:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        candidate = self.root / "origins-preview.acl"
        atomic(candidate, "\n".join(patterns) + "\n")
        config = self.config_file.read_text()
        preview_config = self.root / "haproxy-preview.cfg"
        atomic(preview_config, config.replace(str(self.origins), str(candidate)))
        self.run(["haproxy", "-c", "-f", str(preview_config)])

    def replace_acl(self, path: Path, patterns: list[str]) -> None:
        reply = self.runtime("prepare acl " + str(path))
        match = re.search(r"New version created: (\d+)", reply)
        if not match:
            raise RuntimeError("HAProxy ACL transaction unavailable")
        version = match[1]
        reply = self.runtime(f"clear acl @{version} {path}")
        if reply.strip():
            raise RuntimeError("HAProxy ACL prepare failed")
        # ACL insertion has no multiline payload form. Batch bounded CLI commands instead.
        batch: list[str] = []
        size = 0
        for pattern in patterns:
            command = f"add acl @{version} {path} {pattern}"
            if size + len(command) > 6000 and batch:
                if self.runtime(";".join(batch)).strip():
                    raise RuntimeError("HAProxy ACL insertion failed")
                batch, size = [], 0
            batch.append(command)
            size += len(command) + 1
        if batch and self.runtime(";".join(batch)).strip():
            raise RuntimeError("HAProxy ACL insertion failed")
        reply = self.runtime(f"commit acl @{version} {path}")
        if reply.strip():
            raise RuntimeError("HAProxy ACL commit failed")

    def apply_patterns(self, patterns: list[str]) -> None:
        self.preview(patterns)
        if not self.enabled:
            return
        content = "\n".join(patterns) + "\n"
        if self.origins.read_text() != content:
            self.replace_acl(self.origins, patterns)
            atomic(self.origins, content)

    def apply_sources(self, expiries: dict[str, int]) -> None:
        if not self.enabled:
            return
        wanted = set(expiries)
        atomic(self.sources, "\n".join(sorted(wanted)) + "\n" if wanted else "192.0.2.0/32\n")
        if self.current_sources is None:
            reply = self.runtime("show acl " + str(self.sources))
            self.current_sources = set()
            for line in reply.splitlines():
                columns = line.split()
                if len(columns) >= 2 and columns[0].startswith("0x"):
                    self.current_sources.add(columns[1].removesuffix("/32"))
        if wanted != self.current_sources:
            self.replace_acl(self.sources, sorted(wanted))
            self.current_sources = wanted
        if self.current_expiries == expiries:
            return
        now = int(time.time())
        script = ""
        for family in (4, 6):
            elements = ", ".join(
                f"{ip} timeout {max(1, expiry - now)}s"
                for ip, expiry in sorted(expiries.items())
                if ipaddress.ip_address(ip).version == family
            )
            script += f"flush set inet {self.nft_table} activated_v{family}\n"
            if elements:
                script += f"add element inet {self.nft_table} activated_v{family} {{ {elements} }}\n"
        self.run(["nft", "-f", "-"], input=script)
        self.current_expiries = dict(expiries)


class AgentEngine:
    def __init__(self, settings: Settings, adapter: HostAdapter, *, state_dir: Path | None = None) -> None:
        self.settings, self.adapter = settings, adapter
        self.db = Database(settings.db_path)
        self.catalog = Catalog(self.db, settings.domain, settings.reserved_sni)
        self.state_dir = state_dir or settings.agent_state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.leases = self.state_dir / "leases.sqlite3"
        self.lease_store = Database(self.leases)
        with self.lease_store.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS leases(account_id TEXT,ip TEXT,exit_id TEXT,expires INTEGER,PRIMARY KEY(account_id,ip,exit_id))"
            )
        with self.lease_store.connect() as db:
            if "key_version" not in {r[1] for r in db.execute("PRAGMA table_info(leases)")}:
                db.execute("ALTER TABLE leases ADD COLUMN key_version INTEGER NOT NULL DEFAULT 0")
        self.lock = asyncio.Lock()
        self.last_tick = 0.0
        self.generation = -1
        self.applied_versions: dict[str, int] = {}
        self.last_error: str | None = None
        self.exit_health: dict[str, dict[str, Any]] = {}
        self.http = httpx.AsyncClient(timeout=8)
        self.route_ready = settings.forward_mode == "local"
        self.route_checked = 0.0
        self.filter_checked = 0.0
        self.route_error: str | None = None
        self.probe = httpx.AsyncClient(
            timeout=3, transport=httpx.AsyncHTTPTransport(local_address=settings.forward_source_ipv4 or None)
        )

    def ready(self) -> bool:
        return (
            self.last_tick > 0
            and time.monotonic() - self.last_tick <= 12
            and self.last_error is None
            and self.route_ready
        )

    def snapshot(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        with self.db.connect(readonly=True) as db:
            users = [
                dict(r)
                for r in db.execute(
                    "SELECT a.*,c.version FROM accounts a JOIN credentials c ON c.account_id=a.id WHERE a.status='active'"
                )
            ]
            exceptions = [
                dict(r)
                for r in db.execute(
                    "SELECT e.* FROM exceptions e JOIN accounts a ON a.id=e.account_id WHERE a.status='active'"
                )
            ]
            legacy = [
                dict(r)
                for r in db.execute(
                    "SELECT n.* FROM legacy_networks n JOIN accounts a ON a.id=n.account_id WHERE a.status='active' AND n.expires>?",
                    (int(time.time()),),
                )
            ]
        return users, exceptions, legacy

    async def sync_agh(
        self, users: list[dict[str, Any]], exceptions: list[dict[str, Any]], legacy: list[dict[str, Any]]
    ) -> None:
        root = self.settings.agh_control_url + "/control/"
        response = await self.http.get(root + "clients")
        response.raise_for_status()
        existing = response.json().get("clients") or []
        names = {"beta-" + u["id"] for u in users}
        # This instance is dedicated to SmartDNS; the original VPN resolver is separate.
        for client in existing:
            if client["name"] not in names:
                r = await self.http.post(root + "clients/delete", json={"name": client["name"]})
                r.raise_for_status()
        existing_by_name = {r["name"]: r for r in existing}
        for user in users:
            client = {
                "name": "beta-" + user["id"],
                "ids": [user["id"]],
                "use_global_settings": False,
                "filtering_enabled": bool(user["filtering"]),
                "use_global_blocked_services": True,
                "parental_enabled": False,
                "safebrowsing_enabled": False,
                "safe_search": {"enabled": False},
            }
            if client["name"] in existing_by_name:
                payload = {"name": client["name"], "data": client}
                endpoint = "clients/update"
            else:
                payload, endpoint = client, "clients/add"
            r = await self.http.post(root + endpoint, json=payload)
            r.raise_for_status()
        rules = [
            ("@@" if e["action"] == "allow" else "") + f"||{e['domain']}^$client={e['account_id']}"
            for e in exceptions
        ]
        r = await self.http.post(root + "filtering/set_rules", json={"rules": rules})
        r.raise_for_status()
        r = await self.http.post(
            root + "access/set",
            json={
                "allowed_clients": ["127.0.0.1"] + [u["id"] for u in users] + [n["ip"] for n in legacy],
                "disallowed_clients": [],
                "blocked_hosts": [],
            },
        )
        r.raise_for_status()

    def source_expiries(self, users: list[dict[str, Any]], legacy: list[dict[str, Any]]) -> dict[str, int]:
        now, active = int(time.time()), {u["id"] for u in users}
        with self.lease_store.connect() as db:
            db.execute("DELETE FROM leases WHERE expires<=?", (now,))
            for account_id in {r[0] for r in db.execute("SELECT DISTINCT account_id FROM leases")} - active:
                db.execute("DELETE FROM leases WHERE account_id=?", (account_id,))
            rows = db.execute(
                "SELECT ip,MAX(expires) FROM leases WHERE exit_id=? GROUP BY ip",
                (self.settings.local_exit_id,),
            ).fetchall()
        versions = {u["id"]: u["version"] for u in users}
        with self.lease_store.connect() as db:
            for row in db.execute("SELECT DISTINCT account_id,key_version FROM leases").fetchall():
                if versions.get(row[0]) != row[1]:
                    db.execute("DELETE FROM leases WHERE account_id=? AND key_version=?", tuple(row))
            rows = db.execute(
                "SELECT ip,MAX(expires) FROM leases WHERE exit_id=? GROUP BY ip",
                (self.settings.local_exit_id,),
            ).fetchall()
        expiries = {ip: expiry for ip, expiry in rows}
        for net in legacy:
            ip = public_ipv4(net["ip"])
            expiries[ip] = max(expiries.get(ip, 0), net["expires"])
        return expiries

    async def check_route(self) -> None:
        if self.settings.forward_mode == "local" or time.monotonic() - self.route_checked < 30:
            return
        try:
            response = await self.probe.get("https://api.ipify.org")
            response.raise_for_status()
            self.route_ready = response.text.strip() == self.settings.expected_egress_ipv4
            self.route_error = None if self.route_ready else "unexpected_egress"
        except httpx.HTTPError:
            self.route_ready, self.route_error = False, "egress_unreachable"
        self.route_checked = time.monotonic()

    async def _reconcile(self) -> None:
        await self.check_route()
        if self.adapter.enabled and time.monotonic() - self.filter_checked >= 15:
            health = await self.http.get(self.settings.agh_control_url + "/control/status", timeout=2)
            health.raise_for_status()
            self.filter_checked = time.monotonic()
        generation = self.db.generation()
        users, exceptions, legacy = self.snapshot()
        if generation != self.generation:
            if self.adapter.enabled:
                await self.sync_agh(users, exceptions, legacy)
            patterns = self.catalog.proxy_patterns()
            if patterns:
                await asyncio.to_thread(self.adapter.apply_patterns, patterns)
            new_versions = {u["id"]: u["version"] for u in users}
            for account_id, version in self.applied_versions.items():
                if new_versions.get(account_id) != version:
                    with self.lease_store.connect() as db:
                        db.execute("DELETE FROM leases WHERE account_id=?", (account_id,))
            self.applied_versions = new_versions
            self.generation = generation
        await asyncio.to_thread(self.adapter.apply_sources, self.source_expiries(users, legacy))
        self.last_tick, self.last_error = time.monotonic(), None

    async def reconcile(self) -> None:
        async with self.lock:
            try:
                await self._reconcile()
            except Exception as e:
                self.last_error = type(e).__name__
                raise

    async def grant(
        self, account_id: str, ip: str, exit_id: str, generation: int, credential_version: int | None = None
    ) -> bool:
        if not ACCOUNT_RE.fullmatch(account_id) or not EXIT_RE.fullmatch(exit_id):
            return False
        ip = public_ip(ip)
        async with self.lock:
            if self.generation != generation or not self.ready():
                await self._reconcile()
            with self.db.connect(readonly=True) as db:
                user = db.execute(
                    "SELECT a.status,c.version FROM accounts a JOIN credentials c ON c.account_id=a.id WHERE a.id=?",
                    (account_id,),
                ).fetchone()
                exit_row = db.execute(
                    "SELECT * FROM exits WHERE id=? AND enabled=1 AND healthy=1", (exit_id,)
                ).fetchone()
            if (
                not user
                or user["status"] != "active"
                or not exit_row
                or not self.route_ready
                or exit_id != self.settings.local_exit_id
            ):
                return False
            if credential_version is not None:
                if credential_version == 0:
                    with self.db.connect(readonly=True) as db:
                        allowed = db.execute(
                            "SELECT 1 FROM legacy_networks n WHERE n.account_id=? AND n.ip=? AND n.expires>? AND EXISTS(SELECT 1 FROM legacy_access l WHERE l.account_id=n.account_id AND l.expires>?)",
                            (account_id, ip, int(time.time()), int(time.time())),
                        ).fetchone()
                    if not allowed:
                        return False
                elif credential_version != user["version"]:
                    return False
            now = int(time.time())
            with self.lease_store.connect() as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM leases WHERE account_id=? AND expires>?", (account_id, now)
                ).fetchone()[0]
                known = db.execute(
                    "SELECT 1 FROM leases WHERE account_id=? AND ip=?", (account_id, ip)
                ).fetchone()
                if count >= 128 and not known:
                    return False
                db.execute(
                    "INSERT INTO leases(account_id,ip,exit_id,expires,key_version) VALUES(?,?,?,?,?) ON CONFLICT(account_id,ip,exit_id) DO UPDATE SET expires=excluded.expires,key_version=excluded.key_version",
                    (account_id, ip, exit_id, now + self.settings.lease_seconds, user["version"]),
                )
            users, _, legacy = self.snapshot()
            await asyncio.to_thread(self.adapter.apply_sources, self.source_expiries(users, legacy))
            return True

    async def loop(self) -> None:
        last_logged = None
        while True:
            try:
                await self.reconcile()
                last_logged = None
            except Exception as exc:
                if type(exc).__name__ != last_logged:
                    last_logged = type(exc).__name__
                    logging.getLogger(__name__).error("Agent reconciliation failed: %s", last_logged)
            await asyncio.sleep(3)


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: str = Field(max_length=32)
    ip: str = Field(max_length=45)
    exit_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    generation: int = Field(ge=1)
    credential_version: int = Field(ge=0)


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    patterns: list[str] = Field(max_length=100_000)


def create_agent(engine: AgentEngine) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(engine.loop())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await engine.http.aclose()
            await engine.probe.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    async def health() -> Response:
        return Response(status_code=200 if engine.ready() else 503)

    @app.get("/status")
    async def status() -> dict[str, Any]:
        with engine.lease_store.connect(readonly=True) as c:
            leases = [
                dict(r)
                for r in c.execute(
                    "SELECT account_id,ip,expires,key_version FROM leases WHERE expires>? LIMIT 2000",
                    (int(time.time()),),
                )
            ]
        return {
            "leases": leases,
            "ready": engine.ready(),
            "exits": {
                key: value
                | {"ready": value.get("ready") is True and time.monotonic() - value.get("checked_at", 0) < 10}
                for key, value in engine.exit_health.items()
            },
            "route": {"ready": engine.route_ready, "error": engine.route_error},
            "generation": engine.generation,
            "error": engine.last_error,
            "heartbeat_age": round(time.monotonic() - engine.last_tick, 1) if engine.last_tick else None,
        }

    @app.post("/grant")
    async def grant(body: Grant) -> dict[str, Any]:
        try:
            ready = await engine.grant(
                body.account_id, body.ip, body.exit_id, body.generation, body.credential_version
            )
        except (ValueError, OSError, httpx.HTTPError, subprocess.SubprocessError) as e:
            raise HTTPException(503, "Agent operation failed") from e
        if not ready:
            raise HTTPException(403, "Grant denied")
        return {"ready": True}

    @app.post("/preview")
    async def preview(body: Preview) -> dict[str, Any]:
        try:
            await asyncio.to_thread(engine.adapter.preview, body.patterns)
        except (ValueError, OSError, subprocess.SubprocessError) as e:
            raise HTTPException(400, "Catalog configuration rejected") from e
        return {"ready": True}

    @app.post("/reconcile")
    async def reconcile() -> dict[str, Any]:
        try:
            await engine.reconcile()
        except Exception as e:
            raise HTTPException(503, "Reconciliation failed") from e
        return {"ready": True}

    return app


def main() -> None:
    settings = Settings.load()
    managed = os.environ.get("SMARTDNS_MANAGE_HOST") == "1"
    state = Path(os.environ.get("SMARTDNS_AGENT_STATE", str(settings.agent_state_dir)))
    engine = AgentEngine(settings, HostAdapter(state, enabled=managed, settings=settings), state_dir=state)
    # Two private listeners: authenticated filesystem socket for RPC, loopback health-only listener.
    app = create_agent(engine)

    async def serve() -> None:
        settings.agent_socket.parent.mkdir(parents=True, exist_ok=True)
        config = uvicorn.Config(app, uds=str(settings.agent_socket), access_log=False, log_level="warning")
        health = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        @health.get("/health")
        async def check() -> Response:
            return Response(status_code=200 if engine.ready() else 503)

        health_config = uvicorn.Config(
            health,
            host="127.0.0.1",
            port=int(os.environ.get("SMARTDNS_HEALTH_PORT", "19108")),
            access_log=False,
            log_level="warning",
        )
        await asyncio.gather(uvicorn.Server(config).serve(), uvicorn.Server(health_config).serve())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
