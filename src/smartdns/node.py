"""Optional egress node control plane. Its only network listener requires mTLS."""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from .agent import HostAdapter
from .security import public_ipv4


@dataclass(frozen=True)
class NodeSettings:
    ingress_ip: str
    egress_ip: str
    cert_file: str
    key_file: str
    client_ca: str
    bind_host: str = "0.0.0.0"
    control_port: int = 9443
    health_port: int = 19108


class Lease(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: str = Field(pattern=r"^u[0-9a-f]{12}$")
    ip: str = Field(max_length=45)
    expires: int


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generation: int = Field(ge=1)
    leases: list[Lease] = Field(max_length=1000)
    patterns: list[str] = Field(min_length=1, max_length=100_000)


class NodeEngine:
    def __init__(self, settings: NodeSettings, adapter: HostAdapter):
        self.settings, self.adapter = settings, adapter
        public_ipv4(settings.ingress_ip)
        public_ipv4(settings.egress_ip)
        self.generation = 0
        self.last_sync = 0.0
        self.last_cleanup = 0.0
        self.last_observation = 0.0
        self.observed_egress: str | None = None
        self.leases: list[Lease] = []
        self.lock = asyncio.Lock()
        self.error: str | None = None
        self.patterns: list[str] = []

    def ready(self) -> bool:
        now = time.monotonic()
        return bool(
            now - self.last_sync < 12
            and now - self.last_cleanup < 12
            and now - self.last_observation < 90
            and self.observed_egress == self.settings.egress_ip
            and self.error is None
        )

    def status(self) -> dict[str, Any]:
        return {
            "ready": self.ready(),
            "ingress_ip": self.settings.ingress_ip,
            "egress_ip": self.observed_egress,
            "generation": self.generation,
        }

    async def cleanup(self) -> None:
        expiries: dict[str, int] = {}
        now = int(time.time())
        for lease in self.leases:
            if lease.expires > now:
                expiries[lease.ip] = max(expiries.get(lease.ip, 0), lease.expires)
        await asyncio.to_thread(self.adapter.apply_sources, expiries)
        self.last_cleanup = time.monotonic()

    async def sync(self, body: Snapshot) -> dict[str, Any]:
        async with self.lock:
            if body.generation < self.generation:
                raise ValueError("Stale control generation")
            now = int(time.time())
            for lease in body.leases:
                public_ipv4(lease.ip)
                if not now - 5 <= lease.expires <= now + 1805:
                    raise ValueError("Invalid lease lifetime")
            try:
                if body.patterns != self.patterns:
                    await asyncio.to_thread(self.adapter.apply_patterns, body.patterns)
                    self.patterns = body.patterns
                self.leases = body.leases
                await self.cleanup()
                self.generation = body.generation
                self.last_sync = time.monotonic()
                self.error = None
            except Exception as exc:
                self.error = type(exc).__name__
                raise
            return self.status()

    async def observe(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                response = await client.get("https://api.ipify.org")
                response.raise_for_status()
                self.observed_egress = public_ipv4(response.text.strip())
                self.last_observation = time.monotonic()
        except httpx.HTTPError, ValueError:
            self.observed_egress = None

    async def loop(self) -> None:
        while True:
            if time.monotonic() - self.last_observation > 60:
                await self.observe()
            try:
                async with self.lock:
                    await self.cleanup()
            except Exception as exc:
                self.error = type(exc).__name__
            await asyncio.sleep(3)


def create_node(engine: NodeEngine) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(engine.loop())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/sync")
    async def sync(body: Snapshot) -> dict[str, Any]:
        try:
            return await engine.sync(body)
        except ValueError as exc:
            raise HTTPException(400, "Invalid control snapshot") from exc
        except Exception as exc:
            raise HTTPException(503, "Node configuration failed") from exc

    @app.get("/status")
    async def status() -> dict[str, Any]:
        return engine.status()

    return app


def main() -> None:
    settings = NodeSettings(**json.loads(Path(os.environ["SMARTDNS_NODE_CONFIG"]).read_text()))
    state = Path("/var/lib/smartdns-node")
    engine = NodeEngine(settings, HostAdapter(state, node=True))

    async def serve() -> None:
        control = uvicorn.Config(
            create_node(engine),
            host=settings.bind_host,
            port=settings.control_port,
            ssl_certfile=settings.cert_file,
            ssl_keyfile=settings.key_file,
            ssl_ca_certs=settings.client_ca,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            access_log=False,
            log_level="warning",
            proxy_headers=False,
        )
        health = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        @health.get("/health")
        async def check() -> Response:
            return Response(status_code=200 if engine.ready() else 503)

        monitor = uvicorn.Config(
            health, host="127.0.0.1", port=settings.health_port, access_log=False, log_level="warning"
        )
        await asyncio.gather(uvicorn.Server(control).serve(), uvicorn.Server(monitor).serve())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
