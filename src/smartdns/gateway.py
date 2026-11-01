from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import ssl
import struct
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response

from .agent_client import AgentClient
from .catalog import Catalog, ExitPool
from .config import Settings
from .db import Database
from .security import ACCOUNT_RE, DNS_KEY_RE, digest, public_ipv4
from .telemetry import Recorder


class Gateway:
    def __init__(self, settings: Settings, *, agent: Any = None, upstream: Any = None) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.catalog = Catalog(self.db, settings.domain)
        self.pool = ExitPool(self.db)
        self.agent = agent or AgentClient(settings)
        self.upstream = upstream or httpx.AsyncClient(timeout=8, limits=httpx.Limits(max_connections=100))
        self.recorder = Recorder(self.db)
        self.semaphore = asyncio.Semaphore(150)
        self.rates: dict[str, tuple[int, int]] = {}
        self.lease_cache: dict[tuple[str, str, str, int], float] = {}

    def account(self, key: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self.db.connect(readonly=True) as db:
            if DNS_KEY_RE.fullmatch(key):
                row = db.execute(
                    "SELECT a.id,a.status,c.version FROM credentials c JOIN accounts a ON a.id=c.account_id WHERE c.secret_hash=? AND a.status='active'",
                    (digest(key),),
                ).fetchone()
                return {**dict(row), "legacy": False} if row else None
            if ACCOUNT_RE.fullmatch(key):
                row = db.execute(
                    "SELECT a.id,a.status FROM accounts a WHERE a.id=? AND a.status='active' AND EXISTS(SELECT 1 FROM legacy_access l WHERE l.account_id=a.id AND l.expires>?)",
                    (key, now),
                ).fetchone()
                return {**dict(row), "legacy": True} if row else None
        return None

    def rate_limited(self, account_id: str) -> bool:
        now = int(time.monotonic())
        second, count = self.rates.get(account_id, (now, 0))
        count = count + 1 if second == now else 1
        self.rates[account_id] = (now, count)
        return count > 100

    async def authorize(self, account: dict[str, Any], ip: str, exit_id: str) -> bool:
        try:
            source = public_ipv4(ip)
        except ValueError:
            return False
        generation = self.db.generation()
        if account["legacy"]:
            with self.db.connect(readonly=True) as db:
                permitted = db.execute(
                    "SELECT 1 FROM legacy_networks WHERE account_id=? AND ip=? AND expires>?",
                    (account["id"], source, int(time.time())),
                ).fetchone()
            if not permitted:
                return False
            return bool(await self.agent.grant(account["id"], source, exit_id, generation))
        cache_key = (account["id"], source, exit_id, generation)
        if self.lease_cache.get(cache_key, 0) > time.monotonic():
            return bool(await self.agent.is_ready(exit_id))
        if await self.agent.grant(account["id"], source, exit_id, generation):
            self.lease_cache[cache_key] = time.monotonic() + 30
            return True
        return False

    def legacy_key(self, ip: str) -> str | None:
        now = int(time.time())
        with self.db.connect(readonly=True) as db:
            row = db.execute(
                "SELECT a.id FROM accounts a JOIN legacy_networks n ON n.account_id=a.id "
                "WHERE a.status='active' AND n.ip=? AND n.expires>? AND EXISTS "
                "(SELECT 1 FROM legacy_access l WHERE l.account_id=a.id AND l.expires>?) ORDER BY a.id LIMIT 1",
                (ip, now, now),
            ).fetchone()
        return str(row[0]) if row else None

    async def query(self, key: str, ip: str, wire: bytes, *, record: bool = True) -> bytes:
        account = self.account(key)
        if not account:
            raise PermissionError("Unknown DNS key")
        if self.rate_limited(account["id"]):
            raise BlockingIOError("DNS request limit")
        if not 12 <= len(wire) <= 65535:
            raise ValueError("Invalid DNS message size")
        query = dns.message.from_wire(wire)
        if query.flags & dns.flags.QR or query.opcode() != 0 or len(query.question) != 1:
            raise ValueError("Only single DNS queries are supported")
        question = query.question[0]
        if question.rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR, dns.rdatatype.ANY):
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.REFUSED)
            return response.to_wire()
        domain = question.name.to_text().rstrip(".").lower()
        start = time.monotonic()
        result, service_id, exit_id = "allowed", None, None
        async with self.semaphore:
            try:
                upstream = await self.upstream.post(
                    f"{self.settings.agh_url}/dns-query/{account['id']}",
                    content=wire,
                    headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
                )
                upstream.raise_for_status()
                response = dns.message.from_wire(upstream.content)
                if (
                    response.id != query.id
                    or response.question != query.question
                    or not response.flags & dns.flags.QR
                ):
                    raise ValueError("Invalid upstream response")
                blocked = any(
                    r.rdtype in (1, 28) and any(str(item) in ("0.0.0.0", "::") for item in r)
                    for r in response.answer
                )
                if blocked:
                    result = "blocked"
                elif response.rcode() == dns.rcode.NOERROR:
                    service_id = self.catalog.match(domain)
                    if service_id and question.rdtype in (1, 28, 64, 65):
                        chosen = None
                        ready = False
                        excluded: set[str] = set()
                        for _ in range(8):
                            chosen = self.pool.choose(account["id"], service_id, excluded=excluded)
                            if not chosen:
                                break
                            exit_id = chosen["id"]
                            ready = await self.authorize(account, ip, exit_id)
                            if ready or not await self.agent.is_ready():
                                break
                            excluded.add(exit_id)
                        response = dns.message.make_response(query)
                        response.flags |= dns.flags.RA
                        if not ready:
                            response.set_rcode(dns.rcode.SERVFAIL)
                            result = "error"
                        else:
                            if question.rdtype == dns.rdatatype.A:
                                assert chosen is not None
                                response.answer.append(
                                    dns.rrset.from_text(question.name, 60, "IN", "A", chosen["ingress_ip"])
                                )
                            result = "proxied"
                else:
                    result = "error" if response.rcode() == dns.rcode.SERVFAIL else "allowed"
            except httpx.HTTPError, ValueError, dns.exception.DNSException:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                result = "error"
        if record:
            self.recorder.record(
                account_id=account["id"],
                at=int(time.time()),
                domain=domain,
                qtype=dns.rdatatype.to_text(question.rdtype),
                result=result,
                service_id=service_id,
                exit_id=exit_id,
                elapsed_ms=round((time.monotonic() - start) * 1000, 2),
            )
        return response.to_wire()

    async def plain_answer(self, ip: str, wire: bytes) -> bytes | None:
        key = self.legacy_key(ip)
        if not key:
            return None
        return await self.query(key, ip, wire, record=False)

    async def plain_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            source = writer.get_extra_info("peername")[0]
            for _ in range(1000):
                length = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 30))[0]
                if length < 12:
                    return
                wire = await asyncio.wait_for(reader.readexactly(length), 10)
                answer = await self.plain_answer(source, wire)
                if answer is None:
                    return
                writer.write(struct.pack("!H", len(answer)) + answer)
                await asyncio.wait_for(writer.drain(), 10)
        except (
            OSError,
            ValueError,
            TimeoutError,
            asyncio.IncompleteReadError,
            BlockingIOError,
            dns.exception.DNSException,
        ):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def dot(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            key = getattr(ssl_obj, "dns_key", "")
            if not self.account(key):
                return
            peer = writer.get_extra_info("peername")
            source = peer[0]
            for _ in range(10000):
                head = await asyncio.wait_for(reader.readexactly(2), timeout=120)
                length = struct.unpack("!H", head)[0]
                if length < 12:
                    return
                payload = await asyncio.wait_for(reader.readexactly(length), timeout=10)
                answer = await self.query(key, source, payload)
                writer.write(struct.pack("!H", len(answer)) + answer)
                await asyncio.wait_for(writer.drain(), timeout=10)
        except (
            asyncio.IncompleteReadError,
            TimeoutError,
            PermissionError,
            BlockingIOError,
            ValueError,
            OSError,
            dns.exception.DNSException,
        ):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()

    def tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.settings.cert_file, self.settings.key_file)

        def sni(ssl_object: Any, name: str | None, _: Any) -> int | None:
            suffix = "." + self.settings.domain
            key = name[: -len(suffix)] if name and name.endswith(suffix) else ""
            if not (DNS_KEY_RE.fullmatch(key) or ACCOUNT_RE.fullmatch(key)):
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            ssl_object.dns_key = key
            return None

        context.set_servername_callback(sni)
        return context


class LegacyUDP(asyncio.DatagramProtocol):
    def __init__(self, gateway: Gateway):
        self.gateway = gateway
        self.transport: Any = None
        self.tasks: set[asyncio.Task[None]] = set()

    def connection_made(self, transport: Any) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        if len(self.tasks) >= 100 or not 12 <= len(data) <= 4096:
            return
        task = asyncio.create_task(self.answer(data, address))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def answer(self, data: bytes, address: tuple[str, int]) -> None:
        try:
            answer = await self.gateway.plain_answer(address[0], data)
            if answer is None:
                return
            query = dns.message.from_wire(data)
            max_size = min(1232, max(512, query.payload))
            if len(answer) > max_size:
                response = dns.message.make_response(query)
                response.flags |= dns.flags.TC
                answer = response.to_wire()
            self.transport.sendto(answer, address)
        except OSError, ValueError, PermissionError, BlockingIOError, dns.exception.DNSException:
            return


def create_gateway(settings: Settings, *, engine: Gateway | None = None, enable_dot: bool = True) -> FastAPI:
    gateway = engine or Gateway(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(gateway.recorder.run())
        server = None
        plain_server = None
        udp_transport = None
        udp = LegacyUDP(gateway)
        if enable_dot:
            server = await asyncio.start_server(
                gateway.dot,
                "0.0.0.0",
                settings.dot_port,
                ssl=gateway.tls_context(),
                ssl_handshake_timeout=10,
                limit=131072,
                backlog=256,
            )
        if settings.plain_dns_enabled:
            plain_server = await asyncio.start_server(
                gateway.plain_tcp, settings.public_ipv4, settings.plain_dns_port
            )
            udp_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: udp, local_addr=(settings.public_ipv4, settings.plain_dns_port)
            )
        try:
            yield
        finally:
            if server:
                server.close()
                await server.wait_closed()
            if plain_server:
                plain_server.close()
                await plain_server.wait_closed()
            if udp_transport:
                udp_transport.close()
            for pending in udp.tasks:
                pending.cancel()
            if udp.tasks:
                await asyncio.gather(*udp.tasks, return_exceptions=True)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await gateway.upstream.aclose()
            await gateway.agent.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway = gateway

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ready": True, "stats_dropped": gateway.recorder.dropped}

    @app.api_route("/dns-query/{key}", methods=["GET", "POST"])
    async def doh(key: str, request: Request) -> Response:
        if not gateway.account(key):
            raise HTTPException(403, "DNS-профиль недействителен")
        if request.method == "GET":
            encoded = request.query_params.get("dns", "")
            if len(encoded) > 87384:
                raise HTTPException(413, "DNS message too large")
            try:
                payload = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            except ValueError as e:
                raise HTTPException(400, "Invalid DNS encoding") from e
        else:
            if request.headers.get("content-type", "").split(";")[0] != "application/dns-message":
                raise HTTPException(415, "Expected application/dns-message")
            if int(request.headers.get("content-length", "0")) > 65535:
                raise HTTPException(413, "DNS message too large")
            payload = await request.body()
        peer = request.client.host if request.client else ""
        source = request.headers.get("x-real-ip", "") if peer == "127.0.0.1" else peer
        try:
            ipaddress.ip_address(source)
            answer = await gateway.query(key, source, payload)
        except PermissionError as e:
            raise HTTPException(403, "DNS-профиль отключён") from e
        except BlockingIOError as e:
            raise HTTPException(429, "DNS request limit") from e
        except (ValueError, dns.exception.DNSException) as e:
            raise HTTPException(400, "Invalid DNS query") from e
        return Response(answer, media_type="application/dns-message", headers={"Cache-Control": "no-store"})

    return app


def main() -> None:
    settings = Settings.load()
    uvicorn.run(
        create_gateway(settings),
        host="127.0.0.1",
        port=settings.gateway_port,
        access_log=False,
        log_level="warning",
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
