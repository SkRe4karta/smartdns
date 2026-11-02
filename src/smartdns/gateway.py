from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import signal
import ssl
import struct
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import dns.edns
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
from .policy import CONNECTIVITY_NAMES
from .security import ACCOUNT_RE, DNS_KEY_RE, digest, public_ip
from .telemetry import Recorder


class Gateway:
    def __init__(self, settings: Settings, *, agent: Any = None, upstream: Any = None) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.catalog = Catalog(self.db, settings.domain, settings.reserved_sni)
        self.pool = ExitPool(self.db, settings.local_exit_id)
        self.agent = agent or AgentClient(settings)
        self.upstream = upstream or httpx.AsyncClient(
            timeout=settings.query_timeout,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=32),
        )
        self.recorder = Recorder(self.db)
        self.semaphore = asyncio.Semaphore(settings.dns_concurrency)
        self.rates: dict[str, tuple[int, int]] = {}
        self.dot_active = 0
        self.unauthenticated_failures = 0
        self.tls_rejected = 0
        self.unknown_rates: dict[str, float] = {}
        self.context: ssl.SSLContext | None = None
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
        if len(self.rates) > 10000:
            self.rates = {k: v for k, v in self.rates.items() if v[0] >= now - 1}
        second, count = self.rates.get(account_id, (now, 0))
        count = count + 1 if second == now else 1
        self.rates[account_id] = (now, count)
        return count > 100

    async def authorize(self, account: dict[str, Any], ip: str, exit_id: str) -> bool:
        try:
            source = public_ip(ip)
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
            return bool(
                await self.agent.grant(account["id"], source, exit_id, generation, account.get("version", 0))
            )
        cache_key = (account["id"], source, exit_id, generation)
        if self.lease_cache.get(cache_key, 0) > time.monotonic():
            return bool(await self.agent.is_ready(exit_id))
        if await self.agent.grant(account["id"], source, exit_id, generation, account.get("version", 0)):
            if len(self.lease_cache) > 10000:
                self.lease_cache = {k: v for k, v in self.lease_cache.items() if v > time.monotonic()}
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

    def failure(self, key: str, ip: str, transport: str, reason: str) -> None:
        account = self.account(key)
        if not account:
            self.unauthenticated_failures += 1
            now = time.monotonic()
            if self.unknown_rates.get(ip, 0) > now - 60:
                return
            if len(self.unknown_rates) >= 1000:
                self.unknown_rates = {k: v for k, v in self.unknown_rates.items() if v > now - 60}
                if len(self.unknown_rates) >= 1000:
                    return
            self.unknown_rates[ip] = now
        self.recorder.record(
            account_id=account["id"] if account else "",
            at=int(time.time()),
            domain="",
            qtype="",
            result="error",
            service_id=None,
            exit_id=None,
            elapsed_ms=0,
            client_ip=ip,
            transport=transport,
            key_version=account.get("version") if account else None,
            rcode=None,
            reason=reason,
        )

    async def query(
        self, key: str, ip: str, wire: bytes, *, record: bool = True, transport: str = "dot"
    ) -> bytes:
        account = await asyncio.to_thread(self.account, key)
        if not account:
            if record:
                self.failure(key, ip, transport, "unknown_key")
            raise PermissionError("Unknown DNS key")
        try:
            if not 12 <= len(wire) <= 65535:
                raise ValueError("Invalid DNS message size")
            query = dns.message.from_wire(wire)
            if query.flags & dns.flags.QR or query.opcode() != 0 or len(query.question) != 1:
                raise ValueError("Only single DNS queries are supported")
        except ValueError, dns.exception.DNSException:
            if record:
                self.failure(key, ip, transport, "malformed_query")
            raise
        question = query.question[0]
        domain = question.name.to_text().rstrip(".").lower()
        start = time.monotonic()
        result, service_id, exit_id, reason = "allowed", None, None, None
        response = dns.message.make_response(query)
        phase = "queue"
        if self.rate_limited(account["id"]):
            response.set_rcode(dns.rcode.REFUSED)
            result, reason = "error", "rate_limited"
        elif question.rdclass != 1 or question.rdtype in (
            dns.rdatatype.AXFR,
            dns.rdatatype.IXFR,
            dns.rdatatype.ANY,
        ):
            response.set_rcode(dns.rcode.REFUSED)
            result, reason = "refused", "unsupported_query"
        else:
            try:
                async with asyncio.timeout(self.settings.query_timeout), self.semaphore:
                    phase = "upstream"
                    upstream = await self.upstream.post(
                        self.settings.probe_resolver
                        if domain in CONNECTIVITY_NAMES
                        else f"{self.settings.agh_url}/dns-query/{account['id']}",
                        content=wire,
                        headers={
                            "Content-Type": "application/dns-message",
                            "Accept": "application/dns-message",
                        },
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
                        r.rdtype in (1, 28) and any(str(i) in ("0.0.0.0", "::") for i in r)
                        for r in response.answer
                    )
                    if blocked:
                        result, reason = "blocked", "filtered"
                    elif response.rcode() == dns.rcode.NOERROR:
                        service_id = await asyncio.to_thread(self.catalog.match, domain)
                        if service_id and question.rdtype in (1, 28, 64, 65):
                            phase = "admission"
                            chosen = await asyncio.to_thread(self.pool.choose, account["id"], service_id)
                            exit_id = chosen["id"] if chosen else None
                            ready = bool(chosen and await self.authorize(account, ip, chosen["id"]))
                            response = dns.message.make_response(query)
                            response.flags |= dns.flags.RA
                            if not ready:
                                response.set_rcode(dns.rcode.SERVFAIL)
                                result, reason = (
                                    "error",
                                    "admission_unavailable" if chosen else "exit_unavailable",
                                )
                            else:
                                assert chosen is not None
                                family = ipaddress.ip_address(ip).version
                                if question.rdtype == dns.rdatatype.A and family == 4:
                                    response.answer.append(
                                        dns.rrset.from_text(
                                            question.name, 60, "IN", "A", chosen["ingress_ip"]
                                        )
                                    )
                                elif (
                                    question.rdtype == dns.rdatatype.AAAA
                                    and family == 6
                                    and self.settings.public_ipv6
                                ):
                                    response.answer.append(
                                        dns.rrset.from_text(
                                            question.name, 60, "IN", "AAAA", self.settings.public_ipv6
                                        )
                                    )
                                result = "proxied"
                    elif response.rcode() == dns.rcode.NXDOMAIN:
                        result, reason = "nxdomain", "name_not_found"
                    else:
                        result, reason = "error", "upstream_dns_error"
            except (httpx.HTTPError, ValueError, dns.exception.DNSException, TimeoutError) as exc:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                result = "error"
                reason = (
                    "queue_timeout"
                    if phase == "queue"
                    else "admission_timeout"
                    if phase == "admission"
                    else "upstream_timeout"
                    if isinstance(exc, (TimeoutError, httpx.TimeoutException))
                    else "invalid_upstream"
                    if isinstance(exc, (ValueError, dns.exception.DNSException))
                    else "upstream_network"
                )
        if query.edns >= 0 and result in ("error", "blocked", "refused"):
            ede = (
                15
                if result == "blocked"
                else 18
                if response.rcode() == dns.rcode.REFUSED
                else 14
                if phase == "admission"
                else 23
            )
            response.use_edns(
                payload=min(max(query.payload, 512), 1232),
                options=[dns.edns.EDEOption(dns.edns.EDECode(ede), reason or "DNS error")],
            )
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
                client_ip=ip,
                transport=transport,
                key_version=account.get("version"),
                rcode=dns.rcode.to_text(response.rcode()),
                reason=reason,
            )
        return response.to_wire()

    async def plain_answer(self, ip: str, wire: bytes) -> bytes | None:
        key = self.legacy_key(ip)
        if not key:
            return None
        return await self.query(key, ip, wire, record=False, transport="plain")

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
        tasks: set[asyncio.Task[None]] = set()
        lock = asyncio.Lock()
        accepted = self.dot_active < self.settings.dot_connections
        if accepted:
            self.dot_active += 1
        try:
            if not accepted:
                return
            key = getattr(writer.get_extra_info("ssl_object"), "dns_key", "")
            source = str(ipaddress.ip_address(writer.get_extra_info("peername")[0]))
            if not await asyncio.to_thread(self.account, key):
                self.failure(key, source, "dot", "unknown_key")
                return

            async def answer(payload: bytes) -> None:
                try:
                    wire = await self.query(key, source, payload, transport="dot")
                    async with lock:
                        writer.write(struct.pack("!H", len(wire)) + wire)
                        await asyncio.wait_for(writer.drain(), 10)
                except OSError, PermissionError, ValueError, dns.exception.DNSException, TimeoutError:
                    writer.close()

            for _ in range(10000):
                head = await asyncio.wait_for(reader.readexactly(2), 120)
                length = struct.unpack("!H", head)[0]
                if length < 12:
                    self.failure(key, source, "dot", "malformed_query")
                    return
                payload = await asyncio.wait_for(reader.readexactly(length), 10)
                if len(tasks) >= self.settings.dot_pipeline:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                task = asyncio.create_task(answer(payload))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        except asyncio.IncompleteReadError, TimeoutError, OSError, ValueError:
            pass
        finally:
            if accepted:
                self.dot_active -= 1
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
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
                self.tls_rejected += 1
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            ssl_object.dns_key = key
            return None

        def select_context(ssl_object: Any, name: str | None, original: Any) -> int | None:
            if self.context is not None:
                ssl_object.context = self.context
            return sni(ssl_object, name, original)

        context.set_servername_callback(select_context)
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
        servers: list[asyncio.Server] = []
        plain_server = None
        udp_transport = None
        udp = LegacyUDP(gateway)
        if enable_dot:
            gateway.context = gateway.tls_context()
            for address in ["0.0.0.0", settings.public_ipv6] if settings.public_ipv6 else ["0.0.0.0"]:
                servers.append(
                    await asyncio.start_server(
                        gateway.dot,
                        address,
                        settings.dot_port,
                        ssl=gateway.context,
                        ssl_handshake_timeout=5,
                        backlog=128,
                    )
                )

            def reload_tls() -> None:
                try:
                    gateway.context = gateway.tls_context()
                except OSError, ssl.SSLError:
                    gateway.recorder.write_errors += 1

            asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, reload_tls)
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
            for server in servers:
                server.close()
                await server.wait_closed()
            if enable_dot:
                asyncio.get_running_loop().remove_signal_handler(signal.SIGHUP)
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
            remaining = []
            while not gateway.recorder.queue.empty():
                remaining.append(gateway.recorder.queue.get_nowait())
            if remaining:
                try:
                    await asyncio.to_thread(gateway.recorder.flush, remaining)
                except Exception:
                    gateway.recorder.dropped += len(remaining)
                    gateway.recorder.write_errors += 1
            await gateway.upstream.aclose()
            await gateway.agent.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway = gateway

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ready": True,
            "telemetry": gateway.recorder.status(),
            "dot_connections": gateway.dot_active,
            "unauthenticated_failures": gateway.unauthenticated_failures,
            "tls_rejected": gateway.tls_rejected,
        }

    @app.api_route("/dns-query/{key}", methods=["GET", "POST"])
    async def doh(key: str, request: Request) -> Response:
        peer = request.client.host if request.client else ""
        source = request.headers.get("x-real-ip", "") if peer == "127.0.0.1" else peer
        try:
            source = str(ipaddress.ip_address(source))
        except ValueError as exc:
            raise HTTPException(400, "Invalid source address") from exc
        if not await asyncio.to_thread(gateway.account, key):
            gateway.failure(key, source, "doh", "unknown_key")
            raise HTTPException(403, "DNS-профиль недействителен")
        if request.method == "GET":
            encoded = request.query_params.get("dns", "")
            if len(encoded) > 87384:
                gateway.failure(key, source, "doh", "malformed_query")
                raise HTTPException(413, "DNS message too large")
            try:
                payload = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            except ValueError as e:
                gateway.failure(key, source, "doh", "malformed_query")
                raise HTTPException(400, "Invalid DNS encoding") from e
        else:
            if request.headers.get("content-type", "").split(";")[0] != "application/dns-message":
                raise HTTPException(415, "Expected application/dns-message")
            if not request.headers.get("content-length", "0").isdigit():
                raise HTTPException(400, "Invalid content length")
            if int(request.headers.get("content-length", "0")) > 65535:
                gateway.failure(key, source, "doh", "malformed_query")
                raise HTTPException(413, "DNS message too large")
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 65535:
                    gateway.failure(key, source, "doh", "malformed_query")
                    raise HTTPException(413, "DNS message too large")
            payload = bytes(body)
        try:
            answer = await gateway.query(key, source, payload, transport="doh")
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
        limit_concurrency=settings.dns_concurrency,
        timeout_keep_alive=30,
    )


if __name__ == "__main__":
    main()
