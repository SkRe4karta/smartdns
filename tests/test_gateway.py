import asyncio
import base64
import ssl
import struct
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from smartdns.gateway import Gateway, create_gateway


class Resolver:
    async def post(self, url, *, content, headers):
        query = dns.message.from_wire(content)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        q = query.question[0]
        if q.rdtype == dns.rdatatype.A:
            address = "0.0.0.0" if q.name.to_text() == "doubleclick.net." else "93.184.216.34"
            response.answer.append(dns.rrset.from_text(q.name, 120, "IN", "A", address))
        elif q.rdtype == dns.rdatatype.AAAA:
            response.answer.append(dns.rrset.from_text(q.name, 120, "IN", "AAAA", "2606:4700:4700::1111"))
        return httpx.Response(200, content=response.to_wire(), request=httpx.Request("POST", url))

    async def aclose(self):
        pass


@pytest.fixture
def dns_stack(stack):
    engine = Gateway(stack["settings"], agent=stack["agent"], upstream=Resolver())
    key = stack["accounts"].connection(stack["owner"]["id"])["doh"].rsplit("/", 1)[1]
    return engine, key


@pytest.mark.asyncio
async def test_routing_preserves_blocking_and_normal_ipv6(stack, dns_stack):
    gateway, key = dns_stack
    for domain, qtype in [
        ("chatgpt.com", "A"),
        ("chatgpt.com", "AAAA"),
        ("chatgpt.com", "HTTPS"),
        ("chatgpt.com", "SVCB"),
        ("example.com", "AAAA"),
        ("doubleclick.net", "A"),
    ]:
        response = dns.message.from_wire(
            await gateway.query(key, "8.8.8.8", dns.message.make_query(domain, qtype).to_wire())
        )
        assert response.rcode() == dns.rcode.NOERROR
        if domain == "chatgpt.com":
            if qtype == "A":
                assert str(response.answer[0][0]) == stack["settings"].public_ipv4
                assert response.answer[0].ttl == 60
                assert not response.flags & dns.flags.AD
            else:
                assert not response.answer
        elif domain == "doubleclick.net":
            assert str(response.answer[0][0]) == "0.0.0.0"
        else:
            assert str(response.answer[0][0]) == "2606:4700:4700::1111"
    assert stack["agent"].grants


@pytest.mark.asyncio
async def test_agent_failure_fails_closed_for_routed_domains(stack, dns_stack):
    gateway, key = dns_stack
    stack["agent"].ready = False
    response = dns.message.from_wire(
        await gateway.query(key, "8.8.8.8", dns.message.make_query("chatgpt.com", "A").to_wire())
    )
    assert response.rcode() == dns.rcode.SERVFAIL and not response.answer
    response = dns.message.from_wire(
        await gateway.query(key, "8.8.8.8", dns.message.make_query("example.com", "A").to_wire())
    )
    assert response.rcode() == dns.rcode.NOERROR


@pytest.mark.asyncio
async def test_unknown_keys_and_multi_question_messages_are_rejected(dns_stack):
    gateway, key = dns_stack
    with pytest.raises(PermissionError):
        await gateway.query("k" + "a" * 52, "8.8.8.8", dns.message.make_query("example.com", "A").to_wire())
    for wire in [
        b"short",
        b"\0" * 12,
        dns.message.make_response(dns.message.make_query("example.com", "A")).to_wire(),
    ]:
        with pytest.raises((ValueError, dns.exception.DNSException)):
            await gateway.query(key, "8.8.8.8", wire)
    query = dns.message.make_query("example.com", "A")
    query.question.extend(dns.message.make_query("other.example", "A").question)
    with pytest.raises(ValueError):
        await gateway.query(key, "8.8.8.8", query.to_wire())


@pytest.mark.asyncio
async def test_doh_get_post_and_spoofed_headers(stack, dns_stack):
    gateway, key = dns_stack
    app = create_gateway(stack["settings"], engine=gateway, enable_dot=False)
    transport = httpx.ASGITransport(app=app, client=("8.8.4.4", 12345))
    async with httpx.AsyncClient(transport=transport, base_url="https://dns.example.test") as client:
        wire = dns.message.make_query("chatgpt.com", "A").to_wire()
        response = await client.post(
            "/dns-query/" + key,
            content=wire,
            headers={"Content-Type": "application/dns-message", "X-Real-IP": "1.1.1.1"},
        )
        assert response.status_code == 200
        assert stack["agent"].grants[-1][1] == "8.8.4.4"
        response = await client.get(
            "/dns-query/" + key, params={"dns": base64.urlsafe_b64encode(wire).decode().rstrip("=")}
        )
        assert response.status_code == 200
        assert client.headers.get("Authorization") is None
        assert response.headers["cache-control"] == "no-store"
        assert (await client.get("/dns-query/unknown", params={"dns": "xxx"})).status_code == 403
        assert (await client.get("/dns-query/" + key, params={"dns": "%%%"})).status_code == 400
        assert (await client.post("/dns-query/" + key, content=wire)).status_code == 415


@pytest.mark.asyncio
async def test_rotation_invalidates_existing_dns_key(stack, dns_stack):
    gateway, key = dns_stack
    assert await gateway.query(key, "8.8.8.8", dns.message.make_query("example.com", "A").to_wire())
    stack["accounts"].rotate(stack["owner"]["id"])
    with pytest.raises(PermissionError):
        await gateway.query(key, "8.8.8.8", dns.message.make_query("example.com", "A").to_wire())


def tls_files(tmp_path, domain):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName("*." + domain)]), False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


@pytest.mark.asyncio
async def test_real_dot_multiple_frames_and_revoke_open_connection(stack, tmp_path):
    cert, key_path = tls_files(tmp_path, stack["settings"].domain)
    settings = replace(stack["settings"], cert_file=cert, key_file=key_path)
    gateway = Gateway(settings, agent=stack["agent"], upstream=Resolver())
    key = stack["accounts"].connection(stack["friend"]["id"])["dot"].split(".")[0]
    server = await asyncio.start_server(gateway.dot, "127.0.0.1", 0, ssl=gateway.tls_context())
    port = server.sockets[0].getsockname()[1]
    context = ssl.create_default_context(cafile=str(cert))
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname=key + "." + settings.domain
        )
        for domain in ["example.com", "cloudflare.com"]:
            query = dns.message.make_query(domain, "A")
            wire = query.to_wire()
            frame = struct.pack("!H", len(wire)) + wire
            writer.write(frame[:1])
            await writer.drain()
            await asyncio.sleep(0.01)
            writer.write(frame[1:])
            await writer.drain()
            length = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 2))[0]
            response = dns.message.from_wire(await reader.readexactly(length))
            assert response.id == query.id and response.rcode() == dns.rcode.NOERROR
        stack["accounts"].status(stack["friend"]["id"], False)
        wire = dns.message.make_query("example.com", "A").to_wire()
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(2), 2) == b""
        writer.close()
        await writer.wait_closed()
        with pytest.raises((ssl.SSLError, ConnectionError)):
            await asyncio.open_connection(
                "127.0.0.1", port, ssl=context, server_hostname="unknown.example.test"
            )
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_recording_and_queue_pressure_do_not_invent_statistics(stack, dns_stack):
    gateway, key = dns_stack
    for domain in ["chatgpt.com", "doubleclick.net", "example.com"]:
        await gateway.query(key, "8.8.8.8", dns.message.make_query(domain, "A").to_wire())
    rows = []
    while not gateway.recorder.queue.empty():
        rows.append(gateway.recorder.queue.get_nowait())
    gateway.recorder.flush(rows)
    stats = stack["accounts"].stats(stack["owner"]["id"])
    assert stats["totals"] == {"total": 3, "blocked": 1, "proxied": 1, "errors": 0}
    assert stack["accounts"].stats(stack["friend"]["id"])["totals"]["total"] == 0


@pytest.mark.asyncio
async def test_cached_lease_never_hides_agent_failure(stack, dns_stack):
    gateway, key = dns_stack
    wire = dns.message.make_query("chatgpt.com", "A").to_wire()
    assert dns.message.from_wire(await gateway.query(key, "8.8.8.8", wire)).answer
    stack["agent"].ready = False
    response = dns.message.from_wire(await gateway.query(key, "8.8.8.8", wire))
    assert response.rcode() == dns.rcode.SERVFAIL and not response.answer


@pytest.mark.asyncio
async def test_legacy_plain_dns_requires_active_network_and_has_no_personal_stats(stack, dns_stack):
    import time

    from smartdns.security import digest

    gateway, _ = dns_stack
    wire = dns.message.make_query("example.com", "A").to_wire()
    assert await gateway.plain_answer("8.8.8.8", wire) is None
    with stack["db"].connect() as db:
        db.execute(
            "INSERT INTO legacy_access VALUES(?,?,?)",
            (digest("old-token"), stack["owner"]["id"], int(time.time()) + 3600),
        )
        db.execute(
            "INSERT INTO legacy_networks VALUES(?,?,?)",
            (stack["owner"]["id"], "8.8.8.8", int(time.time()) + 300),
        )
    assert dns.message.from_wire(await gateway.plain_answer("8.8.8.8", wire)).answer
    assert gateway.recorder.queue.empty()
    with stack["db"].connect() as db:
        db.execute("UPDATE legacy_networks SET expires=0")
    assert await gateway.plain_answer("8.8.8.8", wire) is None


@pytest.mark.asyncio
async def test_gateway_reassigns_service_when_selected_exit_cannot_acknowledge(stack, dns_stack):
    gateway, key = dns_stack
    with stack["db"].connect() as db:
        db.execute(
            "INSERT INTO exits(id,name,ingress_ip,egress_ip,country) VALUES('second','Second','8.8.4.4','8.8.4.4','FI')"
        )

    async def grant(account_id, ip, exit_id, generation):
        return exit_id == "second"

    stack["agent"].grant = grant
    response = dns.message.from_wire(
        await gateway.query(key, "1.1.1.1", dns.message.make_query("chatgpt.com", "A").to_wire())
    )
    assert str(response.answer[0][0]) == "8.8.4.4"
    assert gateway.pool.choose(stack["owner"]["id"], "openai")["id"] == "second"
