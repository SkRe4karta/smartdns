import time
from dataclasses import replace

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest

from smartdns.gateway import Gateway
from smartdns.mfa import code_at
from smartdns.telemetry import Recorder


def test_totp_challenge_replay_and_recovery(client, stack):
    setup = client.post("/api/v1/auth/totp/setup", json={"password": "owner-password-12345"}).json()
    now = int(time.time()) // 30
    enabled = client.post("/api/v1/auth/totp/enable", json={"code": code_at(setup["secret"], now)})
    assert enabled.status_code == 200
    codes = enabled.json()["recovery_codes"]
    assert len(codes) == 8
    client.post("/api/v1/auth/logout")
    response = client.post("/api/v1/auth/login", json={"login": "owner", "password": "owner-password-12345"})
    challenge = response.json()["challenge"]
    assert client.get("/api/v1/me").status_code == 401
    assert (
        client.post(
            "/api/v1/auth/totp/verify", json={"challenge": challenge, "code": code_at(setup["secret"], now)}
        ).status_code
        == 401
    )
    assert (
        client.post("/api/v1/auth/totp/verify", json={"challenge": challenge, "code": codes[0]}).status_code
        == 200
    )
    assert (
        client.post("/api/v1/auth/totp/verify", json={"challenge": challenge, "code": codes[0]}).status_code
        == 401
    )
    with stack["db"].connect(readonly=True) as db:
        assert db.execute("SELECT secret FROM totp").fetchone()[0] != setup["secret"]
        assert db.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 7


def test_admin_telemetry_filters_retention_and_credentials(client, friend_client, stack):
    recorder = Recorder(stack["db"])
    now = int(time.time())
    row = dict(
        account_id=stack["friend"]["id"],
        at=now,
        domain="fixture.example",
        qtype="A",
        result="error",
        service_id=None,
        exit_id=None,
        elapsed_ms=12.5,
        client_ip="8.8.8.8",
        transport="dot",
        key_version=1,
        rcode="SERVFAIL",
        reason="upstream_timeout",
    )
    recorder.flush([row, row | {"at": now - 90000}])
    rows = client.get("/api/v1/admin/dns-events?ip=8.8.8.8&result=error&limit=1").json()
    assert len(rows["events"]) == 1 and rows["events"][0]["username"] == "friend"
    assert rows["events"][0]["reason"] == "upstream_timeout"
    summary = client.get("/api/v1/admin/overview?days=1").json()
    assert summary["totals"]["errors"] == 1
    networks = client.get("/api/v1/admin/users/" + stack["friend"]["id"] + "/networks").json()
    assert networks["networks"][0]["total"] == 2
    assert friend_client.get("/api/v1/admin/dns-events").status_code == 401
    assert client.get("/api/v1/admin/dns-events?limit=1000").status_code == 400
    assert "encrypted_secret" not in str(rows) and "secret_hash" not in str(rows)


@pytest.mark.asyncio
async def test_dual_stack_routed_family_and_error_attribution(stack):
    async def reply(request):
        query = dns.message.from_wire(request.content)
        answer = dns.message.make_response(query)
        answer.flags |= dns.flags.RA
        if query.question[0].rdtype == 1:
            answer.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "93.184.216.34"))
        return httpx.Response(200, content=answer.to_wire())

    settings = replace(stack["settings"], public_ipv6="2606:4700:4700::1111")
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(reply))
    gateway = Gateway(settings, agent=stack["agent"], upstream=upstream)
    key = stack["accounts"].connection(stack["friend"]["id"])["doh"].rsplit("/", 1)[1]
    for source, qtype, expected in [
        ("8.8.8.8", "A", settings.public_ipv4),
        ("8.8.8.8", "AAAA", None),
        ("2001:4860:4860::8888", "AAAA", settings.public_ipv6),
        ("2001:4860:4860::8888", "A", None),
    ]:
        response = dns.message.from_wire(
            await gateway.query(key, source, dns.message.make_query("chatgpt.com", qtype).to_wire())
        )
        assert response.rcode() == 0
        assert (str(response.answer[0][0]) if response.answer else None) == expected
    stack["agent"].ready = False
    gateway.lease_cache.clear()
    response = dns.message.from_wire(
        await gateway.query(
            key,
            "8.8.8.8",
            dns.message.make_query("chatgpt.com", "A", use_edns=True).to_wire(),
            transport="doh",
        )
    )
    assert response.rcode() == dns.rcode.SERVFAIL and response.options
    events = []
    while not gateway.recorder.queue.empty():
        events.append(gateway.recorder.queue.get_nowait())
    gateway.recorder.flush(events)
    assert events[-1]["reason"] == "admission_unavailable" and events[-1]["transport"] == "doh"
    assert events[-1]["client_ip"] == "8.8.8.8"
    await upstream.aclose()
