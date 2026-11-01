"""Real-component staging acceptance; secrets stay in the root-only fixture file."""

import argparse
import asyncio
import json
import os
import secrets
import ssl
import statistics
import struct
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import dns.message
import dns.rcode
import httpx

from smartdns.accounts import Accounts
from smartdns.agent_client import AgentClient
from smartdns.config import Settings
from smartdns.db import Database


def command(*args):
    result = subprocess.run(args, check=True, text=True, capture_output=True, timeout=30)
    return result.stdout.strip()


def snapshot():
    result = {"available_kib": 0, "services": {}}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            result["available_kib"] = int(line.split()[1])
    for name in [
        "smartdns-stage-api",
        "smartdns-stage-agent",
        "smartdns-stage-gateway",
        "smartdns-node-haproxy",
    ]:
        base = Path("/sys/fs/cgroup/system.slice") / (name + ".service")
        if base.exists():
            result["services"][name] = {
                k: (base / k).read_text().strip()
                for k in ["memory.current", "memory.peak", "memory.events", "cpu.stat"]
            }
    for name in result["services"]:
        result["services"][name]["restarts"] = int(
            command("systemctl", "show", name, "--property=NRestarts", "--value")
        )
    info = json.loads(command("docker", "inspect", "smartdns-beta-stage-filter"))[0]
    filter_cgroup = Path("/sys/fs/cgroup") / Path(
        "/proc", str(info["State"]["Pid"]), "cgroup"
    ).read_text().strip().split("::", 1)[1].lstrip("/")
    result["filter"] = {
        "restarts": info["RestartCount"],
        **{
            name: (filter_cgroup / name).read_text().strip()
            for name in ["memory.current", "memory.peak", "memory.events", "cpu.stat"]
        },
    }
    result["containers"] = json.loads(
        command("docker", "stats", "--no-stream", "--format", "{{json .}}")
        .replace("\n", ",")
        .join(["[", "]"])
    )
    result["vpn_state"] = command(
        "docker",
        "inspect",
        "remnanode",
        "amnezia-awg2",
        "marusia-awg-backbone",
        "--format",
        "{{.Name}} {{.State.Running}} {{.RestartCount}}",
    )
    return result


async def main():
    os.umask(0o007)
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, choices=range(1, 61), default=60)
    args = parser.parse_args()
    settings = Settings.load()
    root = settings.data_dir.parent
    db = Database(settings.db_path)
    accounts = Accounts(settings, db)
    users = accounts.list()
    password = secrets.token_urlsafe(28)
    owner = next(user for user in users if user["role"] == "admin")
    accounts.setup(accounts.invite(owner["id"], recovery=True).split("#")[1], password)
    for i in range(29):
        login = f"stage-{i:02}"
        if not any(user["login"] == login for user in users):
            invite = accounts.create(login, "Staging fixture")
            accounts.setup(invite["setup_url"].split("#")[1], secrets.token_urlsafe(28))
    users = accounts.list()
    assert len(users) == 30
    profiles = [accounts.connection(user["id"]) for user in users]
    fixture = root / "stage-fixtures.json"
    fixture.write_text(
        json.dumps({"owner_login": owner["login"], "password": password, "profiles": profiles})
    )
    fixture.chmod(0o600)
    control = AgentClient(settings)
    for _attempt in range(10):
        if await control.reconcile():
            break
        await asyncio.sleep(1)
    else:
        raise AssertionError("agent reconciliation")
    await asyncio.sleep(3)
    assert (await control.status())["ready"], "agent readiness"

    async def sni(request):
        request.extensions["sni_hostname"] = settings.domain

    transport = httpx.AsyncHTTPTransport(
        local_address=settings.public_ipv4,
        limits=httpx.Limits(max_connections=80, max_keepalive_connections=80),
    )
    async with httpx.AsyncClient(
        transport=transport,
        timeout=20,
        base_url="https://127.0.0.1:11444",
        headers={"Host": settings.domain + ":11444", "Origin": settings.public_url},
        event_hooks={"request": [sni]},
        trust_env=False,
    ) as client:
        response = await client.post(
            "/api/v1/auth/login", json={"login": owner["login"], "password": password}
        )
        assert response.status_code == 200, "password login"
        response = await client.get("/api/v1/me")
        assert response.status_code == 200
        csrf = response.json()["csrf"]
        client.headers["X-CSRF-Token"] = csrf
        assert (await client.get("/api/v1/auth/options")).json()["telegram"] is False

        async def query(profile, domain="example.com", qtype="A"):
            response = await client.post(
                "/dns-query/" + profile["doh"].rsplit("/", 1)[1],
                content=dns.message.make_query(domain, qtype).to_wire(),
                headers={"Content-Type": "application/dns-message"},
            )
            assert response.status_code == 200, f"DNS HTTP {response.status_code}"
            return dns.message.from_wire(response.content)

        assert (await query(profiles[0])).rcode() == dns.rcode.NOERROR
        routed = await query(profiles[0], "chatgpt.com")
        assert str(routed.answer[0][0]) == settings.public_ipv4
        for qtype in ["AAAA", "HTTPS", "SVCB"]:
            response = await query(profiles[0], "chatgpt.com", qtype)
            assert response.rcode() == dns.rcode.NOERROR and not response.answer
        v6 = await query(profiles[0], "cloudflare.com", "AAAA")
        assert v6.answer
        blocked = await query(profiles[0], "doubleclick.net")
        assert any(str(item) == "0.0.0.0" for row in blocked.answer for item in row), "ad filtering"
        unknown = await client.post(
            "/dns-query/k" + "a" * 52,
            content=dns.message.make_query("example.com", "A").to_wire(),
            headers={"Content-Type": "application/dns-message"},
        )
        assert unknown.status_code == 403
        # DoT runs over real TLS and reuses one connection for several framed messages.
        context = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            1853,
            local_addr=(settings.public_ipv4, 0),
            ssl=context,
            server_hostname=profiles[0]["dot"],
        )
        for domain in ["example.com", "chatgpt.com"]:
            wire = dns.message.make_query(domain, "A").to_wire()
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            length = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 10))[0]
            assert dns.message.from_wire(await reader.readexactly(length)).rcode() == dns.rcode.NOERROR
        writer.close()
        await writer.wait_closed()
        # Temporary diagnostic route verifies the actual exit address through HAProxy.
        with db.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO route_overrides VALUES('api.ipify.org','exact','proxy','openai')"
            )
            db.bump(connection)
        assert await control.reconcile()
        await asyncio.sleep(3)
        assert (await query(profiles[0], "api.ipify.org")).answer

        def exit_probe():
            return command(
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "8",
                "--noproxy",
                "*",
                "--interface",
                settings.public_ipv4,
                "--connect-to",
                "api.ipify.org:443:127.0.0.1:11443",
                "https://api.ipify.org",
            )

        assert await asyncio.to_thread(exit_probe) == settings.public_ipv4, "real HTTPS egress"
        before = snapshot()
        report = {"functional": "passed", "telegram": "deferred and disabled", "before": before}
        # A suspended agent must close the proxy while ordinary resolution continues.
        command("systemctl", "kill", "--signal=STOP", "smartdns-stage-agent")
        try:
            await asyncio.sleep(5)
            try:
                await asyncio.to_thread(exit_probe)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("proxy stayed open while agent was suspended")
            assert (await query(profiles[0])).rcode() == dns.rcode.NOERROR
            assert (await query(profiles[0], "chatgpt.com")).rcode() == dns.rcode.SERVFAIL
        finally:
            command("systemctl", "kill", "--signal=CONT", "smartdns-stage-agent")
        await asyncio.sleep(5)
        assert await control.reconcile()
        assert await asyncio.to_thread(exit_probe) == settings.public_ipv4
        report["watchdog_suspend"] = "passed"
        command("systemctl", "restart", "smartdns-stage-agent")
        await asyncio.sleep(5)
        assert await control.reconcile()
        report["agent_restart"] = "passed"
        print("Functional DNS/TLS, real proxy, suspend watchdog and agent restart passed", flush=True)
        report["before"] = snapshot()
        report["load_began_at"] = datetime.now(UTC).isoformat()
        samples = []
        errors = {}
        counts = [0] * 30
        began = time.monotonic()
        deadline = began + args.seconds

        async def worker(index, device):
            await asyncio.sleep((index * 2 + device) / 30)
            domains = ["example.com", "chatgpt.com", "cloudflare.com", "doubleclick.net"]
            n = device
            while time.monotonic() < deadline:
                started = time.monotonic()
                try:
                    answer = await query(profiles[index], domains[n % 4])
                    if answer.rcode() != dns.rcode.NOERROR:
                        label = "DNS_" + dns.rcode.to_text(answer.rcode())
                        errors[label] = errors.get(label, 0) + 1
                        n += 1
                        await asyncio.sleep(max(0, 2 - (time.monotonic() - started)))
                        continue
                    counts[index] += 1
                    samples.append((time.monotonic() - started) * 1000)
                except Exception as exc:
                    errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1
                n += 1
                await asyncio.sleep(max(0, 2 - (time.monotonic() - started)))

        await asyncio.gather(*(worker(i, d) for i in range(30) for d in range(2)))
        samples.sort()
        report["load"] = {
            "seconds": round(time.monotonic() - began, 2),
            "profiles": 30,
            "clients": 60,
            "requests": sum(counts),
            "errors": errors,
            "min_per_profile": min(counts),
            "p50_ms": round(statistics.median(samples), 2) if samples else None,
            "p95_ms": round(samples[int(len(samples) * 0.95)], 2) if samples else None,
            "p99_ms": round(samples[int(len(samples) * 0.99)], 2) if samples else None,
        }
        report["after"] = snapshot()
        report["no_restarts"] = (
            all(
                report["before"]["services"][name]["restarts"]
                == report["after"]["services"][name]["restarts"]
                for name in report["before"]["services"]
            )
            and report["before"]["filter"]["restarts"] == report["after"]["filter"]["restarts"]
        )
        report["vpn_state_unchanged"] = report["before"]["vpn_state"] == report["after"]["vpn_state"]
        (root / "acceptance-report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report["load"]), flush=True)
        with db.connect() as connection:
            connection.execute("DELETE FROM route_overrides WHERE domain='api.ipify.org'")
            db.bump(connection)
        assert await control.reconcile()
        assert not errors and min(counts) > 0 and report["no_restarts"] and report["vpn_state_unchanged"], (
            "load errors or restarts"
        )
    await control.close()


if __name__ == "__main__":
    try:
        asyncio.run(asyncio.wait_for(main(), timeout=120))
    except Exception as exc:
        import traceback

        print("Staging acceptance failed: " + type(exc).__name__, flush=True)
        print(
            [(Path(frame.filename).name, frame.lineno) for frame in traceback.extract_tb(exc.__traceback__)],
            flush=True,
        )
        if isinstance(exc, AssertionError):
            print(str(exc), flush=True)
        raise SystemExit(1) from None
