"""Disposable privileged CI container only: real service install with synthetic ACME.

Never run this fixture on a VPS or workstation. Production Certbot is not modified by the installer.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import ssl
import struct
import subprocess
import time
from pathlib import Path


def run(args: list[str], **kwargs) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=115, **kwargs).stdout


def main() -> None:
    if os.environ.get("SMARTDNS_DISPOSABLE_INSTALL_TEST") != "1" or not Path("/.dockerenv").exists():
        raise RuntimeError("Requires an explicitly marked disposable CI container")
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact")
    args = parser.parse_args()
    artifact = Path(args.artifact)
    import tarfile

    with tarfile.open(artifact) as bundle:
        manifest = json.load(bundle.extractfile("manifest.json"))
    source = Path("/fixture/source")
    source.mkdir(parents=True)
    # The shipped unpacker checks the supplied archive before the test executes it.
    import sys

    sys.path.insert(0, "/workspace/scripts")
    from release_tools import unpack

    unpack(artifact, source)
    lineage = Path("/etc/smartdns/acme/live/smartdns")
    lineage.mkdir(parents=True)
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "3",
            "-subj",
            "/CN=dns.example.com",
            "-addext",
            "subjectAltName=DNS:dns.example.com,DNS:*.dns.example.com",
            "-keyout",
            str(lineage / "privkey.pem"),
            "-out",
            str(lineage / "fullchain.pem"),
        ]
    )
    # Synthetic ACME returns the local fixture certificate; actual renewal is a separate deployment gate.
    shim = Path("/usr/local/bin/certbot")
    shim.write_text("#!/bin/sh\nexit 0\n")
    shim.chmod(0o755)
    provider = Path("/fixture/provider.json")
    provider.write_text(json.dumps({"certbot_args": ["--manual"]}))
    with Path("/etc/hosts").open("a") as hosts:
        hosts.write("\n8.8.8.8 dns.example.com bootstrap-check.dns.example.com\n")
    for ip in ["8.8.8.8", "8.8.4.4"]:
        run(["ip", "addr", "add", ip + "/32", "dev", "lo"])
    for _ in range(30):
        if subprocess.run(["systemctl", "is-active", "dbus"], capture_output=True).returncode == 0:
            break
        time.sleep(1)
    # Inner Docker uses a private storage tree and network namespace in this disposable outer container.
    Path("/etc/docker").mkdir(exist_ok=True)
    Path("/etc/docker/daemon.json").write_text('{"storage-driver":"vfs"}')
    run(["systemctl", "start", "docker"])
    command = [
        "python3",
        str(source / "scripts/setup.py"),
        "--artifact",
        str(artifact),
        "--sha256",
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "--commit",
        manifest["commit"],
        "--domain",
        "dns.example.com",
        "--ipv4",
        "8.8.8.8",
        "--email",
        "fixture@example.com",
        "--certificate-config",
        str(provider),
        "--uv",
        "/test-tools/uv",
        "--skip-packages",
    ]
    run(command, input="fixture-install-password-123\n")
    context = ssl.create_default_context(cafile=str(lineage / "fullchain.pem"))

    def request(path, method="GET", body=None, headers=None):
        conn = http.client.HTTPSConnection(
            "dns.example.com", 443, context=context, timeout=10, source_address=("8.8.4.4", 0)
        )
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        status = response.status
        head = response.getheaders()
        conn.close()
        return status, data, head

    for _ in range(20):
        try:
            if request("/api/v1/health")[0] == 200:
                break
        except OSError, ssl.SSLError:
            pass
        time.sleep(0.5)
    assert request("/api/v1/health")[0] == 200
    status, data, headers = request(
        "/api/v1/auth/login",
        "POST",
        json.dumps({"login": "admin", "password": "fixture-install-password-123"}),
        {"Content-Type": "application/json"},
    )
    assert status == 200
    cookie = next(v.split(";")[0] for k, v in headers if k.lower() == "set-cookie")
    auth = {"Cookie": cookie, "Content-Type": "application/json"}
    _, data, _ = request("/api/v1/me", headers=auth)
    me = json.loads(data)
    auth["X-CSRF-Token"] = me["csrf"]
    status, data, _ = request("/api/v1/admin/users", "POST", json.dumps({"username": "fixture-client"}), auth)
    assert status == 201
    account = json.loads(data)["id"]
    _, data, _ = request("/api/v1/admin/users/" + account + "/connection", headers=auth)
    connection = json.loads(data)
    # Test source is bound only inside this disposable network namespace.
    with (
        socket.create_connection(("dns.example.com", 853), timeout=10, source_address=("8.8.4.4", 0)) as raw,
        context.wrap_socket(raw, server_hostname=connection["dot"]) as tls,
    ):

        def exact(n):
            data = b""
            while len(data) < n:
                chunk = tls.recv(n - len(data))
                if not chunk:
                    raise EOFError("DoT closed")
                data += chunk
            return data

        # Minimal DNS wire query, repeated on the same real TLS connection.
        query = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"
        )
        for _ in range(2):
            tls.sendall(struct.pack("!H", len(query)) + query)
            answer = exact(struct.unpack("!H", exact(2))[0])
            assert answer[:2] == query[:2] and answer[3] & 15 == 0
    status, answer, _ = request(
        connection["doh"].removeprefix("https://dns.example.com"),
        "POST",
        query,
        {"Content-Type": "application/dns-message"},
    )
    assert status == 200 and answer[:2] == query[:2]
    assert (
        request("/dns-query/" + "k" + "a" * 52, "POST", query, {"Content-Type": "application/dns-message"})[0]
        == 403
    )
    time.sleep(1)
    _, data, _ = request("/api/v1/admin/users/" + account + "/networks?days=7", headers=auth)
    assert json.loads(data)["networks"][0]["ip"] == "8.8.4.4"
    _, profile, _ = request("/api/v1/admin/users/" + account + "/profile.mobileconfig", headers=auth)
    import plistlib

    assert plistlib.loads(profile)["PayloadContent"][0]["DNSSettings"]["ServerURL"] == connection["doh"]
    before = hashlib.sha256(connection["dot"].encode()).hexdigest()
    run(command, input="fixture-install-password-123\n")
    _, data, _ = request("/api/v1/admin/users/" + account + "/connection", headers=auth)
    assert hashlib.sha256(json.loads(data)["dot"].encode()).hexdigest() == before
    print(
        json.dumps(
            {
                "full_clean_install": "passed",
                "idempotent_setup": "passed",
                "real_systemd_nginx_haproxy_adguard": "passed",
                "dot_doh_profile_ip_history": "passed",
                "synthetic_acme": True,
                "public_acme_renewal": "deployment_gate",
                "version": manifest["version"],
                "commit": manifest["commit"],
            }
        )
    )


if __name__ == "__main__":
    main()
