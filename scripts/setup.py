#!/usr/bin/env python3
"""Install a verified SmartDNS release on Ubuntu LTS. Never replaces shared ingress."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path("/opt/smartdns")
ETC = Path("/etc/smartdns")
IMAGE = "adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0"


def run(argv: list[str], **kwargs) -> str:
    try:
        return subprocess.run(
            argv, check=True, text=True, capture_output=True, timeout=120, **kwargs
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        ROOT.mkdir(parents=True, exist_ok=True)
        log = ROOT / "install-error.log"
        log.write_text(exc.stderr or "Command failed without diagnostic output")
        log.chmod(0o600)
        raise RuntimeError(
            f"Installation command {Path(argv[0]).name} failed; private details: {log}"
        ) from None


def write(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(mode)


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("Downloads require HTTPS")
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 -- checked HTTPS scheme
        return response.read()


def install_uv() -> str:
    found = shutil.which("uv")
    if found and run([found, "--version"]).split()[1] == "0.13.6":
        return found
    metadata = json.loads(fetch("https://pypi.org/pypi/uv/0.13.6/json"))
    wheel = next(
        x
        for x in metadata["urls"]
        if "manylinux_2_17_x86_64" in x["filename"] and x["filename"].endswith(".whl")
    )
    content = fetch(wheel["url"])
    if hashlib.sha256(content).hexdigest() != wheel["digests"]["sha256"]:
        raise ValueError("uv download checksum mismatch")
    tools = ROOT / "tools"
    tools.mkdir(parents=True, exist_ok=True)
    archive = tools / wheel["filename"]
    archive.write_bytes(content)
    run([sys.executable, "-m", "venv", str(tools / "uv")])
    run([str(tools / "uv/bin/pip"), "install", "--no-deps", str(archive)])
    archive.unlink()
    return str(tools / "uv/bin/uv")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--domain")
    parser.add_argument("--ipv4")
    parser.add_argument("--ipv6", default="")
    parser.add_argument("--mode", choices=["dedicated", "shared"], default="dedicated")
    parser.add_argument("--forward-mode", choices=["local", "tunnel"], default="local")
    parser.add_argument("--forward-source-ipv4", default="")
    parser.add_argument("--forward-interface", default="")
    parser.add_argument("--expected-egress-ipv4", default="")
    parser.add_argument(
        "--certificate-config", type=Path, help="Existing root-owned Certbot configuration JSON"
    )
    parser.add_argument("--email")
    parser.add_argument("--uv")
    parser.add_argument("--skip-packages", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("Run with sudo")
    os.umask(0o077)
    release = Path(__file__).resolve().parents[1]
    if hashlib.sha256(args.artifact.read_bytes()).hexdigest() != args.sha256:
        raise ValueError("Artifact checksum mismatch")
    # Check the archive contents before using its installer or templates.
    from release_tools import unpack

    prepared = ROOT / "prepared" / args.commit
    if not prepared.exists():
        manifest = unpack(args.artifact, prepared)
    else:
        manifest = json.loads((prepared / "manifest.json").read_text())
        for name, checksum in manifest["files"].items():
            if hashlib.sha256((prepared / name).read_bytes()).hexdigest() != checksum:
                raise ValueError("Prepared release was modified")
    if manifest["commit"] != args.commit:
        raise ValueError("Commit mismatch")
    release = prepared
    osinfo = dict(
        line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line
    )
    if (
        osinfo.get("ID", "").strip('"') != "ubuntu"
        or osinfo.get("VERSION_ID", "").strip('"') not in ("24.04", "26.04")
        or platform.machine() != "x86_64"
    ):
        raise ValueError("Supported platforms: Ubuntu 24.04/26.04 LTS x86_64")
    existing = ETC / "settings.json"
    installed = ROOT / "installed.json"
    if existing.exists() and installed.exists():
        installed = ROOT / "installed.json"
        if installed.exists() and json.loads(installed.read_text()).get("sha256") == args.sha256:
            print("This exact release is already installed; configuration and credentials retained.")
            return
        uv = args.uv or install_uv()
        run(
            [
                sys.executable,
                str(release / "scripts/install.py"),
                "apply",
                str(args.artifact.resolve()),
                "--sha256",
                args.sha256,
                "--commit",
                args.commit,
                "--uv",
                uv,
            ]
        )
        print("Upgraded existing installation; DNS credentials retained.")
        return
    previous = json.loads(existing.read_text()) if existing.exists() else {}
    domain = (
        (
            args.domain
            or previous.get("public_url", "").removeprefix("https://")
            or input("DNS domain (for example dns.example.com): ")
        )
        .strip()
        .lower()
    )
    if not re.fullmatch(r"(?=.{1,190}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Use an ASCII DNS hostname without scheme or path")
    import ipaddress

    ipv4 = str(ipaddress.IPv4Address(args.ipv4 or previous.get("public_ipv4") or input("Public IPv4: ")))
    if not ipaddress.ip_address(ipv4).is_global:
        raise ValueError("Public IPv4 required")
    ipv6 = str(ipaddress.IPv6Address(args.ipv6)) if args.ipv6 else ""
    if ipv6 and not ipaddress.ip_address(ipv6).is_global:
        raise ValueError("Public IPv6 required")
    if args.forward_mode == "tunnel" and not all(
        (args.forward_source_ipv4, args.forward_interface, args.expected_egress_ipv4)
    ):
        raise ValueError("Tunnel mode requires source IPv4, interface and expected egress IPv4")
    import socket

    if args.mode == "dedicated" and not previous:
        for port in (443, 853, 3010, 3007, 3008, 19108):
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    raise ValueError(f"Port {port} is occupied; use shared mode and review ingress fragments")
    if shutil.disk_usage("/").free < 2 * 1024**3:
        raise ValueError("At least 2 GiB of free disk space required")
    if args.mode == "shared":
        print(
            "Shared mode prepares files only; packages, listeners and firewall are managed by the operator."
        )
    if not args.skip_packages and args.mode == "dedicated":
        run(["apt-get", "update"])
        run(
            [
                "apt-get",
                "install",
                "-y",
                "python3-venv",
                "nginx",
                "haproxy",
                "nftables",
                "docker.io",
                "certbot",
                "dnsutils",
                "openssl",
                "ca-certificates",
            ]
        )
    uv = args.uv or install_uv()
    if subprocess.run(["id", "smartdns"], capture_output=True).returncode:
        run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "smartdns"])
    for directory in ("/var/lib/smartdns", "/var/lib/smartdns-agent", "/etc/smartdns", "/opt/smartdns"):
        Path(directory).mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    (ROOT / "releases").mkdir(exist_ok=True)
    (ROOT / "releases").chmod(0o755)
    ETC.chmod(0o750)
    run(["chown", "root:smartdns", str(ETC)])
    run(["chown", "smartdns:smartdns", "/var/lib/smartdns"])
    Path("/var/lib/smartdns").chmod(0o2770)
    cfg = json.loads((release / "config/example.json").read_text())
    cfg.update(previous)
    cfg.update(
        public_url="https://" + domain,
        public_ipv4=ipv4,
        public_ipv6=ipv6,
        cert_file="/etc/smartdns/certs/current/fullchain.pem",
        key_file="/etc/smartdns/certs/current/privkey.pem",
        forward_mode=args.forward_mode,
        forward_source_ipv4=args.forward_source_ipv4,
        forward_interface=args.forward_interface,
        expected_egress_ipv4=args.expected_egress_ipv4,
    )
    write(existing, json.dumps(cfg, indent=2), 0o640)
    run(["chown", "root:smartdns", str(existing)])
    # Save reviewable fragments for shared and dedicated installations alike.
    fragments = ETC / "ingress.d"
    fragments.mkdir(exist_ok=True)
    for name in ("haproxy.cfg", "nginx.conf", "firewall.nft"):
        text = (
            (release / "config/templates" / name)
            .read_text()
            .replace("dns.example.com", domain)
            .replace("203.0.113.10", ipv4)
        )
        if ipv6:
            text = text.replace("2001:db8::10", ipv6)
        else:
            text = "\n".join(line for line in text.splitlines() if "ip6 daddr" not in line) + "\n"
        if name == "haproxy.cfg":
            text = text.replace(
                " bind :443", " bind 0.0.0.0:443" + ("\n bind [" + ipv6 + "]:443" if ipv6 else "")
            )
            if args.forward_mode == "tunnel":
                text = text.replace(
                    "server origin 0.0.0.0:443",
                    "server origin 0.0.0.0:443 source " + args.forward_source_ipv4,
                )
        write(fragments / name, text, 0o640)
    if args.mode == "shared":
        print(
            "Prepared /etc/smartdns/settings.json and ingress.d fragments. Merge them with your existing ingress, certificate and tunnel policy; then follow INSTALLATION.md. Existing listeners were not changed."
        )
        return
    certcfg = {
        "domain": domain,
        "cert_name": "smartdns",
        "config_dir": "/etc/smartdns/acme",
        "work_dir": "/var/lib/smartdns-acme",
        "logs_dir": "/var/log/smartdns-acme",
        "certificate_dir": "/etc/smartdns/certs",
        "group": "smartdns",
        "gateway_unit": "smartdns-gateway",
        "status_file": "/var/lib/smartdns/certificate-status.json",
        "lock_file": "/run/lock/smartdns-cert.lock",
    }
    if args.certificate_config:
        certcfg.update(json.loads(args.certificate_config.read_text()))
    if (ETC / "certificates.json").exists():
        certcfg = json.loads((ETC / "certificates.json").read_text())
    write(ETC / "certificates.json", json.dumps(certcfg, indent=2))
    if not args.certificate_config and not (ETC / "acme-dns.json").exists():
        request = urllib.request.Request(
            "https://auth.acme-dns.io/register", data=b"{}", headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 -- fixed HTTPS provider
            creds = json.load(response)
        creds["api_url"] = "https://auth.acme-dns.io"
        write(ETC / "acme-dns.json", json.dumps(creds))
        print(f"Add DNS records: A {domain} and *.{domain} -> {ipv4}" + (f"; AAAA -> {ipv6}" if ipv6 else ""))
        print(f"Add CNAME _acme-challenge.{domain} -> {creds['fulldomain']}")
        input("Press Enter after saving the DNS records: ")
    for hostname in (domain, "bootstrap-check." + domain):
        if ipv4 not in {r[4][0] for r in socket.getaddrinfo(hostname, 443, socket.AF_INET)}:
            raise ValueError("Base and wildcard A records must point to this server")
    certargs = certcfg.get("certbot_args") or [
        "--manual",
        "--preferred-challenges",
        "dns",
        "--manual-auth-hook",
        shlex.join([sys.executable, str(release / "scripts/acme_auth.py")]),
    ]
    env = os.environ | {"ACME_DNS_CREDENTIALS": str(ETC / "acme-dns.json")}
    run(
        [
            "certbot",
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--email",
            args.email or input("ACME email: "),
            "--cert-name",
            certcfg["cert_name"],
            "--config-dir",
            certcfg["config_dir"],
            "--work-dir",
            certcfg["work_dir"],
            "--logs-dir",
            certcfg["logs_dir"],
            "-d",
            domain,
            "-d",
            "*." + domain,
            *certargs,
        ],
        env=env,
    )
    run([sys.executable, str(release / "scripts/certificates.py"), "prepare"])
    shutil.copy2(fragments / "haproxy.cfg", "/etc/haproxy/haproxy.cfg")
    shutil.copy2(fragments / "nginx.conf", "/etc/nginx/conf.d/smartdns.conf")
    for name, value in [("sources", "192.0.2.0/32\n"), ("origins", "^example\\.com$\n"), ("direct", "\n")]:
        write(Path("/etc/haproxy") / f"smartdns-{name}.acl", value, 0o600)
    for template in (release / "config/templates").glob("smartdns-*.service"):
        shutil.copy2(template, Path("/etc/systemd/system") / template.name)
    for template in (release / "config/templates").glob("smartdns-*.timer"):
        shutil.copy2(template, Path("/etc/systemd/system") / template.name)
    shutil.copy2(fragments / "firewall.nft", ETC / "firewall.nft")
    write(
        Path("/etc/systemd/system/smartdns-network.service"),
        """[Unit]
Description=SmartDNS firewall sets
Before=smartdns-agent.service
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /opt/smartdns/current/scripts/network.py
Environment=SMARTDNS_CONFIG=/etc/smartdns/settings.json
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
""",
        0o644,
    )
    run(["systemctl", "daemon-reload"])
    run([sys.executable, str(release / "scripts/network.py")])
    agh = Path("/etc/smartdns/adguard")
    agh.mkdir(exist_ok=True)
    shutil.copy2(release / "config/templates/AdGuardHome.yaml", agh / "AdGuardHome.yaml")
    if subprocess.run(["docker", "inspect", "smartdns-filter"], capture_output=True).returncode:
        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                "smartdns-filter",
                "--restart",
                "unless-stopped",
                "--network",
                "host",
                "--memory",
                "512m",
                "-v",
                str(agh) + ":/opt/adguardhome/conf",
                "-v",
                "/var/lib/smartdns-adguard:/opt/adguardhome/work",
                IMAGE,
            ]
        )
    else:
        run(["docker", "start", "smartdns-filter"])
    run(["nginx", "-t"])
    run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"])
    run(["systemctl", "reload-or-restart", "nginx", "haproxy"])
    run(
        [
            sys.executable,
            str(release / "scripts/install.py"),
            "apply",
            str(args.artifact.resolve()),
            "--sha256",
            args.sha256,
            "--commit",
            args.commit,
            "--uv",
            uv,
        ]
    )
    cli = str(ROOT / "current/venv/bin/smartdns")
    env = os.environ | {"SMARTDNS_CONFIG": str(existing)}
    direct = run(
        [
            str(ROOT / "current/venv/bin/python"),
            "-c",
            "from smartdns.policy import CONNECTIVITY_NAMES; print(*sorted(CONNECTIVITY_NAMES),sep=chr(10))",
        ]
    )
    write(Path("/etc/haproxy/smartdns-direct.acl"), direct + "\n", 0o600)
    run([cli, "catalog-refresh", "--bootstrap"], env=env)
    run(["nginx", "-t"])
    run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"])
    run(["systemctl", "reload", "nginx", "haproxy"])
    run(
        [
            "systemctl",
            "enable",
            "--now",
            "smartdns-api",
            "smartdns-gateway",
            "smartdns-agent",
            "smartdns-catalog.timer",
            "smartdns-cert.timer",
            "smartdns-network",
        ]
    )
    print("Create your administrator (password is requested privately):")
    subprocess.run([cli, "create", "admin", "--admin"], env=env, check=True)
    print(
        "Installation complete. Allow inbound TCP 443/853 in the provider firewall; run certificate dry-run and authenticated DNS acceptance before distributing profiles."
    )


if __name__ == "__main__":
    main()
