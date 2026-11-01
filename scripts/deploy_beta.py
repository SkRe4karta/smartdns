#!/usr/bin/env python3
"""Prepare/apply/rollback a verified beta artifact on the existing Finnish host.

All modified alpha files are recorded in a private backup. VPN backend blocks are
compared byte-for-byte before the HAProxy reload. Telegram is optional and stays
unconfigured unless its root-only credentials file has been filled by the owner.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from release_tools import unpack

ROOT = Path("/opt/zelyonka-smartdns-beta")
ALPHA = Path("/opt/zelyonka-smartdns")
SERVICES = ["zelyonka-api", "zelyonka-gateway", "zelyonka-agent"]
OLD = ["smartdns-portal", "smartdns-sync.timer", "smartdns-cert.timer"]
FILES = [Path("/etc/haproxy/haproxy.cfg"), Path("/etc/nginx/sites-enabled/zelyonka-smartdns.conf")] + [
    Path("/etc/haproxy") / f"smartdns-{name}.acl" for name in ["sources", "origins", "web", "dot"]
]


def run(args, **kwargs):
    p = subprocess.run([str(v) for v in args], capture_output=True, text=True, timeout=180, **kwargs)
    if p.returncode:
        raise RuntimeError("Command failed: " + str(args[0]) + "\n" + p.stderr[-1500:])
    return p.stdout.strip()


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def unit_state(name):
    return {
        kind: subprocess.run(["systemctl", "is-" + kind, name], capture_output=True, text=True).stdout.strip()
        for kind in ["active", "enabled"]
    }


def backup_database(source, destination):
    with (
        sqlite3.connect(f"file:{source}?mode=ro", uri=True) as origin,
        sqlite3.connect(destination) as target,
    ):
        origin.backup(target)
    destination.chmod(0o600)


def restore(backup):
    manifest = json.loads((backup / "backup.json").read_text())
    if manifest["root"] != str(ROOT):
        raise ValueError("Invalid rollback manifest")
    for name in SERVICES + ["zelyonka-catalog.timer", "zelyonka-cert.timer"]:
        subprocess.run(["systemctl", "disable", "--now", name], capture_output=True)
    subprocess.run(["docker", "stop", "zelyonka-beta-filter"], capture_output=True, timeout=45)
    for filename in manifest["files"]:
        path = Path(filename)
        if path not in FILES:
            raise ValueError("Unknown rollback target")
        shutil.copyfile(backup / path.relative_to("/"), path)
    run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"])
    run(["nginx", "-t"])
    run(["systemctl", "reload", "haproxy"])
    run(["systemctl", "reload", "nginx"])
    run(["docker", "start", "zelyonka-smartdns"])
    for name, state in manifest["units"].items():
        if name not in OLD:
            raise ValueError("Unknown old unit")
        if state["enabled"] == "enabled":
            run(["systemctl", "enable", name])
        if state["active"] == "active":
            run(["systemctl", "start", name])
    run(["/usr/local/sbin/smartdnsctl", "sync"])
    if (ROOT / "installed.json").exists():
        shutil.copyfile(ROOT / "installed.json", backup / "rolled-back-install.json")
    write(
        ROOT / "deployment-state.json", json.dumps({"state": "alpha-restored", "backup": str(backup)}), 0o600
    )
    print("Alpha restored; beta database retained privately; verify client access")


def prepare(archive, expected, commit, uv, staging_root):
    if any(unit_state(name)["active"] == "active" for name in SERVICES):
        raise ValueError("This initial-migration installer requires beta services to be stopped")
    staging_root = staging_root.resolve()
    if staging_root.parent != ROOT / "staging":
        raise ValueError("Invalid staging root")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError("Artifact checksum mismatch")
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("Invalid commit")
    release = ROOT / "releases" / commit
    if not release.exists():
        manifest = unpack(archive, release)
        if manifest["commit"] != commit:
            raise ValueError("Artifact commit mismatch")
        run([uv, "venv", "--python", "3.14.4", release / "venv"])
        run(
            [
                uv,
                "pip",
                "install",
                "--python",
                release / "venv/bin/python",
                "--require-hashes",
                "-r",
                release / "requirements.txt",
            ]
        )
        run(
            [
                uv,
                "pip",
                "install",
                "--python",
                release / "venv/bin/python",
                "--no-deps",
                next((release / "wheels").glob("*.whl")),
            ]
        )
    else:
        manifest = json.loads((release / "manifest.json").read_text())
        if manifest["commit"] != commit or manifest.get("dirty"):
            raise ValueError("Invalid existing release")
    config = {
        "data_dir": str(ROOT / "data"),
        "public_url": "https://smartdns.zelyonkin.ru",
        "public_ipv4": "109.120.185.213",
        "master_key_file": str(ROOT / "secrets/master.key"),
        "telegram_file": str(ROOT / "secrets/telegram.json"),
        "agent_socket": "/run/zelyonka/agent.sock",
        "frontend_dir": str(release / "frontend/dist"),
        "legacy_dir": str(release / "legacy"),
        "plain_dns_enabled": True,
    }
    # The dedicated application user is created during the isolated staging checks.
    import pwd

    user = pwd.getpwnam("zelyonka-beta")
    ROOT.chmod(0o751)
    (ROOT / "releases").chmod(0o755)
    write(ROOT / "settings.json", json.dumps(config, indent=2), 0o640)
    os.chown(ROOT / "settings.json", 0, user.pw_gid)
    (ROOT / "secrets").mkdir(exist_ok=True)
    (ROOT / "secrets").chmod(0o700)
    if not (ROOT / "secrets/telegram.json").exists():
        write(ROOT / "secrets/telegram.json", "{}\n", 0o600)
    env = os.environ | {"ZELYONKA_CONFIG": str(ROOT / "settings.json")}
    cli = release / "venv/bin/zelyonka"
    run([cli, "init"], env=env)
    with sqlite3.connect(ROOT / "data/application.sqlite3") as db:
        empty = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
    if empty:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        initial = ROOT / f"alpha-migration-{stamp}.sqlite3"
        backup_database(ALPHA / "state/users.sqlite3", initial)
        run([cli, "migrate-alpha", initial], env=env)
    with sqlite3.connect(ROOT / "data/application.sqlite3") as db:
        empty_catalog = db.execute("SELECT COUNT(*) FROM domain_rules").fetchone()[0] == 0
    if empty_catalog:
        run([cli, "catalog-refresh", "--bootstrap"], env=env)
    for path in [ROOT / "data", *(ROOT / "data").iterdir()]:
        os.chown(path, user.pw_uid, user.pw_gid)
        path.chmod(0o2770 if path.is_dir() else 0o660)
    state = ROOT / "agent-state"
    state.mkdir(exist_ok=True)
    state.chmod(0o700)
    link = ROOT / "current.new"
    if link.is_symlink():
        link.unlink()
    link.symlink_to(release)
    link.replace(ROOT / "current")
    # The certificate hook checks key matching before nginx reload.
    run([release / "scripts/install_certificate.sh"])
    write(
        ROOT / "candidate.json",
        json.dumps(
            {
                "release": str(release),
                "commit": commit,
                "sha256": expected,
                "staging_root": str(staging_root),
            },
            indent=2,
        ),
        0o600,
    )
    print("Candidate prepared; public listeners unchanged")


def apply():
    candidate = json.loads((ROOT / "candidate.json").read_text())
    release = Path(candidate["release"])
    if any(unit_state(name)["active"] == "active" for name in SERVICES):
        raise ValueError("Beta is already active")
    staging_root = Path(candidate["staging_root"])
    report = json.loads((staging_root / "acceptance-report.json").read_text())
    if (
        report.get("functional") != "passed"
        or report.get("watchdog_suspend") != "passed"
        or report["load"]["seconds"] < 60
        or report["load"]["errors"]
    ):
        raise ValueError("Staging acceptance has not passed")
    installed_manifest = json.loads((release / "manifest.json").read_text())
    staged_manifest = json.loads((staging_root / "application/manifest.json").read_text())
    for name, digest in installed_manifest["files"].items():
        if name.startswith(("src/", "frontend/dist/")) and staged_manifest["files"].get(name) != digest:
            raise ValueError("Application differs from the load-tested candidate")
    stage_configs = Path("/etc/zelyonka-node")
    if not (stage_configs / "haproxy.cfg").is_file():
        raise ValueError("Run isolated staging acceptance first")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = Path("/opt/backups") / f"zelyonka-beta-{stamp}"
    backup.mkdir(parents=True, mode=0o700)
    for path in FILES:
        target = backup / path.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    manifest = {
        "root": str(ROOT),
        "files": [str(path) for path in FILES],
        "units": {name: unit_state(name) for name in OLD},
        "candidate": candidate,
    }
    write(backup / "backup.json", json.dumps(manifest, indent=2), 0o600)
    for folder in ["secrets", "certs", "acme"]:
        if (ROOT / folder).exists():
            shutil.copytree(ROOT / folder, backup / folder)
            for path in [backup / folder, *(backup / folder).rglob("*")]:
                path.chmod(0o700 if path.is_dir() else 0o600)
    shutil.copyfile(ROOT / "settings.json", backup / "settings.json")
    (backup / "settings.json").chmod(0o600)
    backup_database(ROOT / "data/application.sqlite3", backup / "beta.sqlite3")
    backup_database(ALPHA / "state/users.sqlite3", backup / "alpha.sqlite3")
    write(ROOT / "rollback-location", str(backup) + "\n", 0o600)
    old = Path("/etc/haproxy/haproxy.cfg").read_text()
    before = old.split("# BEGIN ZELYONKA SMARTDNS")[0]
    before = before.replace(
        "    maxconn 4096",
        "    maxconn 4096\n    stats socket /run/haproxy/zelyonka-admin.sock mode 600 level admin",
    )
    before = before.replace(
        "    acl sni_smartdns_service",
        "    acl sni_smartdns_web req.ssl_sni,lower -m end .smartdns.zelyonkin.ru\n    acl sni_smartdns_service",
        1,
    )
    block = (stage_configs / "haproxy.cfg").read_text().split("resolvers stage_dns", 1)[1]
    block = "resolvers stage_dns" + block
    for a, b in [
        ("stage_dns", "smartdns_origins_dns"),
        ("stage_proxy", "smartdns_origins"),
        ("stage_health", "smartdns_agent_health"),
        ("/etc/zelyonka-node/sources.acl", "/etc/haproxy/smartdns-sources.acl"),
        ("/etc/zelyonka-node/origins.acl", "/etc/haproxy/smartdns-origins.acl"),
        ("19118", "19108"),
    ]:
        block = block.replace(a, b)
    updated = (
        before
        + "\n# BEGIN ZELYONKA SMARTDNS BETA\nbackend smartdns_web\n    mode tcp\n    server web 127.0.0.1:8544 send-proxy-v2 maxconn 256\n\n"
        + block
    )

    def backend(text, name):
        return (
            re.search(r"^backend " + name + r"\n.*?(?=^backend |^# BEGIN|\Z)", text, re.M | re.S)
            .group(0)
            .strip()
        )

    for name in ["xhttp_reality", "grpc_reality", "trojan_reality", "filtered_dns"]:
        if backend(old, name) != backend(updated, name):
            raise ValueError("VPN backend changed")
    nginx_original = Path("/etc/nginx/sites-enabled/zelyonka-smartdns.conf").read_text()
    http_prefix = nginx_original.split("server {\n listen 127.0.0.1:8544", 1)[0]
    nginx = (
        Path("/etc/nginx/sites-enabled/zelyonka-stage.conf")
        .read_text()
        .replace("127.0.0.1:8545", "127.0.0.1:8544")
    )
    nginx = re.sub(r"ssl_certificate .*?;", f"ssl_certificate {ROOT}/certs/fullchain.pem;", nginx)
    nginx = re.sub(r"ssl_certificate_key .*?;", f"ssl_certificate_key {ROOT}/certs/privkey.pem;", nginx)
    nginx = nginx.replace(
        " server_name",
        " http2 on;\n limit_conn smartdns_connections 128;\n client_body_timeout 10s;\n server_name",
        1,
    )
    write(
        "/usr/local/sbin/zelyonkactl",
        '#!/bin/sh\numask 0007\nexport ZELYONKA_CONFIG=/opt/zelyonka-smartdns-beta/settings.json\nexec /opt/zelyonka-smartdns-beta/current/venv/bin/zelyonka "$@"\n',
        0o750,
    )
    common = f"""Restart=on-failure
RestartSec=2
TimeoutStopSec=15
Environment=ZELYONKA_CONFIG={ROOT}/settings.json
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
UMask=0007
"""
    for name, memory, command in [
        (
            "api",
            192,
            f"{ROOT}/current/venv/bin/python -m uvicorn zelyonka.api:create_app --factory --host 127.0.0.1 --port 3008 --no-access-log --no-proxy-headers",
        ),
        ("gateway", 128, f"{ROOT}/current/venv/bin/zelyonka-gateway"),
        ("agent", 128, f"{ROOT}/current/venv/bin/zelyonka-agent"),
    ]:
        extra = f"User=zelyonka-beta\nGroup=zelyonka-beta\nReadWritePaths={ROOT}/data\n"
        if name == "api":
            extra += f"LoadCredential=master.key:{ROOT}/secrets/master.key\nLoadCredential=telegram.json:{ROOT}/secrets/telegram.json\n"
        if name == "gateway":
            extra += "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        if name == "agent":
            extra = f"User=root\nGroup=zelyonka-beta\nRuntimeDirectory=zelyonka\nRuntimeDirectoryMode=0750\nEnvironment=ZELYONKA_MANAGE_HOST=1\nEnvironment=ZELYONKA_AGENT_STATE={ROOT}/agent-state\nReadWritePaths={ROOT}/agent-state {ROOT}/data /etc/haproxy /run/haproxy /run/zelyonka\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_FOWNER\n"
        write(
            f"/etc/systemd/system/zelyonka-{name}.service",
            f"[Unit]\nDescription=Zelyonka beta {name}\nAfter=network-online.target haproxy.service smartdns-firewall.service\n[Service]\nExecStart={command}\nMemoryMax={memory}M\nLimitNOFILE=512\n"
            + common
            + extra
            + "[Install]\nWantedBy=multi-user.target\n",
        )
    for name, command, schedule, memory in [
        ("catalog", f"{ROOT}/current/venv/bin/zelyonka catalog-refresh", "daily", 256),
        ("cert", f"{ROOT}/current/scripts/renew_certificate.sh", "*-*-* 04,16:30:00", 256),
    ]:
        write(
            f"/etc/systemd/system/zelyonka-{name}.service",
            f"[Unit]\nDescription=Zelyonka {name} maintenance\n[Service]\nType=oneshot\nEnvironment=ZELYONKA_CONFIG={ROOT}/settings.json\nExecStart={command}\nUMask=0007\nMemoryMax={memory}M\n",
        )
        write(
            f"/etc/systemd/system/zelyonka-{name}.timer",
            f"[Unit]\nDescription=Zelyonka {name} schedule\n[Timer]\nOnCalendar={schedule}\nRandomizedDelaySec=30m\nPersistent=true\n[Install]\nWantedBy=timers.target\n",
        )
    try:
        for name in [
            "zelyonka-stage-api",
            "zelyonka-stage-agent",
            "zelyonka-stage-gateway",
            "zelyonka-node-haproxy",
        ]:
            subprocess.run(["systemctl", "stop", name], capture_output=True, timeout=45)
        run(["docker", "stop", "zelyonka-beta-stage-filter"])
        filter_dir = ROOT / "filter"
        if not filter_dir.exists():
            shutil.copytree(staging_root / "filter", filter_dir)
        # Remove staging clients/rules and old query history before using the filter in production.
        import yaml

        config = yaml.safe_load((filter_dir / "conf/AdGuardHome.yaml").read_text())
        config["clients"]["persistent"] = []
        config["user_rules"] = []
        config["dns"]["allowed_clients"] = ["127.0.0.1"]
        write(filter_dir / "conf/AdGuardHome.yaml", yaml.safe_dump(config, sort_keys=False), 0o600)
        for filename in (filter_dir / "work").rglob("*"):
            if filename.is_file() and ("querylog" in filename.name or "stats" in filename.name):
                filename.unlink()
        existing = (
            subprocess.run(["docker", "inspect", "zelyonka-beta-filter"], capture_output=True).returncode == 0
        )
        if existing:
            run(["docker", "start", "zelyonka-beta-filter"])
        else:
            run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    "zelyonka-beta-filter",
                    "--network",
                    "host",
                    "--restart",
                    "unless-stopped",
                    "--memory",
                    "512m",
                    "--memory-swap",
                    "512m",
                    "--cpus",
                    "0.35",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--cap-add",
                    "NET_BIND_SERVICE",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=16m",  # noqa: S108 -- container-local tmpfs
                    "-v",
                    f"{filter_dir}/conf:/opt/adguardhome/conf",
                    "-v",
                    f"{filter_dir}/work:/opt/adguardhome/work",
                    "adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0",
                ]
            )
        for name in OLD:
            subprocess.run(["systemctl", "disable", "--now", name], capture_output=True)
        run(["docker", "stop", "zelyonka-smartdns"])
        shutil.copyfile(stage_configs / "origins.acl", "/etc/haproxy/smartdns-origins.acl")
        write("/etc/haproxy/haproxy.cfg", updated)
        write("/etc/nginx/sites-enabled/zelyonka-smartdns.conf", http_prefix + nginx)
        run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"])
        run(["nginx", "-t"])
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "reload", "haproxy"])
        run(["systemctl", "reload", "nginx"])
        run(["systemctl", "enable", "--now", *SERVICES, "zelyonka-catalog.timer", "zelyonka-cert.timer"])
        write(
            ROOT / "installed.json",
            json.dumps(
                candidate | {"installed_at": datetime.now(UTC).isoformat(), "state": "pilot"}, indent=2
            ),
            0o644,
        )
        write(ROOT / "deployment-state.json", json.dumps({"state": "pilot", "backup": str(backup)}), 0o600)
        print(json.dumps({"state": "pilot", "commit": candidate["commit"], "backup": str(backup)}))
    except Exception:
        restore(backup)
        raise


def main():
    if os.geteuid() != 0:
        raise ValueError("Run as root")
    os.umask(0o007)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    command = sub.add_parser("prepare")
    command.add_argument("archive", type=Path)
    command.add_argument("--sha256", required=True)
    command.add_argument("--commit", required=True)
    command.add_argument("--uv", required=True)
    command.add_argument("--staging-root", type=Path, required=True)
    sub.add_parser("apply")
    command = sub.add_parser("rollback")
    command.add_argument("backup", type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.archive, args.sha256, args.commit, args.uv, args.staging_root)
    elif args.action == "apply":
        apply()
    else:
        restore(args.backup.resolve())


if __name__ == "__main__":
    main()
