#!/usr/bin/env python3
"""Prepare an isolated real-component staging stack around an installed CI artifact.

Does not replace the alpha HAProxy configuration or bind public DNS/HTTPS ports.
"""

import argparse
import copy
import json
import os
import pwd
import shutil
import sqlite3
import subprocess
from pathlib import Path

import yaml

IMAGE = "adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0"


def run(args, **kwargs):
    p = subprocess.run([str(v) for v in args], capture_output=True, text=True, timeout=120, **kwargs)
    if p.returncode:
        raise RuntimeError(p.stderr[-2000:])
    return p.stdout.strip()


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if os.geteuid() != 0 or root.parent != Path("/opt/zelyonka-smartdns-beta/staging"):
        raise ValueError("Run as root against a private staging artifact directory")
    if (root / "stack-prepared").exists():
        raise ValueError("Staging already prepared")
    try:
        user = pwd.getpwnam("zelyonka-beta")
    except KeyError:
        run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "zelyonka-beta"])
        user = pwd.getpwnam("zelyonka-beta")
    for directory in [root, root.parent, root.parent.parent]:
        directory.chmod(0o751)
    config = json.loads((root / "settings.json").read_text())
    config.update(
        public_url="https://smartdns.zelyonkin.ru:11444",
        agent_socket="/run/zelyonka-stage/agent.sock",
        agh_url="http://127.0.0.1:3010",
        agh_control_url="http://127.0.0.1:3010",
        dot_port=1853,
        cert_file=str(root / "certs/fullchain.pem"),
        key_file=str(root / "certs/privkey.pem"),
        legacy_dir=str(root / "application/legacy"),
    )
    write(root / "settings.json", json.dumps(config, indent=2), 0o640)
    os.chown(root / "settings.json", 0, user.pw_gid)
    write(root / "telegram.json", "{}\n", 0o600)
    certs = root / "certs"
    certs.mkdir(exist_ok=True)
    certs.chmod(0o750)
    os.chown(certs, 0, user.pw_gid)
    lineage = Path("/opt/zelyonka-smartdns-beta/acme/config/live/smartdns-beta-wildcard")
    for filename in ["fullchain.pem", "privkey.pem"]:
        shutil.copyfile(lineage / filename, certs / filename)
        (certs / filename).chmod(0o640)
        os.chown(certs / filename, 0, user.pw_gid)
    env = os.environ | {"ZELYONKA_CONFIG": str(root / "settings.json")}
    with sqlite3.connect(root / "data/application.sqlite3") as db:
        empty_catalog = db.execute("SELECT COUNT(*) FROM domain_rules").fetchone()[0] == 0
    if empty_catalog:
        run([root / "venv/bin/zelyonka", "catalog-refresh", "--bootstrap"], env=env)
    for path in [root / "data", *(root / "data").iterdir()]:
        os.chown(path, user.pw_uid, user.pw_gid)
        path.chmod(0o2770 if path.is_dir() else 0o660)
    agh = root / "filter"
    (agh / "conf").mkdir(parents=True, exist_ok=True)
    (agh / "work").mkdir(exist_ok=True)
    if (
        subprocess.run(["docker", "inspect", "zelyonka-beta-stage-filter"], capture_output=True).returncode
        == 0
    ):
        run(["docker", "rm", "-f", "zelyonka-beta-stage-filter"])
    cfg = copy.deepcopy(yaml.safe_load(Path("/opt/zelyonka-smartdns/conf/AdGuardHome.yaml").read_text()))
    cfg["users"] = []
    cfg["http"]["address"] = "127.0.0.1:3010"
    cfg["http"]["doh"]["insecure_enabled"] = True
    cfg["dns"].update(
        bind_hosts=["127.0.0.1"],
        port=5354,
        upstream_dns=["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
        fallback_dns=["https://dns.quad9.net/dns-query"],
        bootstrap_dns=["1.1.1.1", "9.9.9.9"],
        allowed_clients=["127.0.0.1"],
        disallowed_clients=[],
        blocked_hosts=[],
        cache_size=8388608,
        ratelimit=300,
    )
    cfg["tls"].update(
        enabled=False,
        port_https=0,
        port_dns_over_tls=0,
        port_dns_over_quic=0,
        certificate_chain="",
        private_key="",
        certificate_path="",
        private_key_path="",
    )
    cfg["clients"]["persistent"] = []
    cfg["user_rules"] = []
    cfg["filtering"]["rewrites"] = []
    cfg["filters"] = [
        {
            "enabled": True,
            "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
            "name": "AdGuard DNS Filter",
            "id": 1,
        },
        {
            "enabled": True,
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
            "name": "HaGeZi Multi PRO",
            "id": 2,
        },
    ]
    cfg["filtering"]["filters_update_interval"] = 24
    write(agh / "conf/AdGuardHome.yaml", yaml.safe_dump(cfg, sort_keys=False), 0o600)
    run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            "zelyonka-beta-stage-filter",
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
            f"{agh}/conf:/opt/adguardhome/conf",
            "-v",
            f"{agh}/work:/opt/adguardhome/work",
            IMAGE,
        ]
    )
    run(
        ["nft", "-f", "-"],
        input="table inet zelyonka_node {\n set activated_v4 { type ipv4_addr; flags timeout; }\n}\n",
    )
    folder = Path("/etc/zelyonka-node")
    folder.mkdir(exist_ok=True)
    write(folder / "origins.acl", r"^example\.com$" + "\n", 0o600)
    write(folder / "sources.acl", "192.0.2.0/32\n", 0o600)
    haproxy = """global
    daemon
    user haproxy
    group haproxy
    stats socket /run/zelyonka-node/haproxy.sock mode 600 level admin
    maxconn 512
defaults
    mode tcp
    timeout connect 5s
    timeout client 2m
    timeout server 2m
    timeout check 1s
frontend stage_web
    bind 127.0.0.1:11444
    default_backend stage_web_backend
backend stage_web_backend
    server web 127.0.0.1:8545 send-proxy-v2
frontend stage_origins
    bind 127.0.0.1:11443
    tcp-request inspect-delay 5s
    tcp-request content set-var(sess.smartdns_sni) req.ssl_sni,lower if { req.ssl_hello_type 1 }
    tcp-request content accept if { req.ssl_hello_type 1 }
    default_backend stage_proxy
resolvers stage_dns
    nameserver cloudflare 1.1.1.1:53
    nameserver quad9 9.9.9.9:53
    resolve_retries 2
    timeout resolve 1s
    timeout retry 1s
    hold valid 60s
backend stage_proxy
    tcp-request inspect-delay 5s
    tcp-request content reject unless { nbsrv(stage_health) gt 0 }
    tcp-request content reject unless { src -f /etc/zelyonka-node/sources.acl }
    tcp-request content reject unless { var(sess.smartdns_sni) -m reg -f /etc/zelyonka-node/origins.acl }
    tcp-request content do-resolve(sess.target,stage_dns,ipv4) var(sess.smartdns_sni)
    tcp-request content reject unless { var(sess.target) -m found }
    acl bad var(sess.target) -m ip 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 109.120.185.213/32 45.12.63.194/32
    tcp-request content reject if bad
    tcp-request content set-dst var(sess.target)
    server origin 0.0.0.0:443 maxconn 256
backend stage_health
    mode http
    option httpchk GET /health
    server agent 127.0.0.1:19118 check inter 1s fall 2 rise 1
"""
    write(folder / "haproxy.cfg", haproxy)
    run(["haproxy", "-c", "-f", folder / "haproxy.cfg"])
    write(
        "/etc/systemd/system/zelyonka-node-haproxy.service",
        """[Unit]
Description=Isolated beta staging HTTPS proxy
After=network.target
[Service]
Type=notify
RuntimeDirectory=zelyonka-node
ExecStart=/usr/sbin/haproxy -Ws -f /etc/zelyonka-node/haproxy.cfg -p /run/zelyonka-node/pid
ExecReload=/usr/sbin/haproxy -c -f /etc/zelyonka-node/haproxy.cfg
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
MemoryMax=64M
[Install]
WantedBy=multi-user.target
""",
    )
    nginx = f"""server {{
 listen 127.0.0.1:8545 ssl proxy_protocol;
 server_name smartdns.zelyonkin.ru *.smartdns.zelyonkin.ru;
 ssl_certificate {certs}/fullchain.pem;
 ssl_certificate_key {certs}/privkey.pem;
 set_real_ip_from 127.0.0.1;
 real_ip_header proxy_protocol;
 access_log off;
 error_log /var/log/nginx/zelyonka-stage-error.log crit;
 client_max_body_size 64k;
 location /dns-query/ {{
  proxy_pass http://127.0.0.1:3007;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For "";
  proxy_set_header Forwarded "";
  proxy_set_header Host $host;
 }}
 location / {{
  proxy_pass http://127.0.0.1:3008;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For "";
  proxy_set_header Forwarded "";
  proxy_set_header Host $host;
 }}
}}
"""
    write("/etc/nginx/sites-enabled/zelyonka-stage.conf", nginx)
    run(["nginx", "-t"])
    run(["systemctl", "reload", "nginx"])
    shutil.copyfile(Path(__file__).with_name("run_stage_agent.py"), root / "run_stage_agent.py")
    common = f"""Restart=on-failure
RestartSec=2
Environment=ZELYONKA_CONFIG={root}/settings.json
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
UMask=0007
"""
    for name, command, memory in [
        (
            "api",
            f"{root}/venv/bin/python -m uvicorn zelyonka.api:create_app --factory --host 127.0.0.1 --port 3008 --no-access-log --no-proxy-headers",
            192,
        ),
        ("gateway", f"{root}/venv/bin/zelyonka-gateway", 128),
        ("agent", f"{root}/venv/bin/python {root}/run_stage_agent.py", 128),
    ]:
        privileged = name == "agent"
        extras = (
            (
                "User=root\nGroup=zelyonka-beta\nRuntimeDirectory=zelyonka-stage\nRuntimeDirectoryMode=0750\n"
                + f"ReadWritePaths={root}/agent-state {root}/data /etc/zelyonka-node /run/zelyonka-stage /run/zelyonka-node\n"
            )
            if privileged
            else (f"User=zelyonka-beta\nGroup=zelyonka-beta\nReadWritePaths={root}/data\n")
        )
        if name == "api":
            extras += f"LoadCredential=master.key:{root}/master.key\nLoadCredential=telegram.json:{root}/telegram.json\n"
        (root / "agent-state").mkdir(exist_ok=True)
        (root / "agent-state").chmod(0o700)
        write(
            f"/etc/systemd/system/zelyonka-stage-{name}.service",
            f"[Unit]\nDescription=Beta staging {name}\nAfter=network.target zelyonka-node-haproxy.service\n[Service]\nExecStart={command}\nMemoryMax={memory}M\n"
            + common
            + extras
            + "[Install]\nWantedBy=multi-user.target\n",
        )
    run(["systemctl", "daemon-reload"])
    run(
        [
            "systemctl",
            "start",
            "zelyonka-node-haproxy",
            "zelyonka-stage-agent",
            "zelyonka-stage-gateway",
            "zelyonka-stage-api",
        ]
    )
    write(root / "stack-prepared", "isolated staging only\n", 0o600)
    print("Staging components started; public production listeners unchanged")


if __name__ == "__main__":
    main()
