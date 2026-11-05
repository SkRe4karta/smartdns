#!/usr/bin/env python3
"""Render an opt-in, fail-closed Supercell TCP fragment for reviewed client versions.

This only writes a reviewable fragment: it never opens a firewall or reloads ingress.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path

GAME_HOSTS = {
    "royale": "game.clashroyaleapp.com",
    "brawl": "game.brawlstarsgame.com",
    "clans": "gamea.clashofclans.com",
}
FORBIDDEN = (
    "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 "
    "172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 "
    "198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"
)


def render(cfg: dict, versions: dict, resolver: str = "smartdns_public_dns", mss: int = 0) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,60}", resolver):
        raise ValueError("Invalid resolver section name")
    if type(mss) is not int or not (mss == 0 or 536 <= mss <= 1460):
        raise ValueError("MSS must be zero (kernel default) or between 536 and 1460")
    bind_options = f" mss {mss}" if mss else ""
    ingress = ipaddress.IPv4Address(cfg["public_ipv4"])
    if not ingress.is_global:
        raise ValueError("Configure a public ingress IPv4")
    ipv6 = ipaddress.IPv6Address(cfg["public_ipv6"]) if cfg.get("public_ipv6") else None
    if ipv6 and not ipv6.is_global:
        raise ValueError("Configure a public ingress IPv6")
    source = ""
    forbidden_hosts = str(ingress) + "/32"
    mode = cfg.get("forward_mode", "local")
    if mode not in ("local", "tunnel"):
        raise ValueError("Configure local or tunnel forwarding")
    if mode == "tunnel":
        if not cfg.get("forward_interface") or not cfg.get("expected_egress_ipv4"):
            raise ValueError("Tunnel transport requires the guarded egress configuration")
        source = " source " + str(ipaddress.IPv4Address(cfg["forward_source_ipv4"]))
        forbidden_hosts += " " + str(ipaddress.IPv4Address(cfg["expected_egress_ipv4"])) + "/32"
    seen: set[tuple[int, int]] = set()
    matches = []
    for game, entries in versions.items():
        if game not in GAME_HOSTS or not isinstance(entries, list):
            raise ValueError("Unknown game or invalid version list")
        for index, item in enumerate(entries):
            if not isinstance(item, dict) or set(item) != {"protocol", "major"}:
                raise ValueError("Version entry requires protocol and major")
            pair = (item["protocol"], item["major"])
            if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair):
                raise ValueError("Version fields must be unsigned 32-bit integers")
            if pair in seen:
                raise ValueError("Ambiguous or duplicate game handshake: refuse to guess")
            seen.add(pair)
            matches.append((game, index, pair))
    if not matches or len(matches) > 100:
        raise ValueError("Configure between one and 100 reviewed game versions")
    text = f"""# Optional native TCP transport. Review versions and firewall before enabling.
frontend smartdns_games_tcp
    bind {ingress}:9339{bind_options}
"""
    if ipv6:
        text += f"    bind [{ipv6}]:9339{bind_options}\n"
    text += """    mode tcp
    maxconn 128
    timeout client 5m
    stick-table type ip size 4096 expire 1m store conn_rate(10s),conn_cur
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc0_conn_rate gt 30 }
    tcp-request connection reject if { sc0_conn_cur gt 12 }
    tcp-request connection reject unless { nbsrv(smartdns_agent_health) gt 0 }
    tcp-request connection reject unless { src -f /etc/haproxy/smartdns-sources.acl }
    tcp-request inspect-delay 5s
    acl game_hello req.payload(0,2),hex -m str 2774
    tcp-request content set-var(sess.game_protocol) req.payload(7,4),hex if { req.len ge 19 }
    tcp-request content set-var(sess.game_major) req.payload(15,4),hex if { req.len ge 19 }
    tcp-request content reject if { req.len ge 19 } !game_hello
    tcp-request content accept if { req.len ge 19 }
"""
    for game, index, (protocol, major) in matches:
        tag = f"game_{game}_{index}"
        text += f"    acl {tag}_p var(sess.game_protocol) -m str {protocol:08X}\n"
        text += f"    acl {tag}_m var(sess.game_major) -m str {major:08X}\n"
        text += f"    use_backend smartdns_game_{game} if {tag}_p {tag}_m\n"
    text += "    default_backend smartdns_game_deny\n\nbackend smartdns_game_deny\n    mode tcp\n    tcp-request content reject\n"
    for game in sorted({row[0] for row in matches}):
        host = GAME_HOSTS[game]
        text += f"""
backend smartdns_game_{game}
    mode tcp
    timeout connect 5s
    timeout server 5m
    acl game_enabled str({host}) -m reg -f /etc/haproxy/smartdns-origins.acl
    tcp-request content reject unless game_enabled
    tcp-request content do-resolve(sess.game_target,{resolver},ipv4) str({host})
    tcp-request content reject unless {{ var(sess.game_target) -m found }}
    acl game_forbidden var(sess.game_target) -m ip {FORBIDDEN} {forbidden_hosts}
    tcp-request content reject if game_forbidden
    tcp-request content set-dst var(sess.game_target)
    server game 0.0.0.0:9339{source} maxconn 64
"""
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, default=Path("/etc/smartdns/settings.json"))
    parser.add_argument("--versions", type=Path, required=True)
    parser.add_argument("--resolver", default="smartdns_public_dns")
    parser.add_argument(
        "--mss", type=int, default=0, help="Optional game-listener MSS; zero retains kernel default"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    content = render(
        json.loads(args.settings.read_text()), json.loads(args.versions.read_text()), args.resolver, args.mss
    )
    args.output.write_text(content)
    args.output.chmod(0o600)
    print("Fragment prepared; validate the merged HAProxy config before reload. No firewall was changed.")


if __name__ == "__main__":
    main()
