#!/usr/bin/env python3
"""Idempotent, installation-scoped firewall and optional existing-tunnel policy."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path


def run(args: list[str], **kwargs) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10, **kwargs).stdout


def main() -> None:
    cfg = json.loads(Path(os.environ.get("SMARTDNS_CONFIG", "/etc/smartdns/settings.json")).read_text())
    if os.geteuid() != 0:
        raise ValueError("Run as root")
    table = cfg.get("nft_table", "smartdns")
    if not re.fullmatch("[a-zA-Z0-9_]{1,40}", table):
        raise ValueError("Invalid nftables table")
    v4 = str(ipaddress.IPv4Address(cfg["public_ipv4"]))
    v6 = str(ipaddress.IPv6Address(cfg["public_ipv6"])) if cfg.get("public_ipv6") else ""
    check = subprocess.run(["nft", "list", "table", "inet", table], capture_output=True)
    rules = []
    if check.returncode:
        rules.append(f"add table inet {table}")
    for family in (4, 6):
        if subprocess.run(
            ["nft", "list", "set", "inet", table, f"activated_v{family}"], capture_output=True
        ).returncode:
            rules.append(
                f"add set inet {table} activated_v{family} {{ type ipv{family}_addr; flags timeout; }}"
            )
    for chain, hook in [("smartdns_quic", "input"), ("smartdns_egress", "output")]:
        if subprocess.run(["nft", "list", "chain", "inet", table, chain], capture_output=True).returncode:
            rules.append(
                f"add chain inet {table} {chain} {{ type filter hook {hook} priority -10; policy accept; }}"
            )
        rules.append(f"flush chain inet {table} {chain}")
    if cfg.get("fast_quic_fallback", True):
        rules.append(
            f"add rule inet {table} smartdns_quic ip daddr {v4} udp dport 443 reject with icmp type port-unreachable"
        )
        if v6:
            rules.append(
                f"add rule inet {table} smartdns_quic ip6 daddr {v6} udp dport 443 reject with icmpv6 type port-unreachable"
            )
    if cfg.get("plain_dns_enabled"):
        chain = "smartdns_plain"
        if subprocess.run(["nft", "list", "chain", "inet", table, chain], capture_output=True).returncode:
            rules.append(
                f"add chain inet {table} {chain} {{ type filter hook input priority -10; policy accept; }}"
            )
        rules.append(f"flush chain inet {table} {chain}")
        for protocol in ("tcp", "udp"):
            rules.append(
                f"add rule inet {table} {chain} ip daddr {v4} {protocol} dport 53 ip saddr != @activated_v4 drop"
            )
    tunnel = cfg.get("forward_mode") == "tunnel"
    if tunnel:
        interface = cfg["forward_interface"]
        if not re.fullmatch("[a-zA-Z0-9_.-]{1,15}", interface):
            raise ValueError("Invalid tunnel interface")
        source = str(ipaddress.IPv4Address(cfg["forward_source_ipv4"]))
        rules.append(
            f'add rule inet {table} smartdns_egress ip saddr {source} ip daddr 127.0.0.0/8 oifname "lo" accept'
        )
        rules.append(f'add rule inet {table} smartdns_egress ip saddr {source} oifname != "{interface}" drop')
    run(["nft", "-f", "-"], input="\n".join(rules) + "\n")
    if tunnel:
        number = int(cfg.get("forward_route_table", 28443))
        priority = int(cfg.get("forward_route_priority", 18443))
        if number in (0, 253, 254, 255) or not 1 <= number <= 2147483647 or not 1 <= priority <= 32765:
            raise ValueError("Invalid policy routing table/priority")
        # An unreachable fallback exists even before a tunnel becomes available.
        run(
            [
                "ip",
                "-4",
                "route",
                "replace",
                "unreachable",
                "default",
                "table",
                str(number),
                "metric",
                "32760",
            ]
        )
        existing = json.loads(run(["ip", "-j", "-4", "rule", "show"]))
        matching = [r for r in existing if r.get("priority") == priority]
        if matching and any(
            str(r.get("table")) != str(number) or r.get("src") not in (source, source + "/32")
            for r in matching
        ):
            raise ValueError("Policy priority is already used by another service")
        if not matching:
            run(["ip", "-4", "rule", "add", "priority", str(priority), "from", source, "table", str(number)])
        run(
            ["ip", "-4", "route", "replace", "table", str(number), "default", "dev", interface, "src", source]
        )
    print("SmartDNS network policy applied; unrelated tables and listeners retained")


if __name__ == "__main__":
    main()
