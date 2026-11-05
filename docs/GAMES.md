# Optional native Supercell TCP transport

The normal catalog proxies HTTPS resources, account and store hosts. Exact native game hosts resolve directly by default because they use a different protocol/port. If a game rejects the direct client's region, a native transport is required in addition to DNS.

The opt-in `scripts/game_transport.py` produces an HAProxy TCP/9339 fragment. It forwards the original stream without TLS termination, decrypting login packets or installing a CA. It selects a fixed game destination using a reviewed pair of public fields in the initial ClientHello: protocol at byte 7 and major version at byte 15 (four bytes each, network byte order, after the seven-byte header). The expected packet ID is 10100. **Protocol alone is not a game identifier**: assignments changed between games/releases. Unknown and ambiguous version pairs are rejected; never guess a destination.

`config/game-versions.example.json` contains observed client versions, not a promise for every installed or future game release. Configure only client versions you have validated. Add a pair after observing that game's public handshake fields and testing it; if two games share a pair the renderer refuses it. Do not enable a broad fallback. Client updates can require a reviewed version-map update. This transport is experimental and optional.

Prepare a root-owned version map outside Git, then render:

```sh
sudo python3 /opt/smartdns/current/scripts/game_transport.py \
  --settings /etc/smartdns/settings.json \
  --versions /etc/smartdns/game-versions.json \
  --output /etc/smartdns/ingress.d/games.cfg
```

The fragment expects the existing `smartdns_public_dns` resolver, `smartdns_agent_health` watchdog backend and runtime source/origin ACL files. Use `--resolver` if a shared installation names the public resolver differently. It does not alter the installed HAProxy config, reload services, create a DNS user or open firewall ports.

Merge the fragment once into the existing ingress config, validate with `haproxy -c` and reload. Open TCP/9339 only on the configured ingress address in the host/provider firewall. Verify unauthorized sources are rejected and that expiry/revocation and agent failure close new connections. Connection counts/rates and timeouts are bounded. Only the fixed known game hosts can be reached. Public upstream DNS is used, and internal/self destinations are rejected. Tunnel mode binds the configured source address and relies on the existing guarded source route; a working foreign egress and watchdog are mandatory. Preserve existing VPN listeners.

In **Catalog and routes**, add an exact proxy override for each enabled native hostname, associated with Supercell. Leave other native game hostnames direct. Resources and ID continue using the ordinary HTTPS route. Do not enable the hostname before its native listener and version mapping are ready.

Validate lobby/login and gameplay separately on actual devices. UDP battle servers and hardcoded destinations are not proxied by TCP/9339, and may still require a different transport. Removal: change enabled native overrides back to direct, close the dedicated firewall rule, remove the optional fragment, validate and reload HAProxy. Keep HTTPS resource routing enabled if desired.

If measurements show retransmission/PMTU problems, `--mss 1200` can prepare a scoped game-listener adjustment; default zero preserves kernel behavior. Apply to new connections and compare loss and client responsiveness before keeping it. It does not shorten the geographic RTT to the official server. See [HAProxy MSS documentation](https://docs.haproxy.org/3.0/configuration.html#5.1-mss).
