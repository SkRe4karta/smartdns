# Configuration

Set `SMARTDNS_CONFIG` to an absolute private JSON path, normally `/etc/smartdns/settings.json`. Start with `config/example.json`; replace example values before startup. The service rejects missing/invalid public addresses, unknown fields and deployed test mode.

| Setting | Meaning |
|---|---|
| `public_url` | HTTPS origin, e.g. `https://dns.example.com` |
| `public_ipv4` | Actual public ingress IPv4; required |
| `public_ipv6` | Actual public ingress IPv6; empty disables IPv6 ingress |
| `forward_mode` | `local` or `tunnel` |
| `forward_source_ipv4` | Tunnel-local IPv4 used by origin connections |
| `forward_interface` | Existing tunnel interface, required in tunnel mode |
| `expected_egress_ipv4` | Expected foreign public IPv4; the agent probes it in tunnel mode |
| `forward_route_table` / `forward_route_priority` | Installation-owned policy table/priority; defaults 28443/18443; avoid conflicts |
| `fast_quic_fallback` | Reject UDP/443 at ingress so web clients use TCP promptly; disable if that exact address serves another UDP/443 protocol |
| `reserved_sni` | Hostnames belonging to other services sharing TCP/443 |
| `data_dir` | SQLite and diagnostics storage |
| `master_key_file` | Root-only encryption key, outside database and Git |
| `cert_file` / `key_file` | Managed `certs/current` certificate paths |
| `certificate_status_file` | Renewal/deployment status visible to administrators |
| `dns_concurrency`, `dot_connections`, `dot_pipeline` | Bounded query and connection capacity; defaults 150/256/16 |
| `query_timeout` | Total DNS processing deadline, default eight seconds |
| `plain_dns_enabled` | Legacy IP-authorized DNS; false for new installations |

Other port/path defaults are defined in `Settings`. Keep `local_exit_id`, agent paths and ingress ACL names consistent. Never edit a deployed configuration to enable `test_mode`.

## Tunnel mode

The tunnel is provisioned by the operator, not purchased or created by SmartDNS. Origin forwarding binds the configured tunnel source IPv4. Policy routing and an output guard prohibit fallback to the host's normal interface. The agent checks the observed exit address; a failed/mismatched exit closes forwarding admission. The installer emits the HAProxy source binding; a shared installation must merge the same binding.

`network.py` changes only the installation's nftables chains/sets and configured policy-route table/priority. It does not flush the host firewall. Choose an unused table and priority. Do not disable the unreachable route or output guard to fix a connectivity error.

## IPv6

Create base and wildcard AAAA records only after IPv6 listeners, source admission and origin forwarding pass acceptance. A/AAAA for routed domains reflect the family observed on the authenticated DNS request. HTTPS/SVCB records for routed names do not advertise an alternate origin. DNS cannot safely infer a client's unrelated IPv4 from its IPv6 or authorize unseen addresses.

## Certificates

`/etc/smartdns/certificates.json` is root-owned, private configuration for Certbot directories, lineage, deployment paths and the gateway unit. Provider credentials are separate root-only files. `acme-dns.json` can specify an HTTPS `api_url` for a self-hosted provider. Optional `source_address` binds API requests to a local tunnel address when the provider is unreachable over the default route; configure that address's routing first. TLS verification remains enabled.

Gemini uses the upstream `google-deepmind` source and exact `extra_domains` from the service manifest, including its mobile API. These installation-maintained additions are merged on every catalog activation, including cached snapshots. See [upstream list](https://github.com/v2fly/domain-list-community/blob/master/data/google-deepmind) and [Google network guidance](https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/gemini-app-firewall-settings). Shared analytics/advertising domains are not broadly exempted from filtering; system connectivity checks retain their priority. App access still depends on account eligibility and the foreign exit's reputation.

Supercell imports the maintained `supercell` source and retains explicit resource/ID endpoints for Clash Royale, Clash of Clans, Brawl Stars, Hay Day and Boom Beach. This provides HTTPS routing, not a generic game transport. TCP game ports (for example 9339), UDP and hardcoded destinations are not carried by the HTTPS listener; validate login and gameplay separately.

When Android Private DNS fails only after VPN activation, test TCP/TLS 853 and the complete DNS exchange from the VPN exit. Do not publish ingress AAAA records or configure `public_ipv6` until that path is reachable from clients and VPN exits. An assigned IPv6 address alone does not prove reachability. Disable unusable AAAA records and leave `public_ipv6` empty until repaired; ordinary upstream IPv6 answers remain supported. Keep exact OS connectivity-probe exclusions.

Native Supercell game hostnames (`DIRECT_GAME_NAMES` in policy.py) resolve normally even when their parent domain is in the HTTPS catalog. Their resource and ID domains continue through the configured foreign exit. This prevents a broad imported rule from directing native TCP game connections at an ingress with no corresponding game transport. Explicit administrator route overrides still take precedence. Direct game connections can still be restricted by the game operator or network; HTTPS routing alone does not certify gameplay.
