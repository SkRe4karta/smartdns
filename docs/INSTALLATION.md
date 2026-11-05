# Installation

Installer targets: Ubuntu 24.04/26.04 LTS x86_64. CI checks application installation and migration in a fresh environment; full host-service compatibility is recorded separately in the release acceptance report. Budget at least 1 GiB RAM and 2 GiB free disk. Use a validated release artifact, published SHA256 and exact manifest commit. Node is needed only for source builds. A public IPv4 is required; IPv6 is optional.

## Dedicated host

Run the `scripts/setup.py` command in README from the extracted, verified archive. The installer checks OS, architecture, address formats, disk and conflicting ports before configuring nginx, HAProxy, a separate AdGuard Home, application units and timers. Python 3.14.4 and uv 0.13.6 are pinned. Runtime requirements use hashes; the AdGuard image uses a digest.

Create A records for `dns.example.com` and `*.dns.example.com` pointing to your ingress. For IPv6 add matching AAAA records after validating the route. The default acme-dns registration prints a one-time CNAME for `_acme-challenge.dns.example.com`. Keep that delegation for renewals. DNS propagation may take time; dependency downloads and propagation are not load tests.

The certificate must cover both `dns.example.com` and `*.dns.example.com`. Do not install a private CA on client devices. Keep provider credentials, master key and database out of Git. Open inbound TCP 443/853 in your provider firewall and host policy. Port 53 is disabled by default. The filtering control port and agent RPC are private.

For an existing tunnel, also pass `--forward-mode tunnel --forward-source-ipv4 TUNNEL_ADDRESS --forward-interface TUNNEL_INTERFACE --expected-egress-ipv4 FOREIGN_PUBLIC_IPV4`. SmartDNS does not create the tunnel. Its policy table and priority must be unused or explicitly configured for this installation.

## Existing DNS provider plugin

Prepare a root-only certificate JSON and pass `--certificate-config /root/certificates.json`. It can override the Certbot directories/lineage and supply `certbot_args`, an argv list for an already installed DNS plugin. For example, the Cloudflare plugin uses `--dns-cloudflare` and `--dns-cloudflare-credentials /etc/smartdns/cloudflare.ini`. Use a token scoped to the relevant DNS zone. Do not put the token itself in argv, JSON examples or the repository.

A manual TXT challenge without an authentication hook cannot renew unattended. `acme-dns` and configured provider plugins automate DNS-01. The certificate timer runs twice daily with randomized scheduling. It renews only this installation's lineage.

## Shared host

Use `--mode shared`. Review `/etc/smartdns/ingress.d/` and private settings before integration. Preserve existing SNI routes, VPN listeners, firewall policies and certificates.

1. Prepare the dedicated service user, `/var/lib/smartdns`, `/var/lib/smartdns-agent` and master-key path. Data belongs to the application user; the master key remains root-only and is supplied to the API through systemd credentials.
2. Merge the nginx/HAProxy fragments. Bootstrap `smartdns-sources.acl` with `192.0.2.0/32`, origins with `^example\.com$`, and generate the direct-name ACL from `smartdns.policy.CONNECTIVITY_NAMES`.
3. Run a **separate** loopback AdGuard instance from `config/templates/AdGuardHome.yaml`, with a 512 MiB limit. The image digest is pinned in the installer. Keep existing VPN DNS separate.
4. Configure your wildcard certificate and `/etc/smartdns/certificates.json`. Managed certificate files live under `certs/versions/`; `certs/current` switches the pair atomically.
5. Install the application service units and timers from `config/templates`. Adapt private ports/unit names where needed. Prepare installation-scoped nftables sets for both families and the optional tunnel guard using `scripts/network.py`.
6. Validate `nginx -t` and `haproxy -c -f /etc/haproxy/haproxy.cfg` before reload.
7. Run `scripts/install.py apply ARCHIVE --sha256 HASH --commit SHA --uv /path/to/uv`. Non-default installations pass matching `--root`, `--settings`, and `--units`.
8. Run `smartdns create admin --admin` with `SMARTDNS_CONFIG` set; the password is requested privately. Run `smartdns catalog-refresh --bootstrap`, then enable the application, catalog and certificate timers.

Shared mode never automatically replaces a host's existing ingress. It requires operator integration before the application can serve clients.

## Verify and upgrade

Before distributing profiles, test authenticated DoT/DoH, rejected unknown credentials, a rejected unauthorized HTTPS client, filtering, the expected exit and renewal dry-run:

```sh
sudo python3 /opt/smartdns/current/scripts/certificates.py dry-run
```

Then apply the active production certificate once to verify the deployment hook. Staging certificates are refused by the deployment helper. DoT reloads the certificate for new handshakes; existing sessions continue.

Repeat setup with the verified next artifact to upgrade an installed default deployment. The same installed artifact is a no-op. Application updates preserve keys and policies. See OPERATIONS for coherent backups and rollback. If an installation was interrupted, review the reported failure before retrying; never delete the master key to start over.

Optional native game transport is documented separately in [GAMES.md](GAMES.md). It is opt-in, requires reviewed client-version pairs, and is not enabled by the normal installer.
