# Installation

Use a tagged release and verify its checksums and manifest. Build from a specific commit when no validated release artifact exists. Never run development setup scripts against an existing production server.

1. Prepare your own DNS A records for dns.example.com and *.dns.example.com, substituting a domain you control and your public IPv4.
2. Obtain a certificate covering the base and wildcard name using DNS-01. Keep ACME credentials private; configure automated renewal and a deployment hook.
3. Create a dedicated unprivileged service user and data, key and certificate directories. Copy config/example.json outside the release directory and supply real values.
4. Install the wheel and hash-locked requirements in a dedicated Python 3.14 environment. Build frontend with npm ci and npm run build, or use the prebuilt dashboard in the release artifact.
5. Run smartdns init and create an administrator with the CLI. Admin passwords are entered privately; no public registration exists.
6. Run separate AdGuard Home filtering on loopback. Configure nginx for the administrator HTTPS dashboard/DoH and HAProxy for approved HTTPS origins. DoT listens on 853. Configure real client address forwarding only from explicitly trusted local ingress.
7. Validate nginx and HAProxy configuration before reload. On shared VPSs retain existing listeners, VPN SNI routes and firewall rules. Use the installation templates as fragments, not replacements for existing configuration.
8. Enable the API, DNS gateway and limited privileged agent. Configure certificate and catalog update timers. Verify authenticated DNS and rejection of unauthorized proxy clients before distributing profiles.

Do not expose the agent socket or AdGuard administration UI publicly. Do not open an unrestricted recursive DNS server. Archive installation-specific commands in a private runbook.

## Concrete setup (dedicated Debian/Ubuntu host)

Install systemd, Python 3.14.4, uv 0.13.6, Docker, HAProxy, nginx, nftables, Certbot and your DNS-01 plugin. Node 24.21.0 is needed only for source builds (see `.node-version` for the exact project pin). Port 80 is optional for DNS-01; inbound TCP 443 and 853 are required. No public recursive port 53 is enabled by default.

Download the release archive and SHA256SUMS; run `sha256sum -c SHA256SUMS` before extraction. Review `manifest.json`, including its commit and clean-tree flag. Prepare a private configuration file and existing certificate before starting services. Documentation IPs in examples must be replaced.

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin smartdns
sudo install -d -m 0755 /opt/smartdns /opt/smartdns/releases
sudo install -d -o smartdns -g smartdns -m 2770 /var/lib/smartdns
sudo install -d -m 0700 /var/lib/smartdns-agent
sudo install -d -o root -g smartdns -m 0750 /etc/smartdns
sudo install -o root -g smartdns -m 0640 config/example.json /etc/smartdns/settings.json
```

Edit `/etc/smartdns/settings.json` with your actual domain/IP, paths and any reserved SNI names. Install your certificate/key in `/etc/smartdns/certs`, root:smartdns, mode 0640 (directory 0750). Keep `/etc/smartdns/master.key` root-only; systemd passes it to the API using LoadCredential.

Use `config/templates/AdGuardHome.yaml` for a **separate** AdGuard instance. The pinned container image is `adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0`. Mount private conf/work directories under `/opt/adguardhome`, bind only loopback ports 3010/5354, use host networking and a 512 MiB memory limit. Never expose its unauthenticated control port. Its own query history is disabled; SmartDNS retains events for 24 hours and aggregates for seven days.

Merge the HAProxy/nginx/nftables templates into your host configuration, replacing example domain, paths and **all** example/own server destination IPs in the forbidden list. Bootstrap `/etc/haproxy/smartdns-sources.acl` with `192.0.2.0/32` and origins ACL with `^example\.com$`. Generate the exact direct-name file from the installed policy:

```sh
/opt/smartdns/current/venv/bin/python -c 'from smartdns.policy import CONNECTIVITY_NAMES; print("\n".join(sorted(CONNECTIVITY_NAMES)))' | sudo tee /etc/haproxy/smartdns-direct.acl >/dev/null
```

For first setup before a `current` link exists, use the same `CONNECTIVITY_NAMES` from the archive source. ACL files belong to root; the agent is the only writer. Persist the `inet smartdns` set across reboot in your distribution's nftables service. The template adds its own table and does not flush other tables. Validate `haproxy -c -f /etc/haproxy/haproxy.cfg` and `nginx -t` before reload.

Install the three service units and catalog timer from `config/templates/` to `/etc/systemd/system/`. Configure the API systemd credential and gateway certificate group permissions. Initial installation/upgrades use the same verified artifact installer:

```sh
sudo systemctl daemon-reload
sudo python3 scripts/install.py apply /path/to/smartdns-archive.tar.gz --sha256 CHECKSUM --commit COMMIT --uv /path/to/uv
sudo env SMARTDNS_CONFIG=/etc/smartdns/settings.json /opt/smartdns/current/venv/bin/smartdns create admin --admin
sudo env SMARTDNS_CONFIG=/etc/smartdns/settings.json /opt/smartdns/current/venv/bin/smartdns catalog-refresh --bootstrap
sudo systemctl enable smartdns-api smartdns-gateway smartdns-agent smartdns-catalog.timer
sudo systemctl start smartdns-catalog.timer
```

The CLI asks for the administrator password on the terminal; passwords and DNS credentials must not be command-line arguments. Create the administrator after the initial install; the dashboard cannot authenticate until this step is complete. Run the installer after ingress/filtering setup; it installs application dependencies, initializes/migrates the database and starts only its explicitly named application units. It never replaces ingress, firewall, certificates or unrelated units.

Configure Certbot's DNS-01 renewal for your provider and use `scripts/install_certificate.sh` as the deploy hook. `scripts/acme_auth.py` supports an existing acme-dns registration supplied at `/etc/smartdns/acme-dns.json`; credentials are not registered or published by this project. Store the credentials root-only, and add the provider's verification CNAME once. Both the base name and wildcard must be covered. Test renewal with your chosen provider before distribution.
