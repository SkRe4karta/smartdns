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
