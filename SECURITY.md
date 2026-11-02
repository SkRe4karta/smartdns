# Security

Report vulnerabilities through this repository's **Security → Report a vulnerability**. Include the affected version, expected/actual behavior and a sanitized reproduction. Do not publish passwords, DNS hostnames/URLs containing keys, master keys, session cookies, databases or private certificates.

The administrator dashboard controls credentials and sees DNS/IP history. Use a strong password, enable optional TOTP, keep recovery codes offline and terminate unused sessions. The API is unprivileged; the private agent has narrowly defined operations and no public listener. Do not expose AdGuard administration or the HAProxy Runtime API.

DNS credentials authorize requests; HTTPS admission is ultimately source-IP based. Shared NAT is a shared admission boundary. A valid key works from any reachable supported public IPv4/IPv6 network; filtering and access do not depend on a static geographic IP pool. A network can still block access to the server or encrypted DNS port.

An exposed credential must be revoked/rotated. Removing it from Git history does not revoke it, remove external copies or guarantee cache erasure. Keep production state outside Git and check diagnostics/screenshots before sharing.

Known critical/high production dependency vulnerabilities and access-control failures block a release. Passing checks is scoped evidence, not a guarantee that no unknown vulnerability exists. Maintain host updates and verify the release manifest/checksum/provenance before installation.
