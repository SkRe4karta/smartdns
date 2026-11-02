# Validation

The release report records the exact tested commit, artifact checksum and installed manifest. Required CI: backend, frontend, integration, security, release-check. First-install checks cover isolated Ubuntu 24.04/26.04 environments; synthetic certificates/configuration are used where public issuance cannot be exercised in CI. Live certificate renewal and real client applications are checked separately on the deployment.

Validation has two focused intermediate batches and one final batch. Network runs are bounded to two-minute cycles; no long production load campaign is required. Repeat only affected scenarios after fixes, then run required final CI.

Acceptance covers migration/key preservation, username creation and admin-only connections, TOTP/recovery/replay, per-user IP/error attribution, pagination/retention, DoH GET/POST, persistent/pipelined DoT, IPv4/IPv6 source admission, rejected unknown users, revocation, agent/tunnel failure, catalog/filter protection, certificate renewal/deployment, installation/update/restore and desktop system DNS.

Measure direct and routed sites consistently before/after: DNS, TCP/TLS, first response, short transfer, errors and observed exit. Report median and p95 with sample counts. HTTP 403 from a bot-protected homepage alone does not prove an application is unavailable. Validate actual ChatGPT/Codex/Twitch behavior separately and state untested functions.

Short runs do not establish multi-day availability, maximum throughput, every operator/network or all native app protocols. Missing mandatory acceptance is reported as pending and blocks a completed 1.0 publication.
