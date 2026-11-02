# Validation

The release report records the exact tested commit, artifact checksum and installed manifest. Required CI: backend, frontend, integration, security, release-check. The `release-check` job installs the verified wheel and hash-locked dependencies in a fresh Python environment on the Ubuntu 24.04 CI runner, then checks migration, key preservation and SQLite backup/restore. It does not boot a complete VPS or certify systemd, Docker and ACME behavior on both Ubuntu versions.

Full nested Docker/systemd installation jobs were retired because they coupled application acceptance to privileged container behavior. Live service startup, real DNS forwarding, certificate renewal and client acceptance are separate deployment gates. Ubuntu 24.04/26.04 remain installation targets; each release report must identify which platform was actually exercised. A green application installation check does not replace live deployment acceptance.

Validation has two focused intermediate batches and one final batch. Network runs are bounded to two-minute cycles; no long production load campaign is required. Repeat only affected scenarios after fixes, then run required final CI.

Acceptance covers migration/key preservation, username creation and admin-only connections, TOTP/recovery/replay, per-user IP/error attribution, pagination/retention, DoH GET/POST, persistent/pipelined DoT, IPv4/IPv6 source admission, rejected unknown users, revocation, agent/tunnel failure, catalog/filter protection, certificate renewal/deployment, installation/update/restore and desktop system DNS.

Measure direct and routed sites consistently before/after: DNS, TCP/TLS, first response, short transfer, errors and observed exit. Report median and p95 with sample counts. HTTP 403 from a bot-protected homepage alone does not prove an application is unavailable. Validate actual ChatGPT/Codex/Twitch behavior separately and state untested functions.

Short runs do not establish multi-day availability, maximum throughput, every operator/network or all native app protocols. Missing mandatory acceptance is reported as pending and blocks a completed 1.0 publication.
