# Architecture

React/TypeScript administrator UI -> FastAPI API -> SQLite. DNS users are credentials and filtering policies, not dashboard principals. Argon2id protects administrator passwords; server sessions use Secure/HttpOnly cookies and CSRF checks.

The DNS gateway authenticates DoT/DoH credentials, asks a separate loopback AdGuard Home for filtering, and selectively rewrites supported domain answers to one configured ingress. A limited privileged agent maintains temporary client-IP permissions in the HTTPS forwarder. User HTTPS is passed through without TLS interception or installing a private CA on client devices.

Network validation names and the installation's own names must resolve directly. Their protection takes priority over imported routing rules. Other IPv6 answers remain intact; routed AAAA/HTTPS/SVCB answers must not accidentally bypass the chosen forwarding route.

DNS cannot identify physical devices or reroute hardcoded destination IPs. Multiple devices using one credential have common filtering and statistics. Proxy access is ultimately IP-scoped: users behind a shared public IP share that network admission boundary.
