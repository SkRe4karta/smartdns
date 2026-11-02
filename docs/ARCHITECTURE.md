# Architecture

React/TypeScript administrator UI → FastAPI → SQLite with versioned migrations. DNS recipients have a username, DNS credential and filtering policy; they cannot sign in. Credentials are hashed for authentication and encrypted for administrator display. The master key is outside SQLite/Git and supplied to the API through systemd credentials.

The gateway authenticates DoT/DoH, obtains filtered DNS from a dedicated loopback AdGuard instance, then rewrites supported A/AAAA answers. Protected connectivity probes resolve separately and cannot be overridden through ordinary route/filter controls. HTTPS/SVCB for routed names cannot advertise a bypass origin. Unknown domains resolve normally.

A private Unix-socket agent controls temporary client IP admissions, filtering configuration and transactional HAProxy ACLs. Its health gates new forwarded connections. Source-IP permissions expire after 30 minutes and refresh on routed requests. Disabling an account or rotating its key removes its leases; shared-IP permissions from other active accounts remain effective.

Client HTTPS → HAProxy on the ingress → original HTTPS server. TLS remains between client and original server. In tunnel mode, origin sockets bind the tunnel-local IPv4, use a guarded policy route and leave through the expected foreign public address. Loss of the route must not silently expose the ingress address as a fallback exit.

IPv4/IPv6 are admitted independently. Routed DNS responses use the authenticated request's family; unmodified domains retain ordinary IPv6 answers. IPv4-only apps with IPv6 DNS transport are a documented boundary. Hardcoded-IP traffic, non-HTTPS protocols and encrypted ClientHello without usable SNI cannot be transparently forwarded by this design.

The telemetry queue is bounded and written in batches. Full events are retained 24 hours, network/time aggregates seven days, with storage limits. Unknown credentials never enter logs as raw secrets. The dashboard shows recorder errors/drops. The application records DNS behavior, not message contents or decrypted website traffic.

The default deployment has one ingress and one exit, which are single points of failure. Shared deployments retain existing VPN/Telegram listeners and use installation-scoped configuration and firewall rules.
