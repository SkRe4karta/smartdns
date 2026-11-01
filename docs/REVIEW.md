# Implementation review

Version: 0.3.0-rc.1, stabilization in progress.

- Identity migration keeps encrypted DNS credentials, filtering, activity and administrator sessions; recipient web sessions, enrollment tokens and passwords are revoked.
- All target-user connection/profile/filter endpoints require the administrator dependency and mutations require CSRF. Removed invitation, OIDC and egress-management endpoints return 404.
- System routing is pinned, compiled into the wheel, omitted from catalog serialization and takes precedence over manual overrides. The owner can still inspect and fork the source. User ad filtering is independent.
- Exact OS connectivity probes resolve through a separate unfiltered upstream and never receive the forwarding address. Imported sibling domains retain routing. Proxy ingress retains source authorization, public-address destination checks and a separate agent-health watchdog.
- Valid rate-limited DNS messages return REFUSED inside the existing DoT connection. Invalid credentials close access; a revoked credential is rechecked on every request.
- Shared-host integration requires preserving existing VPN/other-service SNI routes and keeping production values in private configuration. Public templates do not replace a live ingress.

The second control batch found a nested SQLite migration transaction and ambiguous responses for removed POST endpoints. Both were corrected; the affected checks passed. Final CI, artifact installation and external-device acceptance are recorded separately; this review is not a substitute for them.
