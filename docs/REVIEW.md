# Release review

Version: 1.0.0. Final readiness is recorded in the commit-specific acceptance asset.

Review scope: administrator authorization/CSRF/body limits, optional TOTP/replay/recovery, secret handling, IPv4/IPv6 admission, private RPC, catalog protection, guarded tunnel routing, bounded DNS/telemetry, certificate deployment and archive/installation integrity. The release PR records concrete findings, corrections and checks. This is an engineering code review, not an independent penetration-test certification.

Known boundaries: source-IP admission is shared behind NAT; DNS cannot reroute hardcoded IPs or arbitrary protocols; ECH without usable SNI is unsupported; IPv4-only applications may require IPv4 DNS transport; one ingress/exit provides no host-level redundancy. See README and VALIDATION.
