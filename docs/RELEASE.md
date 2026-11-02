# Release process

`main` contains published versions; `develop` integrates changes; feature/fix branches use PRs. Release stabilization uses `release/1.0.0`. Protected branches require green backend/frontend/integration/security/release-check jobs, forbid force-push/deletion and apply to administrators. No second-account approval is required.

Review migrations, authorization, privileged operations, production dependency advisories and sanitized assets. Fix blocking findings before merge. Record the reviewer and actual checks without implying independent human approval.

Build from a clean exact `main` commit. Produce the archive, SHA256SUMS, dependency inventory and provenance. Verify clean installation/update/restore; deploy that artifact, compare installed SHA/version/hash, and complete live acceptance before tagging `v1.0.0` and publishing.

Release assets and public acceptance contain no private domains, IPs, SSH aliases, secrets or installation paths. Private operational details stay outside Git. Archival pre-1.0 source tags are not newly validated binaries. History rewriting cannot erase external downloads/caches.
