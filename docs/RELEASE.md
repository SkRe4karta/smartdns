# Release process

Use main for published versions, develop for integration and feature/fix branches for pull requests. Pin GitHub Actions by SHA, use minimal permissions and retain branch protection. Never publish an artifact built from a dirty working tree as a release.

For 0.3.0-rc.1 schedule two small intermediate verification batches and one final batch. Required failures block release. Record which application/device scenarios were actually checked; do not replace missing client verification with server-only checks.

Build a commit-specific archive and SHA256SUMS; include the source SHA and file hashes in a manifest. Deploy that artifact, then compare its SHA/version to the installed instance. Keep production configuration and credentials outside it.

Historical tags are archival source snapshots. After privacy-driven history rewriting their old binary assets and hashes must not be presented as verified builds of the rewritten commits. Remove affected old assets and invalidate stale links.
