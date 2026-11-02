# Validation and acceptance

This document defines release checks; the commit-specific acceptance report attached to a release records actual results. A version number alone is not evidence of passing checks. Unfinished mandatory scenarios block publication of a ready release candidate.

The three planned batches are:

1. Privacy: managed source history, documentation, examples, secrets and artifact contents. Keep private backups and record cache limitations separately.
2. Admin migration/access/policy: preserve DNS credentials, administrator access, filtering and statistics; create active username-only profiles; deny recipient access; protect system rules and render one connection card.
3. Final: required backend/frontend/integration/security/release CI, exact-commit build, wheel-only clean installation, upgrade/backup restoration, DoH/DoT, profiles and short external-device acceptance. Corrective checks address failures or subsequent changes; no sustained load runs are used.

The bounded automated suite contains 23 Python scenarios, three API-transport frontend scenarios, three browser scenarios and one clean-install/upgrade/backup-restore scenario. Required CI reports these checks under five protected contexts. The installation scenario intercepts service-control commands while restoring a real SQLite backup, application symlink, key and installed identity.

External acceptance records Android Private DNS internet validation on Wi-Fi and mobile data, desktop application DNS, Twitch video in the browser/mobile app and an actual Codex request. Record device/browser limits such as unavailable HEVC/1440p separately from DNS failure. Successful desktop/browser traffic does not prove every VPN, native app, game, call or region. Apple profile generation and authorization are distinct from a physical-device installation test.

Record the source SHA, archive SHA256, installed manifest identity, CI links, client observations, rollback command location and remaining limits in the acceptance report. Production configuration and private rollback paths do not belong in its public copy. Historical sanitized tags are archived source, not newly validated installable releases.
