# Operations

Only administrators sign in to the dashboard. Create a DNS user by username, open its card and copy DoT/DoH settings or download the Apple profile. Send settings privately yourself. Recipients do not receive dashboard passwords or invitations.

Disabling a user revokes DNS access; rotating its key requires updating every device using that profile. Do not rotate keys just to change the username.

## Backup and restore

Use the CLI SQLite backup operation; preserve the corresponding master key, private deployment configuration, certificate/ACME credentials and installed release manifest. Store backups outside Git with restricted permissions. Stop writers when restoring a coherent snapshot, restore the matching release, then reconcile the agent before reopening forwarding.

## Catalog and filtering

Updates are prepared from a pinned upstream commit, validated and activated together. On failure preserve the last working catalog. Built-in protected routing policy is not editable through the dashboard or API; its source remains available in the public project. It does not bypass ad filtering.

## Certificates

Automate renewal for your own domain with your selected ACME provider. Validate the certificate/key match before installation. Reload only components consuming the renewed certificate. No production DNS API credentials belong in this repository.

## Diagnostics

Check service health, certificate validity, authenticated DoT/DoH, filtering backend and agent readiness. Record timestamps, query outcomes and the relevant client source address, never raw DNS credentials. A mobile connection may obtain a new address after reconnecting.

Do not interpret a successful website load as proof of native app or call support. Attach sanitized diagnostics and exact application/network versions when reporting failures.
