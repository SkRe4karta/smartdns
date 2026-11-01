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

## Application upgrade and rollback commands

Use `scripts/install.py apply ARCHIVE --sha256 HASH --commit SHA` from the verified release. It prepares dependencies before stopping the three application writers, saves a SQLite snapshot, encryption key and configuration in a mode-0700 backup, migrates and atomically switches `current`. The installer reports the backup path and records it in `/opt/smartdns/rollback-location`. Existing ingress configuration is retained.

```sh
sudo python3 /opt/smartdns/current/scripts/install.py rollback /opt/smartdns/backups/TIMESTAMP
```

Supply the same `--root`, `--settings` and `--units` options for non-default installations. Rollback restores the previous binary directory, database, master key and configuration; certificate/ingress changes require their own private backup. For an interrupted first install, rollback removes `current` and leaves services stopped. Off-host encrypted backups are still required: an on-disk rollback copy does not protect against host loss.

Do not share `/opt/smartdns/installed.json` without reviewing its installation-specific backup path. Public release manifests contain only version, commit and artifact checksums.

## OS connectivity and VPNs

Exact connectivity probes in `src/smartdns/policy.py` always bypass imported routing and AdGuard, using a separately configured public DoH resolver (`probe_resolver`). This prevents ad filters and broad catalog suffixes from turning expected HTTP 204 probes into requests to the HTTPS forwarder. The HAProxy direct-name ACL also rejects these destinations. Do not replace these exact exclusions with whole Google/Microsoft/CDN exceptions. In particular, `www.google.com` is excluded in full: DNS cannot distinguish URL paths on that hostname.

Android Private DNS is a DNS setting, not a VPN. With a real VPN, its client may override DNS or change the HTTPS source address independently. DNS authorization and redirected HTTPS must use the same public egress. Reconnect DNS after switching networks, and configure the VPN's DNS policy consistently. Universal compatibility with untested VPN apps is not claimed; never open proxy access globally as a workaround.

Sources: [Samsung connectivity probes](https://docs.samsungknox.com/admin/knox-platform-for-enterprise/kbas/kba-838-connected-without-internet-status-after-connecting-to-wifi/), [Android Private DNS and VPN behavior](https://developers.google.com/speed/public-dns/docs/using/), [OpenAI network requirements](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps).
