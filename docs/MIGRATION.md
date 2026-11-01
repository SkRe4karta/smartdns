# Migration

Back up the database, matching encryption key and deployment configuration before upgrading. Apply versioned migrations once, preserving existing DNS credential hashes/encrypted values, user IDs, filtering policies and activity history.

The admin-only migration revokes non-administrator web sessions and removes setup/recovery invitations and Telegram Login state. Existing DNS profiles become active recipients without website enrollment. Preserve administrator access and its existing DNS profile.

Remove remote-node/egress management from the supported public interface. Retain the existing primary forwarding endpoint during upgrade; do not silently move users to another address. Keep existing working DNS names, certificates and connection values in private deployment configuration.

Rollback restores the coherent database, key and configuration snapshot with the matching old application. Do not implement reverse schema changes by guessing. Publishing rewritten repository history does not update an installed production server.
