# Configuration

Set SMARTDNS_CONFIG to an absolute path outside the source/release directory containing a JSON configuration. Start from config/example.json and replace the documentation domain and IPv4 before startup. public_url must be an HTTPS origin, and public_ipv4 must be the actual public server address. Reserved example addresses are not deployment values.

The master encryption key must remain outside the database and source tree. Keep the key paired with database backups. A missing master key for an existing database is a restore error, not permission to generate a replacement.

Private production paths may differ from installation defaults. Do not paste real configuration or connection URLs into issues, screenshots or shared logs.

Use one forwarding server. Multiple egress pools and remote-node management are not part of this version. Configure reserved SNI names for other services sharing port 443 in private deployment configuration; do not route them through the DNS HTTPS forwarder.
