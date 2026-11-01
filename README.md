# SmartDNS

Self-hosted encrypted DNS, ad filtering and selective HTTPS forwarding. The project is preparing version **0.3.0-rc.1**; a release is usable only when its attached validation report passes the required checks.

The administrator creates DNS users by username and distributes their connection settings. Recipients need no website account. One credential provides a DoT hostname, a DoH URL and an Apple configuration profile for multiple devices.

## Capabilities and limits

- Admin-only dashboard; user status, filtering, aggregate activity and credential rotation.
- AdGuard Home filtering; configurable installation address and domain.
- Domain routing catalog including OpenAI/Codex, Twitch and Supercell HTTPS resources.
- Daily validated catalog updates with rollback to the previous working version.
- The bundled system routing policy includes categories not displayed in the dashboard. Policy sources are inspectable in the catalog manifests and code; dashboard visibility is not the complete policy.

DNS does not route connections to hardcoded IP addresses or arbitrary UDP/TCP traffic. A catalog entry is not a promise that every feature of a native app, game or call works. DNS cannot remove every advertisement, particularly ads sharing a content hostname. Account region and server IP reputation can affect access.

## Installation

See [installation](docs/INSTALLATION.md), [configuration](docs/CONFIGURATION.md), [operations](docs/OPERATIONS.md) and [architecture](docs/ARCHITECTURE.md). Configure your own domain, public IPv4 and certificate. Examples use reserved addresses and are not live services.

Requires Linux with systemd, Python 3.14 and Node 24 for building the dashboard. Python and npm dependencies are locked. AdGuard Home, nginx and HAProxy are separate deployment components; shared-server installations must preserve existing listeners and routes.

## Development and releases

`main` contains releases; `develop` integrates changes; feature and fix branches use pull requests. See [release process](docs/RELEASE.md), [validation](docs/VALIDATION.md), [migration](docs/MIGRATION.md) and [security](SECURITY.md).

Production configuration, databases, certificates, credentials and private connection links must never be committed. License: [MIT](LICENSE).

Repository history was sanitized for public distribution. Read the [cleanup scope and cache limitations](docs/PRIVACY.md) before reusing an older clone.
