# Contributing

Use a feature/fix branch against `develop`; release stabilization uses `release/*` and a PR into `main`. Describe behavior, migrations and focused validation. Required CI checks apply to administrators too; a second-account approval is not required.

Use Python 3.14.4, Node from `.node-version`, `uv sync --locked` and `npm ci` in `frontend`. Runtime dependencies are exported with hashes. Run relevant checks for the change; avoid unnecessary production load. Tests use isolated paths and synthetic identities, never real connection profiles.

Do not commit `.env`, deployment configuration, databases, live DNS URLs, certificates, keys or private logs. Security reports belong in GitHub private vulnerability reporting, not public issues.
