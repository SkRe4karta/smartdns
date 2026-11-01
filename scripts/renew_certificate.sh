#!/bin/sh
set -eu
ROOT=/opt/zelyonka-smartdns-beta
exec /usr/bin/certbot renew --non-interactive --no-random-sleep-on-renew \
  --cert-name smartdns-beta-wildcard --config-dir "$ROOT/acme/config" \
  --work-dir "$ROOT/acme/work" --logs-dir "$ROOT/acme/logs" \
  --deploy-hook "$ROOT/current/scripts/install_certificate.sh"
