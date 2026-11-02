#!/bin/sh
set -eu
exec /usr/bin/certbot renew --non-interactive --cert-name "${SMARTDNS_CERT_NAME:-smartdns}" --deploy-hook /opt/smartdns/current/scripts/install_certificate.sh
