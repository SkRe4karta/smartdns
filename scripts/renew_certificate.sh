#!/bin/sh
set -eu
exec /usr/bin/certbot renew --non-interactive --deploy-hook /opt/smartdns/current/scripts/install_certificate.sh
