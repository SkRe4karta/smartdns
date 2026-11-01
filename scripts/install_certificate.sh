#!/bin/sh
set -eu
ROOT=/opt/smartdns-smartdns-beta
LINEAGE=${RENEWED_LINEAGE:-$ROOT/acme/config/live/smartdns-beta-wildcard}
install -d -m 0750 -o root -g smartdns-beta "$ROOT/certs"
install -m 0640 -o root -g smartdns-beta "$LINEAGE/fullchain.pem" "$ROOT/certs/fullchain.pem.new"
install -m 0640 -o root -g smartdns-beta "$LINEAGE/privkey.pem" "$ROOT/certs/privkey.pem.new"
openssl x509 -in "$ROOT/certs/fullchain.pem.new" -noout -checkend 86400
CERT_PUBLIC=$(openssl x509 -in "$ROOT/certs/fullchain.pem.new" -pubkey -noout | openssl sha256)
KEY_PUBLIC=$(openssl pkey -in "$ROOT/certs/privkey.pem.new" -pubout | openssl sha256)
[ "$CERT_PUBLIC" = "$KEY_PUBLIC" ]
mv "$ROOT/certs/privkey.pem.new" "$ROOT/certs/privkey.pem"
mv "$ROOT/certs/fullchain.pem.new" "$ROOT/certs/fullchain.pem"
nginx -t
systemctl reload nginx
if systemctl is-active --quiet smartdns-gateway; then systemctl restart smartdns-gateway; fi
