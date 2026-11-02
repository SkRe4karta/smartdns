#!/bin/sh
set -eu
: "${RENEWED_LINEAGE:?Certbot must supply RENEWED_LINEAGE}"
CERT_DIR=${SMARTDNS_CERT_DIR:-/etc/smartdns/certs}
CERT_GROUP=${SMARTDNS_CERT_GROUP:-smartdns}
install -d -m 0750 -o root -g "$CERT_GROUP" "$CERT_DIR"
install -m 0640 -o root -g "$CERT_GROUP" "$RENEWED_LINEAGE/fullchain.pem" "$CERT_DIR/fullchain.pem.new"
install -m 0640 -o root -g "$CERT_GROUP" "$RENEWED_LINEAGE/privkey.pem" "$CERT_DIR/privkey.pem.new"
openssl x509 -in "$CERT_DIR/fullchain.pem.new" -noout -checkend 86400
CERT_PUBLIC=$(openssl x509 -in "$CERT_DIR/fullchain.pem.new" -pubkey -noout | openssl sha256)
KEY_PUBLIC=$(openssl pkey -in "$CERT_DIR/privkey.pem.new" -pubout | openssl sha256)
[ "$CERT_PUBLIC" = "$KEY_PUBLIC" ]
mv "$CERT_DIR/privkey.pem.new" "$CERT_DIR/privkey.pem"
mv "$CERT_DIR/fullchain.pem.new" "$CERT_DIR/fullchain.pem"
nginx -t
systemctl reload nginx
systemctl try-restart "${SMARTDNS_GATEWAY_UNIT:-smartdns-gateway}"
