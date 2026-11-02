#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 "$SCRIPT_DIR/certificates.py" renew --config "${SMARTDNS_CERTIFICATE_CONFIG:-/etc/smartdns/certificates.json}"
