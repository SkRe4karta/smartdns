#!/usr/bin/env python3
"""Certbot DNS-01 hook; secrets are read from a root-only credentials file."""

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

credentials = json.loads(Path("/opt/smartdns-smartdns-beta/secrets/acme-dns.json").read_text())
validation = os.environ["CERTBOT_VALIDATION"]
request = urllib.request.Request(
    "https://auth.acme-dns.io/update",
    data=json.dumps({"subdomain": credentials["subdomain"], "txt": validation}).encode(),
    headers={
        "Content-Type": "application/json",
        "X-Api-User": credentials["username"],
        "X-Api-Key": credentials["password"],
    },
)
with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 -- fixed HTTPS ACME service
    if response.status != 200:
        raise RuntimeError("ACME DNS update failed")
for _ in range(60):
    result = subprocess.run(
        ["dig", "@1.1.1.1", "+short", "+time=2", "+tries=1", "_acme-challenge.dns.example.com", "TXT"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if '"' + validation + '"' in result.stdout:
        break
    time.sleep(5)
else:
    raise RuntimeError("ACME TXT propagation timeout")
