#!/usr/bin/env python3
import hashlib
import json
import secrets
import subprocess
import sys
import time
import smartdns as m

if sys.argv[1]=='setup':
    subprocess.run(['systemctl','stop','smartdns-sync.timer'],check=True)
    subprocess.run(['systemctl','stop','smartdns-sync.service'],check=True)
    with m.database() as db:
        count=db.execute('SELECT COUNT(*) FROM users WHERE enabled=1').fetchone()[0]
        for n in range(30-count):
            i='u'+secrets.token_hex(6)
            db.execute('INSERT INTO users VALUES(?,?,?,?,?)',(i,f'[loadtest] {n}',hashlib.sha256(secrets.token_bytes(32)).hexdigest(),1,int(time.time())))
    users,nets,exceptions=m.snapshot();m.write_routes(users,nets);m.sync_agh(users,nets,exceptions)
    m.atomic('/run/smartdns-load-ids.json',json.dumps([u['id'] for u in users]))
    print('Prepared',len(users),'profiles; certificate issuance skipped for temporary profiles.')
elif sys.argv[1]=='cleanup':
    with m.database() as db:
        db.execute("DELETE FROM networks WHERE user_id IN (SELECT id FROM users WHERE name LIKE '[loadtest]%')")
        db.execute("DELETE FROM users WHERE name LIKE '[loadtest]%'")
    m.sync()
    subprocess.run(['systemctl','start','smartdns-sync.timer'],check=True)
    print('Temporary profiles removed; normal synchronization restored.')
