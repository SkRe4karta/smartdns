#!/usr/bin/env python3
"""Exercise real portal/DoH revocation with a temporary user, then remove it."""
import hashlib
import json
import secrets
import subprocess
from integration import https,packet

ssh=['ssh','-F','/home/operator/.ssh/config','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','dns-server','sudo -n python3 -']
i='u'+secrets.token_hex(6);token=secrets.token_urlsafe(32);h=hashlib.sha256(token.encode()).hexdigest()


def remote(code):
    prefix="import sys,time,subprocess;sys.path.insert(0,'/opt/smartdns-smartdns/app');import smartdns as m\n"
    return subprocess.run(ssh,input=prefix+code,text=True,capture_output=True,check=True).stdout


try:
    remote(f"""subprocess.run(['systemctl','stop','smartdns-sync.timer'],check=True)
subprocess.run(['systemctl','stop','smartdns-sync.service'],check=True)
with m.database() as db: db.execute('INSERT INTO users VALUES(?,?,?,?,?)',({i!r},'[revocationtest]',{h!r},1,int(time.time())))
users,nets,ex=m.snapshot();m.write_routes(users,nets);m.sync_agh(users,nets,ex)
""")
    headers={'Authorization':'Bearer '+token}
    status,body=https('/api/status',headers=headers)
    assert status==200,(status,body[:160])
    assert https('/dns-query/'+i,packet('example.com'),{'Content-Type':'application/dns-message'})[0]==200
    remote(f"with m.database() as db: db.execute('UPDATE users SET enabled=0 WHERE id=?',({i!r},))\nusers,nets,ex=m.snapshot();m.write_routes(users,nets);m.sync_agh(users,nets,ex)\n")
    r={'revoked_portal_denied':https('/api/status',headers=headers)[0]==403,
       'revoked_doh_denied':https('/dns-query/'+i,packet('example.com'),{'Content-Type':'application/dns-message'})[0]==403}
    s,b=https('/cdn-cgi/trace',host='chatgpt.com');r['owner_proxy_still_works']=s==200 and b'ip=203.0.113.10' in b
    assert all(r.values()),r
    print(json.dumps(r,indent=2))
finally:
    remote(f"with m.database() as db:\n db.execute('DELETE FROM networks WHERE user_id=?',({i!r},))\n db.execute('DELETE FROM users WHERE id=?',({i!r},))\nm.sync()\nsubprocess.run(['systemctl','start','smartdns-sync.timer'],check=True)\n")
