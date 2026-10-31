#!/usr/bin/env python3
"""Run as root on the VPS after copying this directory to /opt/zelyonka-smartdns/app."""
import copy
import datetime
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import time
import yaml

ROOT = Path('/opt/zelyonka-smartdns')
APP = ROOT / 'app'
IP = '109.120.185.213'
BASE = 'smartdns.zelyonkin.ru'


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def write(path, text, mode=0o644):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text); p.chmod(mode)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run as root')
    marker = ROOT / 'runtime/installed'
    if marker.exists():
        raise RuntimeError('Already installed; use smartdnsctl and inspect before redeploying')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = Path('/opt/backups') / ('smartdns-' + stamp)
    backup.mkdir(mode=0o700, parents=True)
    for name in ['haproxy', 'nginx', 'ufw']:
        shutil.copytree('/etc/' + name, backup / name, symlinks=True)
    write(backup / 'nft-before.txt', run(['nft', 'list', 'ruleset']).stdout, 0o600)
    write(ROOT / 'backup-location', str(backup) + '\n', 0o600)
    for folder, mode in [('conf',0o700),('work',0o700),('certs',0o700),('runtime',0o700),('state',0o700),('webroot',0o755),('acme',0o700)]:
        (ROOT / folder).mkdir(mode=mode, exist_ok=True)
    try:
        account = pwd.getpwnam('smartdns')
    except KeyError:
        run(['useradd', '--system', '--home-dir', str(ROOT), '--no-create-home', '--shell', '/usr/sbin/nologin', 'smartdns'])
        account = pwd.getpwnam('smartdns')
    os.chown(ROOT / 'state', account.pw_uid, account.pw_gid)
    shutil.copyfile(APP / 'domains.txt', ROOT / 'domains.txt')
    write('/usr/local/sbin/smartdnsctl', '#!/bin/sh\nexec /usr/bin/python3 /opt/zelyonka-smartdns/app/smartdns.py "$@"\n', 0o755)
    run(['smartdnsctl', 'init'])
    os.chown(ROOT / 'state/users.sqlite3', account.pw_uid, account.pw_gid)
    (ROOT / 'state/users.sqlite3').chmod(0o660)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
         '-keyout', str(ROOT / 'certs/privkey.pem'), '-out', str(ROOT / 'certs/fullchain.pem'),
         '-subj', '/CN=' + BASE, '-addext', 'subjectAltName=DNS:' + BASE])
    (ROOT / 'certs/privkey.pem').chmod(0o600)
    # Copy only schema defaults; no existing passwords, clients, rules, or private URLs.
    old = yaml.safe_load(Path('/opt/marusia-dns/conf/AdGuardHome.yaml').read_text())
    cfg = copy.deepcopy(old)
    cfg['users'] = []
    cfg['http']['address'] = '127.0.0.1:3005'
    cfg['http']['doh']['insecure_enabled'] = True
    cfg['dns'].update(bind_hosts=[IP], port=53, upstream_dns=['https://1.1.1.1/dns-query','https://dns.google/dns-query'],
                      bootstrap_dns=['1.1.1.1','9.9.9.9'], fallback_dns=['https://dns.quad9.net/dns-query'],
                      ratelimit=300, allowed_clients=['127.0.0.1', IP], disallowed_clients=[],
                      blocked_hosts=[], trusted_proxies=['127.0.0.1/32'], aaaa_disabled=False,
                      cache_size=8388608, use_private_ptr_resolvers=False)
    cfg['tls'].update(enabled=False, server_name=BASE, port_https=0, port_dns_over_tls=8853,
                      port_dns_over_quic=0, certificate_path='', private_key_path='', certificate_chain='', private_key='')
    cfg['clients'] = {'persistent': [], 'runtime_sources': {'whois':False,'arp':False,'rdns':False,'dhcp':False,'hosts':False}}
    cfg['user_rules'] = []
    cfg['filters'] = [
        {'enabled':True,'url':'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt','name':'AdGuard DNS filter','id':1},
        {'enabled':True,'url':'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt','name':'HaGeZi Multi PRO','id':2}]
    cfg['whitelist_filters'] = []
    cfg['filtering'].update(rewrites=[], filtering_enabled=True, protection_enabled=True, filters_update_interval=24,
                            safebrowsing_enabled=False, parental_enabled=False, rewrites_enabled=True)
    cfg['querylog'].update(interval='24h', enabled=True, size_memory=500)
    cfg['statistics'].update(interval='24h', enabled=True)
    if 'dhcp' in cfg:
        cfg['dhcp']['enabled'] = False
    write(ROOT / 'conf/AdGuardHome.yaml', yaml.safe_dump(cfg, sort_keys=False), 0o600)
    image = run(['docker','inspect','adguard-home-fi','--format','{{.Image}}']).stdout.strip()
    compose = {'services':{'smartdns':{'image':image,'container_name':'zelyonka-smartdns','network_mode':'host',
              'restart':'unless-stopped','mem_limit':'512m','memswap_limit':'512m','cpus':0.5,'read_only':True,
              'tmpfs':['/tmp:rw,noexec,nosuid,size=16m'],'cap_drop':['ALL'],'cap_add':['NET_BIND_SERVICE'],
              'security_opt':['no-new-privileges:true'],
              'volumes':[f'{ROOT}/conf:/opt/adguardhome/conf',f'{ROOT}/work:/opt/adguardhome/work',f'{ROOT}/certs:{ROOT}/certs:ro']}}}
    write(ROOT / 'compose.json', json.dumps(compose,indent=2)+'\n', 0o600)
    for name, text in [('web',BASE+'\n'),('dot','disabled.invalid\n'),('origins','^disabled\\.invalid$\n'),('sources','192.0.2.0/32\n')]:
        write('/etc/haproxy/smartdns-'+name+'.acl', text)
    write('/etc/nginx/conf.d/00-smartdns-clients.conf','map "$host:$uri" $smartdns_client { default ""; }\n')
    write('/etc/nginx/conf.d/01-smartdns-limits.conf', '''limit_req_zone $binary_remote_addr zone=smartdns_dns:1m rate=50r/s;
limit_req_zone $binary_remote_addr zone=smartdns_portal:1m rate=10r/m;
limit_conn_zone $binary_remote_addr zone=smartdns_connections:1m;
''')
    nginx = r'''server {
 listen 80 default_server;
 server_name _;
 access_log off;
 return 444;
}
server {
 listen 80;
 server_name BASE *.BASE;
 access_log off;
 location ^~ /.well-known/acme-challenge/ { root ROOT/webroot; try_files $uri =404; }
 location / { return 404; }
}
server {
 listen 127.0.0.1:8544 ssl proxy_protocol;
 http2 on;
 server_name BASE *.BASE;
 ssl_certificate ROOT/certs/fullchain.pem;
 ssl_certificate_key ROOT/certs/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 set_real_ip_from 127.0.0.1;
 real_ip_header proxy_protocol;
 access_log off;
 error_log /var/log/nginx/smartdns-error.log crit;
 server_tokens off;
 client_max_body_size 64k;
 client_body_timeout 10s;
 limit_conn smartdns_connections 128;
 add_header X-Content-Type-Options nosniff always;
 add_header Referrer-Policy no-referrer always;
 add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" always;
 location ~ ^/dns-query(?:/[a-z0-9-]+)?$ {
  if ($smartdns_client = "") { return 403; }
  limit_req zone=smartdns_dns burst=100 nodelay;
  limit_req_status 429;
  proxy_pass http://127.0.0.1:3005/dns-query/$smartdns_client$is_args$args;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For "";
  proxy_set_header Forwarded "";
  proxy_set_header Authorization "";
  proxy_read_timeout 15s;
 }
 location ~ ^/(connect|app\.js|app\.css)$ {
  proxy_pass http://127.0.0.1:3006;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For "";
 }
 location ~ ^/api/(status|activate|profile)$ {
  limit_req zone=smartdns_portal burst=10 nodelay;
  limit_req_status 429;
  proxy_pass http://127.0.0.1:3006;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For "";
  proxy_set_header Forwarded "";
  proxy_set_header Host $host;
 }
 location = / { return 302 /connect; }
 location / { return 404; }
}
'''.replace('BASE',BASE).replace('ROOT',str(ROOT))
    write('/etc/nginx/sites-available/zelyonka-smartdns.conf',nginx)
    link = Path('/etc/nginx/sites-enabled/zelyonka-smartdns.conf')
    if not link.exists(): link.symlink_to('/etc/nginx/sites-available/zelyonka-smartdns.conf')
    hpath = Path('/etc/haproxy/haproxy.cfg')
    h = hpath.read_text()
    if 'frontend fi_tls_443' not in h or 'smartdns_web' in h:
        raise RuntimeError('Unexpected HAProxy state; inspect before editing')
    old_reject = '    tcp-request content reject if !sni_xhttp !sni_grpc !sni_trojan !sni_dns'
    if h.count(old_reject) != 1:
        raise RuntimeError('Unexpected existing HAProxy ACL layout')
    h = h.replace(old_reject, '''    acl sni_smartdns_web req.ssl_sni,lower -f /etc/haproxy/smartdns-web.acl
    acl sni_smartdns_service req.ssl_sni,lower -m reg -f /etc/haproxy/smartdns-origins.acl
    acl smartdns_active src -f /etc/haproxy/smartdns-sources.acl
    tcp-request content reject if !sni_xhttp !sni_grpc !sni_trojan !sni_dns !sni_smartdns_web !sni_smartdns_service

    use_backend smartdns_web if sni_smartdns_web
    use_backend smartdns_origins if sni_smartdns_service smartdns_active''')
    h = h.replace('    tcp-request content accept if { req.ssl_hello_type 1 }',
                  '    tcp-request content set-var(sess.smartdns_sni) req.ssl_sni,lower if { req.ssl_hello_type 1 }\n    tcp-request content accept if { req.ssl_hello_type 1 }', 1)
    h += '''
# BEGIN ZELYONKA SMARTDNS
frontend smartdns_dot
    bind 0.0.0.0:853
    mode tcp
    maxconn 256
    tcp-request inspect-delay 5s
    tcp-request content reject if { req.ssl_hello_type 1 } !{ req.ssl_sni,lower -f /etc/haproxy/smartdns-dot.acl }
    tcp-request content accept if { req.ssl_hello_type 1 }
    default_backend smartdns_dot_backend

backend smartdns_dot_backend
    mode tcp
    stick-table type ip size 10k expire 1m store conn_cur,conn_rate(10s)
    tcp-request content track-sc2 src
    tcp-request content reject if { sc2_conn_cur gt 64 }
    tcp-request content reject if { sc2_conn_rate gt 100 }
    server smartdns_dot 109.120.185.213:8853 maxconn 256

backend smartdns_web
    mode tcp
    server smartdns_web 127.0.0.1:8544 send-proxy-v2 maxconn 256

resolvers smartdns_origins_dns
    nameserver cloudflare 1.1.1.1:53
    nameserver quad9 9.9.9.9:53
    resolve_retries 2
    timeout resolve 1s
    timeout retry 1s
    hold valid 60s
    accepted_payload_size 1232

backend smartdns_origins
    mode tcp
    tcp-request inspect-delay 5s
    timeout server 5m
    stick-table type ip size 10k expire 1m store conn_cur,conn_rate(10s)
    tcp-request content reject unless { src -f /etc/haproxy/smartdns-sources.acl }
    tcp-request content track-sc2 src
    tcp-request content reject if { sc2_conn_cur gt 128 }
    tcp-request content reject if { sc2_conn_rate gt 200 }
    tcp-request content do-resolve(sess.smartdns_ip,smartdns_origins_dns,ipv4) var(sess.smartdns_sni)
    tcp-request content reject unless { var(sess.smartdns_ip) -m found }
    acl smartdns_bad_destination var(sess.smartdns_ip) -m ip 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 109.120.185.213/32 45.12.63.194/32
    tcp-request content reject if smartdns_bad_destination
    tcp-request content set-dst var(sess.smartdns_ip)
    server origin 0.0.0.0:443 maxconn 512
# END ZELYONKA SMARTDNS
'''
    write(hpath,h)
    run(['haproxy','-c','-f',str(hpath)])
    run(['nginx','-t'])
    write('/etc/systemd/system/smartdns-firewall.service','''[Unit]
Description=Smart DNS fail-closed DNS firewall
Before=docker.service ufw.service haproxy.service
After=local-fs.target
DefaultDependencies=no
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/smartdnsctl sync --firewall-only
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
    write('/etc/systemd/system/smartdns-portal.service','''[Unit]
Description=Private Smart DNS activation portal
After=network.target
[Service]
User=smartdns
Group=smartdns
ExecStart=/usr/bin/python3 /opt/zelyonka-smartdns/app/smartdns.py serve
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/zelyonka-smartdns/state
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryMax=96M
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    write('/etc/systemd/system/smartdns-sync.service','''[Unit]
Description=Apply Smart DNS users and expiring network grants
After=docker.service smartdns-firewall.service
Requires=smartdns-firewall.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/smartdnsctl sync
TimeoutStartSec=300
UMask=0077
''')
    write('/etc/systemd/system/smartdns-sync.timer','''[Unit]
Description=Refresh Smart DNS access rules
[Timer]
OnBootSec=15s
OnUnitInactiveSec=5s
AccuracySec=1s
Unit=smartdns-sync.service
[Install]
WantedBy=timers.target
''')
    write('/etc/systemd/system/smartdns-cert.service',f'''[Unit]
Description=Renew Smart DNS TLS certificate
After=network-online.target nginx.service
[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --config-dir {ROOT}/acme/config --work-dir {ROOT}/acme/work --logs-dir {ROOT}/acme/logs --deploy-hook /usr/local/sbin/smartdns-cert-deploy
TimeoutStartSec=300
''')
    write('/usr/local/sbin/smartdns-cert-deploy','#!/bin/sh\nexec /usr/local/sbin/smartdnsctl deploy-cert\n',0o755)
    write('/etc/systemd/system/smartdns-cert.timer','''[Unit]
Description=Daily Smart DNS certificate renewal
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
''')
    write('/usr/local/sbin/smartdns-rollback',f'''#!/bin/sh
set -eu
systemctl disable --now smartdns-sync.timer smartdns-cert.timer smartdns-portal.service
systemctl stop smartdns-sync.service || true
docker stop zelyonka-smartdns
cp {backup}/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl reload haproxy
rm -f /etc/nginx/sites-enabled/zelyonka-smartdns.conf /etc/nginx/sites-available/zelyonka-smartdns.conf /etc/nginx/conf.d/00-smartdns-clients.conf /etc/nginx/conf.d/01-smartdns-limits.conf
nginx -t
systemctl reload nginx
ufw --force delete allow to {IP} port 53 proto udp
ufw --force delete allow to {IP} port 53 proto tcp
ufw --force delete allow 853/tcp
ufw --force delete allow 80/tcp
systemctl disable --now smartdns-firewall.service
nft delete table inet zelyonka_smartdns
echo 'Smart DNS stopped; pre-install proxy configuration restored. Data and backup retained.'
''',0o700)
    run(['systemctl','daemon-reload'])
    # Guard is installed before opening firewall ports or starting the new DNS listener.
    run(['systemctl','enable','--now','smartdns-firewall.service'])
    run(['docker','compose','-f',str(ROOT/'compose.json'),'up','-d'])
    for _ in range(40):
        p = subprocess.run(['curl','-sf','http://127.0.0.1:3005/control/status'],capture_output=True)
        if p.returncode == 0: break
        time.sleep(.5)
    else:
        raise RuntimeError('New AdGuard Home did not become ready')
    for args in [ ['allow','to',IP,'port','53','proto','udp'],['allow','to',IP,'port','53','proto','tcp'],['allow','853/tcp'],['allow','80/tcp'] ]:
        run(['ufw']+args)
    run(['systemctl','reload','nginx'])
    run(['systemctl','reload','haproxy'])
    run(['systemctl','enable','--now','smartdns-portal.service','smartdns-sync.timer','smartdns-cert.timer'])
    write(marker,stamp+'\n',0o600)
    print('Installed. Backup:',backup)


if __name__ == '__main__':
    main()
