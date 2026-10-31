#!/usr/bin/env python3
"""Small private Smart DNS control plane. Public HTTP is provided by nginx only."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(os.environ.get('SMARTDNS_ROOT', '/opt/smartdns-smartdns'))
BASE = 'dns.example.com'
PUBLIC_IP = '203.0.113.10'
DB = ROOT / 'state/users.sqlite3'
ID_RE = re.compile(r'u[0-9a-f]{12}\Z')
DOMAIN_RE = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z')
GRANT_SECONDS = 7 * 86400
MAX_NETWORKS = 3
AGH = 'http://127.0.0.1:3005/control/'
RUNTIME = ROOT / 'runtime'


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=kwargs.pop('timeout', 30), **kwargs)


def atomic(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode() if isinstance(text, str) else text
    if path.exists() and path.read_bytes() == data:
        return False
    tmp = path.with_name(path.name + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


@contextlib.contextmanager
def database():
    DB.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS networks (
        user_id TEXT NOT NULL REFERENCES users(id), ip TEXT NOT NULL,
        expires INTEGER NOT NULL, updated INTEGER NOT NULL,
        PRIMARY KEY(user_id,ip));
      CREATE TABLE IF NOT EXISTS exceptions (
        user_id TEXT NOT NULL DEFAULT '*', domain TEXT NOT NULL,
        PRIMARY KEY(user_id, domain));
    ''')
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def active_users(db):
    return [dict(r) for r in db.execute('SELECT id,name FROM users WHERE enabled=1 ORDER BY id')]


def authorize(db, token):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token or ''):
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    return db.execute('SELECT id,name FROM users WHERE token_hash=? AND enabled=1', (h,)).fetchone()


def grant(db, user_id, ip, now=None):
    now = int(time.time()) if now is None else now
    ip = str(ipaddress.ip_address(ip))
    if not ipaddress.ip_address(ip).is_global or ':' in ip:
        raise ValueError('Нужен публичный IPv4-адрес текущей сети')
    if not db.execute('SELECT 1 FROM users WHERE id=? AND enabled=1', (user_id,)).fetchone():
        raise ValueError('Пользователь отключён')
    db.execute('DELETE FROM networks WHERE expires<=?', (now,))
    db.execute('INSERT INTO networks VALUES(?,?,?,?) ON CONFLICT(user_id,ip) DO UPDATE SET expires=excluded.expires,updated=excluded.updated',
               (user_id, ip, now + GRANT_SECONDS, now))
    keep = list(db.execute('SELECT ip FROM networks WHERE user_id=? ORDER BY updated DESC,ip DESC LIMIT ?', (user_id, MAX_NETWORKS)))
    keep_ips = {r['ip'] for r in keep}
    # Always keep the network being activated, including multiple activations in one second.
    if ip not in keep_ips:
        keep_ips.pop()
        keep_ips.add(ip)
    for r in db.execute('SELECT ip FROM networks WHERE user_id=?', (user_id,)).fetchall():
        if r['ip'] not in keep_ips:
            db.execute('DELETE FROM networks WHERE user_id=? AND ip=?', (user_id, r['ip']))
    return ip


def domains():
    result = []
    for line in (ROOT / 'domains.txt').read_text().splitlines():
        d = line.split('#', 1)[0].strip().lower()
        if not d:
            continue
        if not DOMAIN_RE.fullmatch(d) or d in ('google.com', 'github.io', 'dl.google.com', 'www.apple.com', BASE):
            raise ValueError('Invalid or conflicting origin domain')
        result.append(d)
    return sorted(set(result))


def rules_for(exceptions):
    rules = []
    for d in domains():
        rules.extend([f'||{d}^$dnstype=A,dnsrewrite=NOERROR;A;{PUBLIC_IP}',
                      f'||{d}^$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;'])
    for e in exceptions:
        d, user_id = e['domain'], e['user_id']
        if not DOMAIN_RE.fullmatch(d) or (user_id != '*' and not ID_RE.fullmatch(user_id)):
            raise ValueError('Invalid exception')
        # dnsrewrite rules intentionally survive advertising allowlist exceptions.
        rules.append(f'@@||{d}^' + (f'$client={user_id}' if user_id != '*' else ''))
    return rules


def agh(path, data=None):
    payload = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(AGH + path, data=payload, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=15) as r:
        text = r.read()
        return json.loads(text) if text else None


def snapshot():
    with database() as db:
        users = active_users(db)
        if any(not ID_RE.fullmatch(u['id']) for u in users):
            raise ValueError('Invalid user ID in database')
        nets = [dict(r) for r in db.execute('SELECT n.user_id,n.ip,n.expires FROM networks n JOIN users u ON u.id=n.user_id WHERE u.enabled=1 AND n.expires>?', (int(time.time()),))]
        for n in nets:
            a = ipaddress.ip_address(n['ip'])
            if a.version != 4 or not a.is_global:
                raise ValueError('Invalid network grant')
        exceptions = [dict(r) for r in db.execute('SELECT user_id,domain FROM exceptions ORDER BY user_id,domain')]
    return users, nets, exceptions


def firewall(nets):
    # A separate nftables input chain runs before UFW. No Docker published ports are used.
    exists = subprocess.run(['nft', 'list', 'table', 'inet', 'smartdns_smartdns'], capture_output=True).returncode == 0
    if not exists:
        script = f'''table inet smartdns_smartdns {{
 set activated_v4 {{ type ipv4_addr; flags timeout; }}
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "lo" accept
  ip daddr {PUBLIC_IP} udp dport 53 ip saddr != @activated_v4 drop
  ip daddr {PUBLIC_IP} tcp dport 53 ip saddr != @activated_v4 drop
  tcp dport 8853 drop
 }}
}}\n'''
        run(['nft', '-f', '-'], input=script)
    # nft transactions update the set atomically; kernel timeouts fail closed if the control plane stops.
    by_ip = {}
    for n in nets:
        by_ip[n['ip']] = max(by_ip.get(n['ip'], 0), n['expires'])
    now = int(time.time())
    script = 'flush set inet smartdns_smartdns activated_v4\n'
    if by_ip:
        elements = ', '.join(f'{ip} timeout {max(1, expiry-now)}s' for ip, expiry in sorted(by_ip.items()))
        script += f'add element inet smartdns_smartdns activated_v4 {{ {elements} }}\n'
    run(['nft', '-f', '-'], input=script)


def write_routes(users, nets):
    names = [BASE] + [f"{u['id']}.{BASE}" for u in users]
    changed_h = atomic('/etc/haproxy/smartdns-web.acl', '\n'.join(names) + '\n')
    changed_h |= atomic('/etc/haproxy/smartdns-dot.acl', '\n'.join(names[1:]) + '\n' if users else 'disabled.invalid\n')
    regex = '\n'.join(r'^([a-z0-9-]+\.)*' + re.escape(d) + '$' for d in domains()) + '\n'
    changed_h |= atomic('/etc/haproxy/smartdns-origins.acl', regex)
    sources = sorted({n['ip'] for n in nets})
    changed_h |= atomic('/etc/haproxy/smartdns-sources.acl', '\n'.join(sources) + '\n' if sources else '192.0.2.0/32\n')
    m = ['map "$host:$uri" $smartdns_client {', ' default "";']
    for u in users:
        i = u['id']
        m.extend([f' "{i}.{BASE}:/dns-query" {i};', f' "{BASE}:/dns-query/{i}" {i};'])
    m.append('}')
    changed_n = atomic('/etc/nginx/conf.d/00-smartdns-clients.conf', '\n'.join(m) + '\n')
    if changed_h:
        run(['haproxy', '-c', '-f', '/etc/haproxy/haproxy.cfg'])
        run(['systemctl', 'reload', 'haproxy'])
    if changed_n:
        run(['nginx', '-t'])
        run(['systemctl', 'reload', 'nginx'])


def sync_agh(users, nets, exceptions):
    wanted = {'policy': 2, 'users': users, 'ips': sorted({n['ip'] for n in nets}), 'rules': rules_for(exceptions)}
    cache = RUNTIME / 'agh-applied.json'
    # The state is only a performance cache; force-apply on container restart.
    start = run(['docker', 'inspect', 'smartdns-smartdns', '--format', '{{.State.StartedAt}}']).stdout.strip()
    wanted['started'] = start
    if cache.exists() and json.loads(cache.read_text()) == wanted:
        return
    existing = agh('clients').get('clients') or []
    desired_names = {f"smartdns-{u['id']}" for u in users}
    existing_names = {c['name'] for c in existing}
    for c in existing:
        if c['name'] not in desired_names:
            agh('clients/delete', {'name': c['name']})
    for u in users:
        if f"smartdns-{u['id']}" not in existing_names:
            agh('clients/add', {'name': f"smartdns-{u['id']}", 'ids': [u['id']], 'use_global_settings': True,
                                'filtering_enabled': True, 'use_global_blocked_services': True})
    agh('access/set', {'allowed_clients': ['127.0.0.1'] + [u['id'] for u in users] + wanted['ips'],
                       'disallowed_clients': [], 'blocked_hosts': []})
    agh('filtering/set_rules', {'rules': wanted['rules']})
    atomic(cache, json.dumps(wanted, sort_keys=True), 0o600)


def certificate_names():
    p = ROOT / 'certs/fullchain.pem'
    if not p.exists():
        return set()
    s = run(['openssl', 'x509', '-in', str(p), '-noout', '-ext', 'subjectAltName']).stdout
    return set(re.findall(r'DNS:([a-z0-9.-]+)', s))


def deploy_certificate():
    import yaml
    live = ROOT / 'acme/config/live' / BASE
    if not (live / 'fullchain.pem').exists():
        raise RuntimeError('No issued certificate')
    changed = atomic(ROOT / 'certs/fullchain.pem', (live / 'fullchain.pem').read_bytes())
    changed |= atomic(ROOT / 'certs/privkey.pem', (live / 'privkey.pem').read_bytes(), 0o600)
    cfg = ROOT / 'conf/AdGuardHome.yaml'
    d = yaml.safe_load(cfg.read_text())
    if not d['tls']['enabled'] or changed:
        # Stop only this instance before writing its YAML; AdGuard persists config on exit.
        run(['docker', 'stop', '-t', '10', 'smartdns-smartdns'])
        d = yaml.safe_load(cfg.read_text())
        d['tls'].update(enabled=True, server_name=BASE, port_https=0, port_dns_over_tls=8853,
                        port_dns_over_quic=0, certificate_path=str(ROOT / 'certs/fullchain.pem'),
                        private_key_path=str(ROOT / 'certs/privkey.pem'), certificate_chain='',
                        private_key='', strict_sni_check=True)
        atomic(cfg, yaml.safe_dump(d, sort_keys=False), 0o600)
        run(['docker', 'start', 'smartdns-smartdns'])
        for _ in range(30):
            try:
                agh('status')
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.25)
        run(['nginx', '-t'])
        run(['systemctl', 'reload', 'nginx'])
        print('Certificate deployed; new DNS instance restarted.')


def ensure_certificate(users, force=False):
    names = [BASE] + [f"{u['id']}.{BASE}" for u in users]
    if set(names).issubset(certificate_names()):
        return
    attempt = RUNTIME / 'last-cert-attempt'
    if not force and attempt.exists() and time.time() - attempt.stat().st_mtime < 300:
        return
    atomic(attempt, str(time.time()), 0o600)
    for name in names:
        resolved = run(['dig', '@1.1.1.1', '+short', '+time=2', '+tries=1', name, 'A'], timeout=5).stdout.splitlines()
        if PUBLIC_IP not in resolved:
            print('Certificate pending: public DNS has not propagated.')
            return
    args = ['certbot', 'certonly', '--webroot', '-w', str(ROOT / 'webroot'), '--cert-name', BASE,
            '--config-dir', str(ROOT / 'acme/config'), '--work-dir', str(ROOT / 'acme/work'),
            '--logs-dir', str(ROOT / 'acme/logs'), '--non-interactive', '--agree-tos',
            '--register-unsafely-without-email', '--renew-with-new-domains']
    for n in names:
        args.extend(['-d', n])
    run(args, timeout=240)
    deploy_certificate()


def sync(force_cert=False, firewall_only=False):
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with open(RUNTIME / 'sync.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        users, nets, exceptions = snapshot()
        firewall(nets)
        if firewall_only:
            sources = sorted({n['ip'] for n in nets})
            atomic('/etc/haproxy/smartdns-sources.acl', '\n'.join(sources) + '\n' if sources else '192.0.2.0/32\n')
            return
        write_routes(users, nets)
        sync_agh(users, nets, exceptions)
        ensure_certificate(users, force_cert)


def apple_profile(user):
    identifier = 'org.smartdns.smartdns.' + user['id']
    payload = {'PayloadType': 'com.apple.dnsSettings.managed', 'PayloadVersion': 1,
               'PayloadIdentifier': identifier + '.dns', 'PayloadUUID': str(uuid.uuid5(uuid.NAMESPACE_DNS, identifier + '.dns')),
               'PayloadDisplayName': 'SmartDNS',
               'DNSSettings': {'DNSProtocol': 'HTTPS', 'ServerURL': f"https://{BASE}/dns-query/{user['id']}", 'ServerAddresses': [PUBLIC_IP]}}
    return plistlib.dumps({'PayloadType': 'Configuration', 'PayloadVersion': 1,
                          'PayloadIdentifier': identifier, 'PayloadUUID': str(uuid.uuid5(uuid.NAMESPACE_DNS, identifier)),
                          'PayloadDisplayName': 'SmartDNS · личный DNS', 'PayloadDescription': 'DNS с фильтрацией рекламы',
                          'PayloadRemovalDisallowed': False, 'PayloadContent': [payload]}, sort_keys=False)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'SmartDNS'

    def log_message(self, *args):
        pass  # No request paths, credentials, or activation tokens in journals.

    def send(self, status, data, content_type='application/json; charset=utf-8'):
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False).encode()
        elif isinstance(data, str):
            data = data.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def user(self, db):
        auth = self.headers.get('Authorization', '')
        return authorize(db, auth[7:] if auth.startswith('Bearer ') else '')

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        static = {'/connect': ('portal.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/app.css': ('app.css', 'text/css; charset=utf-8')}
        if path in static:
            f, typ = static[path]
            return self.send(200, (ROOT / 'app' / f).read_bytes(), typ)
        if path != '/api/status':
            return self.send(404, {'error': 'Не найдено'})
        with database() as db:
            u = self.user(db)
            if not u:
                return self.send(403, {'error': 'Личная ссылка недействительна или пользователь отключён'})
            nets = [dict(r) for r in db.execute('SELECT ip,expires FROM networks WHERE user_id=? AND expires>? ORDER BY updated DESC', (u['id'], int(time.time())))]
            return self.send(200, {'name': u['name'], 'dot': f"{u['id']}.{BASE}",
                                  'doh': f"https://{BASE}/dns-query/{u['id']}", 'networks': nets})

    def do_POST(self):
        if self.client_address[0] != '127.0.0.1':
            return self.send(403, {'error': 'Недопустимый источник'})
        if self.headers.get('Origin') not in (None, f'https://{BASE}'):
            return self.send(403, {'error': 'Недопустимый источник'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.send(400, {'error': 'Некорректный запрос'})
        if not 0 <= length <= 1024:
            return self.send(413, {'error': 'Слишком большой запрос'})
        self.rfile.read(length)
        with database() as db:
            u = self.user(db)
            if not u:
                return self.send(403, {'error': 'Личная ссылка недействительна или пользователь отключён'})
            if self.path == '/api/profile':
                return self.send(200, apple_profile(u), 'application/x-apple-aspen-config')
            if self.path != '/api/activate':
                return self.send(404, {'error': 'Не найдено'})
            try:
                ip = grant(db, u['id'], self.headers.get('X-Real-IP', ''))
            except ValueError as e:
                return self.send(400, {'error': str(e)})
            db.commit()
            return self.send(200, {'ip': ip, 'expires': int(time.time()) + GRANT_SECONDS})


def main():
    p = argparse.ArgumentParser(description='Управление SmartDNS Smart DNS')
    p.add_argument('--version', action='version', version=(ROOT / 'app/VERSION').read_text().strip() if (ROOT / 'app/VERSION').exists() else '0.1.0-alpha.1')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('init')
    sub.add_parser('serve')
    s = sub.add_parser('sync'); s.add_argument('--cert', action='store_true'); s.add_argument('--firewall-only', action='store_true')
    s = sub.add_parser('create'); s.add_argument('name'); s.add_argument('--output')
    sub.add_parser('list')
    sub.add_parser('status')
    s = sub.add_parser('revoke'); s.add_argument('id')
    s = sub.add_parser('reset-link'); s.add_argument('id'); s.add_argument('--output')
    s = sub.add_parser('allow'); s.add_argument('action', choices=['add','remove','list']); s.add_argument('domain', nargs='?'); s.add_argument('--user', default='*')
    s = sub.add_parser('network'); s.add_argument('action', choices=['add','remove','list']); s.add_argument('--user'); s.add_argument('--ip')
    sub.add_parser('deploy-cert')
    a = p.parse_args()
    if a.cmd == 'serve':
        http.server.ThreadingHTTPServer(('127.0.0.1', 3006), Handler).serve_forever()
        return
    if a.cmd == 'sync':
        sync(a.cert, a.firewall_only); return
    if a.cmd == 'deploy-cert':
        deploy_certificate(); return
    with database() as db:
        if a.cmd == 'init':
            pass
        elif a.cmd in ('create', 'reset-link'):
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if a.cmd == 'create':
                if len(a.name) > 100 or not a.name.strip():
                    raise ValueError('Имя должно содержать от 1 до 100 символов')
                if db.execute('SELECT COUNT(*) FROM users WHERE enabled=1').fetchone()[0] >= 30:
                    raise ValueError('Достигнут лимит 30 активных пользователей')
                i = 'u' + secrets.token_hex(6)
                db.execute('INSERT INTO users VALUES(?,?,?,?,?)', (i, a.name, token_hash, 1, int(time.time())))
            else:
                i = a.id
                if not db.execute('SELECT 1 FROM users WHERE id=? AND enabled=1', (i,)).fetchone():
                    raise ValueError('Активный пользователь не найден')
                db.execute('UPDATE users SET token_hash=? WHERE id=?', (token_hash, i))
                db.execute('DELETE FROM networks WHERE user_id=?', (i,))
            result = {'id': i, 'dot': f'{i}.{BASE}', 'doh': f'https://{BASE}/dns-query/{i}', 'activation': f'https://{BASE}/connect#{token}'}
            if a.output:
                atomic(a.output, json.dumps(result, ensure_ascii=False, indent=2) + '\n', 0o600)
                print('Профиль сохранён:', a.output)
            else:
                print(json.dumps(result, ensure_ascii=False, indent=2))
        elif a.cmd == 'status':
            covered = certificate_names()
            users = active_users(db)
            print(json.dumps({'domain':BASE,'active_users':len(users),
                              'users':[{'id':u['id'],'name':u['name'],'dot':f"{u['id']}.{BASE}",
                                        'certificate_ready':f"{u['id']}.{BASE}" in covered} for u in users]},ensure_ascii=False,indent=2))
        elif a.cmd == 'list':
            print(json.dumps([dict(r) for r in db.execute('SELECT id,name,enabled,created FROM users ORDER BY created')], ensure_ascii=False, indent=2))
        elif a.cmd == 'revoke':
            if not db.execute('UPDATE users SET enabled=0 WHERE id=?', (a.id,)).rowcount:
                raise ValueError('Пользователь не найден')
            db.execute('DELETE FROM networks WHERE user_id=?', (a.id,))
            print('Пользователь отключён. Правила обновятся в течение 10 секунд.')
        elif a.cmd == 'allow':
            if a.action == 'list':
                print(json.dumps([dict(r) for r in db.execute('SELECT * FROM exceptions')], ensure_ascii=False, indent=2))
            else:
                d = (a.domain or '').lower().rstrip('.')
                if not DOMAIN_RE.fullmatch(d):
                    raise ValueError('Укажи домен без протокола и пути')
                if a.user != '*' and not db.execute('SELECT 1 FROM users WHERE id=? AND enabled=1', (a.user,)).fetchone():
                    raise ValueError('Пользователь не найден')
                if a.action == 'add':
                    db.execute('INSERT OR IGNORE INTO exceptions VALUES(?,?)', (a.user, d))
                else:
                    db.execute('DELETE FROM exceptions WHERE user_id=? AND domain=?', (a.user, d))
                print('Исключения обновлены.')
        elif a.cmd == 'network':
            if a.action == 'list':
                print(json.dumps([dict(r) for r in db.execute('SELECT * FROM networks WHERE expires>?', (int(time.time()),))], indent=2))
            elif a.action == 'add':
                if not a.user or not a.ip:
                    raise ValueError('Нужны --user и --ip')
                grant(db, a.user, a.ip); print('Сеть активирована.')
            else:
                if not a.user or not a.ip:
                    raise ValueError('Нужны --user и --ip')
                db.execute('DELETE FROM networks WHERE user_id=? AND ip=?', (a.user, str(ipaddress.ip_address(a.ip))))
                print('Сеть удалена.')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        # Never print subprocess output; it may contain ACME account metadata.
        print(f'Ошибка: {type(e).__name__}: {e}', file=sys.stderr)
        sys.exit(1)
