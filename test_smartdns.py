import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('smartdns', Path(__file__).with_name('smartdns.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        m.ROOT = Path(self.temp.name); m.DB = m.ROOT / 'state/users.sqlite3'
        shutil.copyfile(Path(__file__).with_name('domains.txt'), m.ROOT / 'domains.txt')
        self.id = 'u0123456789ab'; self.token = secrets.token_urlsafe(32)
        with m.database() as db:
            db.execute('INSERT INTO users VALUES(?,?,?,?,?)',(self.id,'Owner',hashlib.sha256(self.token.encode()).hexdigest(),1,1))

    def tearDown(self): self.temp.cleanup()

    def test_only_valid_token_and_enabled_user(self):
        with m.database() as db:
            self.assertEqual(m.authorize(db,self.token)['id'],self.id)
            self.assertIsNone(m.authorize(db,secrets.token_urlsafe(32)))
            self.assertIsNone(m.authorize(db,"' OR 1=1 --"))
            db.execute('UPDATE users SET enabled=0')
            self.assertIsNone(m.authorize(db,self.token))
        self.assertNotIn(self.token.encode(),m.DB.read_bytes())

    def test_grant_rejects_internal_reserved_and_ipv6(self):
        with m.database() as db:
            for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1','192.168.1.1','0.0.0.0','::1','2001:4860:4860::8888','garbage']:
                with self.subTest(ip=ip), self.assertRaises(ValueError): m.grant(db,self.id,ip,100)

    def test_three_networks_expiry_and_disabled_user(self):
        with m.database() as db:
            for i,ip in enumerate(['1.1.1.1','8.8.8.8','9.9.9.9','8.8.4.4']): m.grant(db,self.id,ip,100+i)
            ips = {r['ip'] for r in db.execute('SELECT ip FROM networks')}
            self.assertEqual(ips,{'8.8.8.8','9.9.9.9','8.8.4.4'})
            m.grant(db,self.id,'1.0.0.1',100+m.GRANT_SECONDS+4)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM networks').fetchone()[0],1)
            db.execute('UPDATE users SET enabled=0')
            with self.assertRaises(ValueError): m.grant(db,self.id,'8.8.8.8',999999)

    def test_simultaneous_activation_keeps_current_network(self):
        with m.database() as db:
            for ip in ['9.9.9.9','8.8.8.8','8.8.4.4','1.1.1.1']: m.grant(db,self.id,ip,100)
            ips = {r['ip'] for r in db.execute('SELECT ip FROM networks')}
            self.assertEqual(len(ips),3); self.assertIn('1.1.1.1',ips)

    def test_domain_rules_bounded_and_ipv6_selective(self):
        ds=m.domains(); self.assertNotIn('google.com',ds); self.assertNotIn('github.io',ds)
        rules=m.rules_for([])
        self.assertTrue(any('dnstype=AAAA|HTTPS|SVCB' in r for r in rules))
        for d in ds:
            import re
            pat=re.compile(r'^([a-z0-9-]+\.)*'+re.escape(d)+'$')
            self.assertTrue(pat.fullmatch(d)); self.assertTrue(pat.fullmatch('a.'+d)); self.assertFalse(pat.fullmatch('evil'+d))
        with self.assertRaises(ValueError): m.rules_for([{'domain':'a.com\ninject','user_id':'*'}])

    def test_apple_profile_contains_correct_doh_no_activation_secret(self):
        b=m.apple_profile({'id':self.id}); d=plistlib.loads(b)
        self.assertEqual(d['PayloadContent'][0]['DNSSettings']['ServerURL'],f'https://{m.BASE}/dns-query/{self.id}')
        self.assertNotIn(self.token.encode(),b)


if __name__ == '__main__': unittest.main()
