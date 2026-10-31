#!/usr/bin/env python3
"""Isolated network-namespace firewall checks; never changes existing VPN namespaces."""
import json
import subprocess
import time
import smartdns as m


def cmd(args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=12)


def query(tcp=False):
    args=['ip','netns','exec','zsmartdns-qa','dig','@'+m.PUBLIC_IP,'+short','+time=1','+tries=1','chatgpt.com','A']
    if tcp: args.append('+tcp')
    # dig writes timeout diagnostics to stdout, including the server IP.
    return '\n'.join(line for line in cmd(args,False).stdout.splitlines() if line.strip()==m.PUBLIC_IP)


def main():
    access=m.agh('access/list'); users,nets,_=m.snapshot(); results={}
    cmd(['systemctl','stop','smartdns-sync.timer'])
    cmd(['systemctl','stop','smartdns-sync.service'])
    try:
        cmd(['ip','netns','add','zsmartdns-qa'])
        cmd(['ip','link','add','zsd-qa-host','type','veth','peer','name','zsd-qa-ns'])
        cmd(['ip','addr','add','198.19.0.1/30','dev','zsd-qa-host'])
        cmd(['ip','link','set','zsd-qa-host','up'])
        cmd(['ip','link','set','zsd-qa-ns','netns','zsmartdns-qa'])
        prefix=['ip','netns','exec','zsmartdns-qa']
        cmd(prefix+['ip','addr','add','198.19.0.2/30','dev','zsd-qa-ns'])
        cmd(prefix+['ip','link','set','zsd-qa-ns','up'])
        cmd(prefix+['ip','link','set','lo','up'])
        cmd(prefix+['ip','route','add',m.PUBLIC_IP+'/32','via','198.19.0.1'])
        results['unapproved_udp_blocked']=m.PUBLIC_IP not in query()
        results['unapproved_tcp_blocked']=m.PUBLIC_IP not in query(True)
        test_access={**access,'allowed_clients':access['allowed_clients']+['198.19.0.2']}
        m.agh('access/set',test_access)
        cmd(['nft','add','element','inet','zelyonka_smartdns','activated_v4','{','198.19.0.2','timeout','20s','}'])
        results['approved_udp_answers']=query()==m.PUBLIC_IP
        results['approved_tcp_answers']=query(True)==m.PUBLIC_IP
        cmd(['nft','delete','element','inet','zelyonka_smartdns','activated_v4','{','198.19.0.2','}'])
        cmd(['nft','add','element','inet','zelyonka_smartdns','activated_v4','{','198.19.0.2','timeout','1s','}'])
        time.sleep(1.3)
        results['expired_udp_blocked']=m.PUBLIC_IP not in query()
        results['expired_tcp_blocked']=m.PUBLIC_IP not in query(True)
        assert all(results.values()),results
        print(json.dumps(results,indent=2))
    finally:
        m.agh('access/set',access)
        m.firewall(nets)
        cmd(['ip','netns','delete','zsmartdns-qa'],False)
        cmd(['ip','link','delete','zsd-qa-host'],False)
        cmd(['systemctl','start','smartdns-sync.timer'])


if __name__=='__main__':main()
