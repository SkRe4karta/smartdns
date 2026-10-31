#!/usr/bin/env python3
import argparse
import http.client
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import time

BASE='smartdns.zelyonkin.ru'; IP='109.120.185.213'


def https(path, data=None, headers=None, host=BASE, cafile=None, timeout=15):
    context = ssl.create_default_context(cafile=cafile)
    s = context.wrap_socket(socket.create_connection((IP,443),timeout=timeout), server_hostname=host)
    c = http.client.HTTPConnection(host,timeout=timeout); c.sock=s
    c.request('POST' if data is not None else 'GET',path,body=data,headers=headers or {})
    r=c.getresponse(); status=r.status; body=r.read(); c.close()
    return status,body


def packet(name,qtype=1):
    return struct.pack('!HHHHHH',secrets.randbelow(65536),0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',qtype,1)


def skip_name(data,offset):
    while data[offset]:
        if data[offset]&0xc0==0xc0: return offset+2
        offset+=data[offset]+1
    return offset+1


def answers(data):
    _,flags,qd,an,_,_=struct.unpack('!HHHHHH',data[:12]); off=12
    for _ in range(qd): off=skip_name(data,off)+4
    ips=[]
    for _ in range(an):
        off=skip_name(data,off); typ,cls,ttl,ln=struct.unpack('!HHIH',data[off:off+10]); off+=10
        if typ in (1,28): ips.append(str(ipaddress.ip_address(data[off:off+ln])))
        off+=ln
    return {'rcode':flags&15,'count':an,'ips':ips}


def udp(name='example.com',timeout=2):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(timeout); s.sendto(packet(name),(IP,53))
        try: return answers(s.recv(65535))
        except socket.timeout: return None


def tcp_dns(name='example.com',timeout=2):
    try:
        with socket.create_connection((IP,53),timeout=timeout) as s:
            q=packet(name); s.sendall(struct.pack('!H',len(q))+q)
            head=s.recv(2)
            if len(head)!=2: return None
            length=struct.unpack('!H',head)[0]; data=b''
            while len(data)<length:
                part=s.recv(length-len(data))
                if not part: return None
                data+=part
            return answers(data)
    except (socket.timeout,ConnectionError): return None


def main():
    p=argparse.ArgumentParser(); p.add_argument('--cafile'); p.add_argument('--activate',action='store_true'); a=p.parse_args()
    owner=json.loads(Path('outputs/owner-connection.json').read_text()); token=owner['activation'].split('#')[1]
    results={}
    results['portal_status']=https('/connect',cafile=a.cafile)[0]
    assert results['portal_status']==200
    assert https('/control/status',cafile=a.cafile)[0]==404
    assert https('/api/status',cafile=a.cafile)[0]==403
    assert https('/dns-query/unknown',packet('example.com'),{'Content-Type':'application/dns-message'},cafile=a.cafile)[0]==403
    headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
    if a.activate:
        results['plain_dns_before_activation']=tcp_dns()
        assert results['plain_dns_before_activation'] is None
        status,b=https('/api/activate',b'{}',{**headers,'X-Real-IP':'8.8.8.8','X-Forwarded-For':'8.8.8.8'},cafile=a.cafile)
        assert status==200,(status,b)
        results['activated_ip']=json.loads(b)['ip']
        assert results['activated_ip']!='8.8.8.8'
        time.sleep(8)
    status,b=https('/api/status',headers=headers,cafile=a.cafile)
    assert status==200; assert json.loads(b)['dot']==owner['dot']
    status,b=https('/api/profile',b'{}',headers,cafile=a.cafile)
    assert status==200; assert b'com.apple.dnsSettings.managed' in b
    results['apple_profile']=True
    for name,typ in [('example.com',1),('chatgpt.com',1),('chatgpt.com',28),('chatgpt.com',65),('chatgpt.com',64),('doubleclick.net',1),('cloudflare.com',28)]:
        status,b=https('/dns-query/'+owner['id'],packet(name,typ),{'Content-Type':'application/dns-message'},cafile=a.cafile)
        assert status==200,(status,b)
        result=answers(b); results[f'{name}/{typ}']=result
        if name=='chatgpt.com' and typ==1: assert result['ips']==[IP],result
        if name=='chatgpt.com' and typ!=1: assert result['count']==0,result
        if name=='doubleclick.net': assert result['ips']==['0.0.0.0'],result
        if name=='example.com': assert result['ips'] and IP not in result['ips'],result
        if name=='cloudflare.com': assert result['ips'],result
    if a.activate:
        results['plain_dns_after_activation']=tcp_dns('chatgpt.com')
        assert results['plain_dns_after_activation']['ips']==[IP]
    Path('work/integration-results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(results,ensure_ascii=False,indent=2))


if __name__=='__main__': main()
