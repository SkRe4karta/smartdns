import concurrent.futures
import json
from pathlib import Path
import statistics
import threading
import time
from integration import https,packet,answers,IP

ids=json.loads(Path('work/load-ids.json').read_text());barrier=threading.Barrier(len(ids))


def worker(i):
    barrier.wait(timeout=20);latencies=[];errors=[];proxied=False
    for n in range(10):
        start=time.monotonic()
        try:
            status,b=https('/dns-query/'+i,packet('example.com' if n%2==0 else 'chatgpt.com'),{'Content-Type':'application/dns-message'})
            assert status==200,('HTTP',status)
            result=answers(b);assert result['rcode']==0
            if n%2:assert result['ips']==[IP]
            latencies.append(time.monotonic()-start)
            if n==0:
                status,b=https('/cdn-cgi/trace',host='chatgpt.com');assert status==200
                assert ('ip='+IP).encode() in b;proxied=True
        except Exception as e:errors.append(type(e).__name__+': '+str(e))
        time.sleep(max(0,1-(time.monotonic()-start)))
    return {'latencies':latencies,'errors':errors,'proxy':proxied}


start=time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool: rows=list(pool.map(worker,ids))
lat=sorted(x for r in rows for x in r['latencies']);errors=[e for r in rows for e in r['errors']]
result={'profiles':len(ids),'dns_requests_success':len(lat),'dns_errors':len(errors),'proxy_success':sum(r['proxy'] for r in rows),
        'seconds':round(time.monotonic()-start,2),'dns_latency_p50_ms':round(statistics.median(lat)*1000,1),
        'dns_latency_p95_ms':round(lat[min(len(lat)-1,int(len(lat)*.95))]*1000,1),'errors':errors[:10]}
print(json.dumps(result,indent=2));Path('work/load-results.json').write_text(json.dumps(result,indent=2)+'\n')
assert not errors and len(lat)==len(ids)*10 and result['proxy_success']==len(ids)
