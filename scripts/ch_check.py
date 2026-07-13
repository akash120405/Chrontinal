#!/usr/bin/env python3
import urllib.request, time

URL = 'http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs'

def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=30)
    return r.read().decode().strip()

out = []
out.append(f'=== CH STATUS @ {time.strftime("%H:%M:%S")} ===')

tables = ['raw_logs','security_events','network_events','process_events',
          'triage_scores','hunter_investigations','verifier_results',
          'evidence_anchors','hunter_training_data']

total = 0
for t in tables:
    try:
        cnt = int(ch(f'SELECT count() FROM {t}'))
        total += cnt
        out.append(f'  {t:40s} {cnt:>12,}')
    except Exception as e:
        out.append(f'  {t:40s} ERR: {e}')

out.append(f'  {"TOTAL":40s} {total:>12,}')
out.append('')

try:
    r = ch("SELECT action, count() as c, round(avg(combined_score),4) as avg FROM triage_scores GROUP BY action ORDER BY action FORMAT TabSeparated")
    if r:
        out.append('TRIAGE:')
        for line in r.split('\n'):
            out.append(f'  {line}')
        out.append('')
except: pass

try:
    r = ch("SELECT finding_type, count() FROM hunter_investigations GROUP BY finding_type FORMAT TabSeparated")
    if r:
        out.append('HUNTER:')
        for line in r.split('\n'):
            out.append(f'  {line}')
        out.append('')
except: pass

try:
    r = ch("SELECT verdict, count(), round(avg(confidence),4) FROM verifier_results GROUP BY verdict FORMAT TabSeparated")
    if r:
        out.append('VERIFIER:')
        for line in r.split('\n'):
            out.append(f'  {line}')
except: pass

result = '\n'.join(out)
with open('C:/CLIF/ch_status.txt', 'w') as f:
    f.write(result)
print(result)
