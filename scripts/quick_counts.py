import urllib.request, sys

url = 'http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs'
tables = [
    'triage_scores', 'hunter_investigations', 'verifier_results',
    'evidence_anchors', 'raw_logs', 'security_events', 'network_events',
    'events_per_10s', 'events_per_minute',
]
out = open(r'c:\CLIF\q_counts.txt', 'w')
for t in tables:
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=f'SELECT count() FROM {t}'.encode()))
        line = f'{t}: {r.read().decode().strip()}'
    except Exception as e:
        line = f'{t}: ERROR {e}'
    print(line)
    out.write(line + '\n')
out.close()
