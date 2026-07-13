#!/usr/bin/env python3
"""Check if ClickHouse is clean and insert thresholds"""
import urllib.request

URL = 'http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs'

def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()))
    return r.read().decode().strip()

# Check non-empty tables
tables = ch('SHOW TABLES FORMAT TabSeparated').split('\n')
nonempty = []
for t in tables:
    try:
        cnt = int(ch(f'SELECT count() FROM {t}'))
        if cnt > 0:
            nonempty.append((t, cnt))
    except:
        pass

if nonempty:
    print(f'WARNING: {len(nonempty)} non-empty tables:')
    for t, c in nonempty:
        print(f'  {t}: {c}')
else:
    print('All tables empty - CH is clean!')

# Insert source thresholds
print('\nInserting source thresholds...')
ch("""INSERT INTO source_thresholds (source_type, suspicious_threshold, anomalous_threshold) VALUES
('security-events', 0.10, 0.35),
('network-events', 0.10, 0.35),
('raw-logs', 0.15, 0.40),
('socket', 0.10, 0.35)""")
cnt = ch('SELECT count() FROM source_thresholds')
print(f'source_thresholds: {cnt} rows inserted')
