#!/usr/bin/env python3
"""Robust nuclear clear - handles large tables with timeout-safe truncation"""
import os
import urllib.parse
import urllib.request, time

URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))

def ch(q, timeout=120):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=timeout)
    return r.read().decode().strip()

tables = ch('SHOW TABLES FORMAT TabSeparated').split('\n')
print(f'Found {len(tables)} tables')

# First pass - truncate everything
for t in sorted(tables):
    try:
        cnt = ch(f'SELECT count() FROM {t}', timeout=10)
        if int(cnt) > 0:
            print(f'  Truncating {t} ({cnt} rows)...', end='', flush=True)
            ch(f'TRUNCATE TABLE IF EXISTS {t}', timeout=120)
            print(' OK')
        else:
            print(f'  Empty: {t}')
    except Exception as e:
        print(f'  Skip: {t} ({e})')

# Verify
print('\n=== VERIFY ===')
nonempty = []
for t in sorted(tables):
    try:
        cnt = int(ch(f'SELECT count() FROM {t}', timeout=10))
        if cnt > 0:
            nonempty.append((t, cnt))
    except:
        pass

if nonempty:
    print(f'{len(nonempty)} non-empty:')
    for t, c in nonempty:
        print(f'  {t}: {c}')
else:
    print('ALL CLEAN!')

# Insert thresholds
print('\nInserting source_thresholds...')
ch("""INSERT INTO source_thresholds (source_type, suspicious_threshold, anomalous_threshold) VALUES
('security-events', 0.10, 0.35),
('network-events', 0.10, 0.35),
('raw-logs', 0.15, 0.40),
('socket', 0.10, 0.35)""")
print(f'Thresholds: {ch("SELECT count() FROM source_thresholds")} rows')
print('DONE')
