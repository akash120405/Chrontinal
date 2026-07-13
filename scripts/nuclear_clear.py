#!/usr/bin/env python3
"""Nuclear cleanup - truncate ALL ClickHouse tables"""
import urllib.request

URL = 'http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs'

def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()))
    return r.read().decode().strip()

tables = ch('SHOW TABLES FORMAT TabSeparated').split('\n')
print(f'Found {len(tables)} tables')
for t in sorted(tables):
    try:
        cnt = ch(f'SELECT count() FROM {t}')
        if int(cnt) > 0:
            ch(f'TRUNCATE TABLE {t}')
            print(f'  TRUNCATED {t} ({cnt} rows)')
        else:
            print(f'  EMPTY     {t}')
    except Exception as e:
        print(f'  SKIP      {t} ({e})')

print('\n=== VERIFICATION ===')
for t in sorted(tables):
    try:
        cnt = ch(f'SELECT count() FROM {t}')
        if int(cnt) > 0:
            print(f'  WARNING: {t} still has {cnt} rows!')
    except:
        pass
print('DONE - All ClickHouse tables cleared')
