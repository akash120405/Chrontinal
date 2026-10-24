#!/usr/bin/env python3
"""Nuclear cleanup - truncate ALL ClickHouse tables"""
import os
import urllib.parse
import urllib.request

URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))

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
