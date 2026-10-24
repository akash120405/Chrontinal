#!/usr/bin/env python3
import os
import urllib.parse
import urllib.request
URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))
def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=10)
    return r.read().decode().strip()
tables = ['raw_logs','security_events','network_events','process_events','triage_scores','hunter_investigations','verifier_results','dead_letter_events']
for t in tables:
    try: print(f"{t}: {ch(f'SELECT count() FROM {t}')}")
    except Exception as e: print(f"{t}: ERR {e}")
