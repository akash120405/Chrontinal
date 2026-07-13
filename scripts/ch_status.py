#!/usr/bin/env python3
import urllib.request
URL = "http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs"
def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=10)
    return r.read().decode().strip()
tables = ['raw_logs','security_events','network_events','process_events','triage_scores','hunter_investigations','verifier_results','dead_letter_events']
for t in tables:
    try: print(f"{t}: {ch(f'SELECT count() FROM {t}')}")
    except Exception as e: print(f"{t}: ERR {e}")
