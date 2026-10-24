#!/usr/bin/env python3
import os
import urllib.parse
import urllib.request
URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))
def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=30)
    return r.read().decode().strip()
print("=== triage_scores columns ===")
print(ch("SELECT name, type FROM system.columns WHERE database='clif_logs' AND table='triage_scores' FORMAT TabSeparated"))
print("\n=== sample row ===")
print(ch("SELECT * FROM triage_scores LIMIT 1 FORMAT Vertical"))
