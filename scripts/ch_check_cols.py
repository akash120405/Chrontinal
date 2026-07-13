#!/usr/bin/env python3
import urllib.request
URL = "http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs"
def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=30)
    return r.read().decode().strip()
print("=== triage_scores columns ===")
print(ch("SELECT name, type FROM system.columns WHERE database='clif_logs' AND table='triage_scores' FORMAT TabSeparated"))
print("\n=== sample row ===")
print(ch("SELECT * FROM triage_scores LIMIT 1 FORMAT Vertical"))
