#!/usr/bin/env python3
import os
import urllib.parse
import urllib.request
U=("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))
def ch(q):
    r=urllib.request.urlopen(urllib.request.Request(U,data=q.encode()),timeout=10)
    return r.read().decode().strip()
def si(q):
    try: return int(ch(q))
    except: return 0
raw=si("SELECT count() FROM raw_logs")
sec=si("SELECT count() FROM security_events")
net=si("SELECT count() FROM network_events")
proc=si("SELECT count() FROM process_events")
dead=si("SELECT count() FROM dead_letter_events")
t=raw+sec+net+proc
SENT=2000000
BLAST_TIME=56.7
send_eps=SENT/BLAST_TIME
ingest_eps=t/BLAST_TIME if t>0 else 0
loss=max(0,SENT-t)/SENT*100
print(f"raw={raw:,}  sec={sec:,}  net={net:,}  proc={proc:,}")
print(f"TOTAL CH={t:,}  dead={dead:,}  loss={loss:.3f}%")
print(f"Go blast: {SENT:,} in {BLAST_TIME}s = {send_eps:,.0f} EPS (send)")
print(f"Pipeline: {t:,} in {BLAST_TIME}s = {ingest_eps:,.0f} EPS (ingest)")
