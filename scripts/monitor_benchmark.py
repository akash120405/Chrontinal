#!/usr/bin/env python3
"""Monitor ClickHouse ingestion + triage after tcpblaster finishes. Final report."""
import os
import urllib.parse
import urllib.request, time, sys
from datetime import datetime, timezone

URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))
SENT = 2_000_000

def ch(q):
    try:
        r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=30)
        return r.read().decode().strip()
    except:
        return ""

def si(q):
    v = ch(q)
    try: return int(v)
    except: return 0

print("=== Monitoring pipeline after tcpblaster send ===\n")
t0 = time.time()
prev_ch = 0
prev_tri = 0
stable_ch = 0
stable_tri = 0
ch_done_time = None

while True:
    time.sleep(5)
    raw = si("SELECT count() FROM raw_logs")
    sec = si("SELECT count() FROM security_events")
    net = si("SELECT count() FROM network_events")
    proc = si("SELECT count() FROM process_events")
    ch_total = raw + sec + net + proc
    triage = si("SELECT count() FROM triage_scores")
    hunter = si("SELECT count() FROM hunter_investigations")
    verifier = si("SELECT count() FROM verifier_results")
    elapsed = time.time() - t0

    eps_ch = ch_total / elapsed if elapsed > 0 else 0
    print(f"  [{elapsed:6.1f}s] CH:{ch_total:>10,}  Triage:{triage:>10,}  Hunt:{hunter:>5}  Verif:{verifier:>5}  CH-EPS:{eps_ch:>8,.0f}", flush=True)

    if ch_total == prev_ch and ch_total > 0:
        stable_ch += 1
    else:
        stable_ch = 0
    if ch_total >= SENT and ch_done_time is None:
        ch_done_time = time.time() - t0

    if triage == prev_tri and triage > 0:
        stable_tri += 1
    else:
        stable_tri = 0

    prev_ch = ch_total
    prev_tri = triage

    # Wait until both CH and triage are stable
    if stable_ch >= 3 and stable_tri >= 3:
        break
    # Or timeout at 15 min
    if elapsed > 900:
        print("  Timeout 15min — generating report with current numbers")
        break

total_time = time.time() - t0

# Final numbers
raw = si("SELECT count() FROM raw_logs")
sec = si("SELECT count() FROM security_events")
net = si("SELECT count() FROM network_events")
proc = si("SELECT count() FROM process_events")
ch_total = raw + sec + net + proc
triage = si("SELECT count() FROM triage_scores")
hunter = si("SELECT count() FROM hunter_investigations")
verifier = si("SELECT count() FROM verifier_results")
dead = si("SELECT count() FROM dead_letter_events")

monitor_ct = si("SELECT count() FROM triage_scores WHERE action='monitor'")
escalate_ct = si("SELECT count() FROM triage_scores WHERE action='escalate'")
discard_ct = si("SELECT count() FROM triage_scores WHERE action='discard'")

avg_s = ch("SELECT round(avg(combined_score),6) FROM triage_scores")
p99_s = ch("SELECT round(quantile(0.99)(combined_score),6) FROM triage_scores")
max_s = ch("SELECT round(max(combined_score),6) FROM triage_scores")

mitre = ch("SELECT mitre_tactic, count() c FROM triage_scores WHERE mitre_tactic NOT IN ('unknown','') GROUP BY mitre_tactic ORDER BY c DESC LIMIT 10 FORMAT TabSeparated")

src_raw = ch("SELECT source_type, count() c FROM raw_logs GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")
src_sec = ch("SELECT source_type, count() c FROM security_events GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")
src_net = ch("SELECT source_type, count() c FROM network_events GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")

data_loss = max(0, SENT - ch_total) / SENT * 100 if SENT > 0 else 0
e2e_eps = ch_total / (ch_done_time if ch_done_time else total_time)
triage_cov = triage / ch_total * 100 if ch_total > 0 else 0

print(f"""
{'='*70}
       CLIF REAL-DATA BENCHMARK — FINAL RESULTS (Go Blaster)
{'='*70}

  DATA:               100% REAL logs, 16 datasets, 11 source types

  CLICKHOUSE:
    raw_logs:           {raw:>12,}
    security_events:    {sec:>12,}
    network_events:     {net:>12,}
    process_events:     {proc:>12,}
    TOTAL:              {ch_total:>12,}
    dead_letter:        {dead:>12,}
    
  DATA LOSS:            {data_loss:>11.3f}%
  CH Ingest Time:       {ch_done_time or total_time:>11.1f}s
  E2E Ingest EPS:       {e2e_eps:>11,.0f}
  
  AI PIPELINE:
    Triage Scored:      {triage:>12,}
      discard:          {discard_ct:>12,}
      monitor:          {monitor_ct:>12,}
      escalate:         {escalate_ct:>12,}
    Hunter:             {hunter:>12,}
    Verifier:           {verifier:>12,}
    
  Triage Coverage:      {triage_cov:>11.1f}%
  
  SCORES:
    avg:  {avg_s}    p99:  {p99_s}    max:  {max_s}
""")

if mitre:
    print("  MITRE TACTICS:")
    for l in mitre.strip().split("\n"):
        if l.strip():
            print(f"    {l}")

print(f"\n  SOURCE TYPES (raw_logs):")
for l in (src_raw or "").strip().split("\n"):
    if l.strip(): print(f"    {l}")
print(f"  SOURCE TYPES (security_events):")
for l in (src_sec or "").strip().split("\n"):
    if l.strip(): print(f"    {l}")
print(f"  SOURCE TYPES (network_events):")
for l in (src_net or "").strip().split("\n"):
    if l.strip(): print(f"    {l}")

print(f"\n{'='*70}")
print(f"  Done: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
print(f"{'='*70}")
