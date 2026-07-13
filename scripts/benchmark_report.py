#!/usr/bin/env python3
"""Final benchmark report — collect and display complete results."""
import urllib.request, time, sys
from datetime import datetime, timezone

URL = "http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs"

def ch(q, timeout=30):
    try:
        r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=timeout)
        return r.read().decode().strip()
    except Exception as e:
        return f"ERR:{e}"

# Wait for triage to stabilize (check every 10s for 10 min)
print("Waiting for triage pipeline to stabilize...")
prev_triage = 0
stable = 0
for i in range(60):
    time.sleep(10)
    try:
        r = ch("SELECT count() FROM triage_scores")
        triage = int(r) if r and not r.startswith("ERR") else 0
    except:
        triage = 0
    print(f"  Triage: {triage:,}", flush=True)
    if triage == prev_triage and triage > 0:
        stable += 1
    else: 
        stable = 0
    prev_triage = triage
    if stable >= 3:
        break

def safe_int(val, default=0):
    try:
        if val and not val.startswith("ERR"):
            return int(val)
    except:
        pass
    return default

# Collect final stats
raw = safe_int(ch("SELECT count() FROM raw_logs"))
sec = safe_int(ch("SELECT count() FROM security_events"))
net = safe_int(ch("SELECT count() FROM network_events"))
proc = safe_int(ch("SELECT count() FROM process_events"))
ch_total = raw + sec + net + proc
triage = safe_int(ch("SELECT count() FROM triage_scores"))
hunter = safe_int(ch("SELECT count() FROM hunter_investigations"))
verifier = safe_int(ch("SELECT count() FROM verifier_results"))
dead = safe_int(ch("SELECT count() FROM dead_letter_events"))

# Action breakdown (monitor=suspicious, escalate=anomalous)
monitor = safe_int(ch("SELECT count() FROM triage_scores WHERE action='monitor'"))
escalate = safe_int(ch("SELECT count() FROM triage_scores WHERE action='escalate'"))
discard = safe_int(ch("SELECT count() FROM triage_scores WHERE action='discard'"))

# Scores
avg_score = ch("SELECT round(avg(combined_score), 6) FROM triage_scores")
max_score = ch("SELECT round(max(combined_score), 6) FROM triage_scores")
p99_score = ch("SELECT round(quantile(0.99)(combined_score), 6) FROM triage_scores")

# Source type distributions
src_raw = ch("SELECT source_type, count() as c FROM raw_logs GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")
src_sec = ch("SELECT source_type, count() as c FROM security_events GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")
src_net = ch("SELECT source_type, count() as c FROM network_events GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")

# MITRE
mitre = ch("SELECT mitre_tactic, count() as c FROM triage_scores WHERE mitre_tactic != 'unknown' AND mitre_tactic != '' GROUP BY mitre_tactic ORDER BY c DESC LIMIT 10 FORMAT TabSeparated")

# Severity
sev_dist = ch("SELECT action, count() as c, round(avg(combined_score), 6) as avg_score FROM triage_scores GROUP BY action ORDER BY c DESC FORMAT TabSeparated")

SENT = 2_000_000
SEND_TIME = 85.1  # from benchmark output
data_loss = max(0, SENT - ch_total) / SENT * 100 if SENT > 0 else 0
send_eps = SENT / SEND_TIME

print(f"""
{'='*70}
       CLIF REAL-DATA BENCHMARK — FINAL RESULTS
{'='*70}

  DATA SOURCE:        100% REAL logs (ZERO synthetic)
                      16 datasets, 11 source types
                      Sources: SSH, Syslog, Windows Events, EVTX attacks,
                      UNSW Firewall, DNS DGA, CloudTrail, CSIC Web,
                      NetFlow, CIC-IDS-2018, Email Phishing, LANL AD
  
  INGESTION:
    Events Sent:        {SENT:>12,}
    Send Time:          {SEND_TIME:>12.1f}s
    Send EPS:           {send_eps:>12,.0f}
    Workers:                       8
    
  CLICKHOUSE:
    raw_logs:           {raw:>12,}
    security_events:    {sec:>12,}
    network_events:     {net:>12,}
    process_events:     {proc:>12,}
    TOTAL:              {ch_total:>12,}
    dead_letter:        {dead:>12,}
    DATA LOSS:          {data_loss:>11.2f}%
  
  AI PIPELINE:
    Triage Scored:      {triage:>12,}
      - discard:        {discard:>12,}
      - monitor:        {monitor:>12,}
      - escalate:       {escalate:>12,}
    Hunter Investig:    {hunter:>12,}
    Verifier Results:   {verifier:>12,}
  
  SCORES:
    avg_score:          {avg_score}
    p99_score:          {p99_score}
    max_score:          {max_score}
  
  SOURCE TYPES (raw_logs):
""")

for line in (src_raw or "").strip().split("\n"):
    if line.strip():
        print(f"    {line}")

print("\n  SOURCE TYPES (security_events):")
for line in (src_sec or "").strip().split("\n"):
    if line.strip():
        print(f"    {line}")

print("\n  SOURCE TYPES (network_events):")
for line in (src_net or "").strip().split("\n"):
    if line.strip():
        print(f"    {line}")

print("\n  ACTION DISTRIBUTION:")
for line in (sev_dist or "").strip().split("\n"):
    if line.strip():
        print(f"    {line}")

if mitre and "ERR" not in mitre:
    print("\n  MITRE TACTICS:")
    for line in mitre.strip().split("\n"):
        if line.strip():
            print(f"    {line}")

# Grade
if send_eps >= 200000 and data_loss < 0.1:
    grade = "A+"
elif send_eps >= 100000 and data_loss < 1:
    grade = "A"
elif send_eps >= 50000 and data_loss < 2:
    grade = "B+"
elif send_eps >= 30000 and data_loss < 5:
    grade = "B"
elif send_eps >= 10000 and data_loss < 10:
    grade = "B-"
elif send_eps >= 5000 and data_loss < 20:
    grade = "C"
else:
    grade = "D"

# Triage coverage
triage_coverage = triage / ch_total * 100 if ch_total > 0 else 0

print(f"""
  TRIAGE COVERAGE:    {triage_coverage:>11.1f}%  ({triage:,} / {ch_total:,})
  
  OVERALL GRADE:      {grade}
  
{'='*70}
  Benchmark completed at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
{'='*70}
""")
