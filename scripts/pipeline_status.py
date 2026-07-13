#!/usr/bin/env python3
"""Pipeline status check — counts across all tables"""
import urllib.request, time

URL = 'http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs'

def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()), timeout=30)
    return r.read().decode().strip()

tables = [
    'raw_logs', 'security_events', 'network_events', 'process_events',
    'triage_scores', 'hunter_investigations', 'verifier_results',
    'evidence_anchors', 'features_entity_freq', 'features_entity_baseline',
    'triage_score_rollup', 'events_per_minute', 'events_per_10s',
    'security_severity_hourly', 'hunter_training_data',
]

print(f'=== PIPELINE STATUS @ {time.strftime("%H:%M:%S")} ===')
total_ch = 0
for t in tables:
    try:
        cnt = int(ch(f'SELECT count() FROM {t}'))
        total_ch += cnt
        print(f'  {t:40s} {cnt:>12,}')
    except Exception as e:
        print(f'  {t:40s} ERROR: {e}')

print(f'  {"TOTAL":40s} {total_ch:>12,}')
print()

# Triage action breakdown
try:
    r = ch("SELECT action, count() as c, round(avg(combined_score),4) as avg FROM triage_scores GROUP BY action ORDER BY action FORMAT TabSeparated")
    if r:
        print('=== TRIAGE ACTIONS ===')
        for line in r.split('\n'):
            print(f'  {line}')
        print()
except:
    pass

# Hunter/Verifier breakdown
try:
    r = ch("SELECT finding_type, count() FROM hunter_investigations GROUP BY finding_type FORMAT TabSeparated")
    if r:
        print('=== HUNTER ===')
        for line in r.split('\n'):
            print(f'  {line}')
        print()
except:
    pass

try:
    r = ch("SELECT verdict, count(), round(avg(confidence),4) FROM verifier_results GROUP BY verdict FORMAT TabSeparated")
    if r:
        print('=== VERIFIER ===')
        for line in r.split('\n'):
            print(f'  {line}')
except:
    pass
