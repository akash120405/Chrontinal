import requests, json

r = requests.get('http://localhost:3001/api/metrics', timeout=30)
d = r.json()
ai = d.get('aiPipeline', {})

print('=== DASHBOARD METRICS (LIVE) ===')
print(f'  Total Events (raw):   {d["totalEvents"]:>12,}')
print(f'  Active Alerts:        {d["activeAlerts"]:>12,}')
print(f'  Critical Alerts:      {d.get("criticalAlertCount",0):>12,}')
print(f'  Ingest Rate:          {d["ingestRate"]:>12.1f} eps')
print(f'  Evidence Batches:     {d.get("evidenceBatches",0):>12,}')
print(f'  Evidence Anchored:    {d.get("evidenceAnchored",0):>12,}')
print(f'  Uptime:               {d.get("uptime","--"):>12}%')
print()
print('=== AI PIPELINE ===')
print(f'  Triage Scored:        {ai["triageTotal"]:>12,}')
for a in ai.get('triageActions', []):
    print(f'    {a["action"]:>12}: {a["count"]:>10,}  (avg {a["avgScore"]:.4f})')
print(f'  Hunter Investigations:{ai["hunterTotal"]:>12,}')
for h in ai.get('hunterTypes', []):
    print(f'    {h["type"]:>24}: {h["count"]:>6,}')
print(f'  Verifier Results:     {ai["verifierTotal"]:>12,}')
for v in ai.get('verifierVerdicts', []):
    print(f'    {v["verdict"]:>24}: {v["count"]:>6,}  (conf {v["avgConfidence"]:.4f})')
print()
print('=== TABLE COUNTS ===')
tc = d.get('tableCounts', {})
for t, c in sorted(tc.items(), key=lambda x: -x[1]):
    print(f'  {t:>25}: {c:>12,}')
print()
print('=== API HEALTH ===')
endpoints = [
    '/api/metrics', '/api/alerts', '/api/ai/agents', '/api/ai/leaderboard',
    '/api/investigations', '/api/evidence/chain', '/api/events/stream',
    '/api/threat-intel', '/api/reports', '/api/system',
]
for ep in endpoints:
    try:
        r2 = requests.get(f'http://localhost:3001{ep}', timeout=30)
        ok = 'OK' if r2.status_code == 200 else 'FAIL'
        print(f'  {ok:>4} {r2.status_code} {ep} ({len(r2.content):,} bytes)')
    except Exception as e:
        print(f'  FAIL {ep} ({e})')
