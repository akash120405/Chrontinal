"""Quick verification of all dashboard API endpoints against real ClickHouse data."""
import json
import urllib.request

BASE = "http://localhost:3001/api"

def get(ep):
    return json.loads(urllib.request.urlopen(f"{BASE}/{ep}", timeout=10).read())

endpoints = {
    "metrics": lambda d: (
        f"totalEvents={d['totalEvents']}, tables={d['tableCounts']}, "
        f"ingestRate={d['ingestRate']}, riskScore={d['riskScore']}, "
        f"severity={d['severityDistribution']}"
    ),
    "alerts": lambda d: (
        f"total={d['total']}, critical={d['critical']}, high={d['high']}, "
        f"medium={d['medium']}, confidence_first={d['alerts'][0]['confidence'] if d['alerts'] else 'none'}"
    ),
    "ai/agents": lambda d: (
        f"agents={[a['name'] for a in d['agents']]}, "
        f"totalProcessed={d['pipeline']['totalProcessed']}, "
        f"hmac={d['pipeline']['hmacEnabled']}"
    ),
    "ai/leaderboard": lambda d: (
        f"samples={d['binary'][0]['samplesLast24h']}, "
        f"totalProcessed={d['ensemble']['totalProcessed']}, "
        f"lgbmAvg={d['binary'][0]['avgScore']}, "
        f"escalateRate={d['ensemble']['escalateRate']}"
    ),
    "ai/xai": lambda d: (
        f"available={d['available']}, "
        f"featureCount={len(d.get('globalFeatures', []))}, "
        f"top3={[f['feature'] for f in d.get('globalFeatures', [])[:3]]}"
    ),
    "investigations": lambda d: (
        f"count={len(d['investigations'])}, total={d['total']}, "
        f"hunt_statuses={set(i['hunt_status'] for i in d['investigations'])}, "
        f"severities={set(i['severity'] for i in d['investigations'])}"
    ),
    "events/stream": lambda d: (
        f"count={len(d['data'])}, "
        f"sources={set(e.get('_table','?') for e in d['data'][:20])}"
    ),
    "threat-intel": lambda d: (
        f"iocs={len(d.get('iocs', []))}, "
        f"mitre={len(d.get('mitre_patterns', []))}, "
        f"threats={len(d.get('active_threats', []))}"
    ),
    "evidence/chain": lambda d: (
        f"batches={d['summary']['totalBatches']}, "
        f"anchored={d['summary']['totalAnchored']}"
    ),
    "system": lambda d: (
        f"brokers={d.get('redpanda', {}).get('brokers', 0)}, "
        f"partitions={d.get('redpanda', {}).get('totalPartitions', 0)}, "
        f"healthy={d.get('redpanda', {}).get('isHealthy', False)}, "
        f"services={len(d.get('services', []))}"
    ),
    "reports/ml": lambda d: (
        f"tp={d['tpFpRatio']['truePositive']}, fp={d['tpFpRatio']['falsePositive']}, "
        f"precision={d['tpFpRatio']['precision']}, "
        f"samples24h={d['modelHealth']['samplesLast24h']}, "
        f"scoreDist(first3)={d['scoreDistribution'][:3]}"
    ),
}

print("=" * 70)
print("CLIF Dashboard API Verification — All 11 Endpoints")
print("=" * 70)
for ep, fmt in endpoints.items():
    try:
        d = get(ep)
        print(f"\n[OK] /api/{ep}")
        print(f"     {fmt(d)}")
    except Exception as e:
        print(f"\n[FAIL] /api/{ep}")
        print(f"     {e}")
print("\n" + "=" * 70)
