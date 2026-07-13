"""Check all source types in triage_scores."""
import urllib.request, urllib.parse

def q(sql):
    params = urllib.parse.urlencode({
        'user': 'clif_admin',
        'password': 'Cl1f_Ch@ngeM3_2026!',
        'database': 'clif_logs',
        'query': sql,
    })
    return urllib.request.urlopen('http://localhost:8123/?' + params).read().decode()

print("=== All source_types in triage_scores ===")
print(q("SELECT source_type, count(), min(timestamp), max(timestamp) FROM triage_scores GROUP BY source_type ORDER BY count() DESC"))

print("\n=== Total rows ===")
print(q("SELECT count() FROM triage_scores"))

print("\n=== CloudTrail breakdown ===")
print(q("SELECT action, count() AS cnt, round(avg(lgbm_score),4), round(max(lgbm_score),4) FROM triage_scores WHERE source_type='cloudtrail' GROUP BY action ORDER BY action"))

print("\n=== CloudTrail total (all time) ===")
print(q("SELECT count() FROM triage_scores WHERE source_type='cloudtrail'"))

print("\n=== All sources last 8min ===")
print(q("SELECT source_type, count() FROM triage_scores WHERE timestamp > now() - INTERVAL 8 MINUTE GROUP BY source_type ORDER BY source_type"))

# Check raw_logs for CloudTrail
print("\n=== Raw logs recent (by source) ===")
try:
    print(q("SELECT source_type, count() FROM raw_logs WHERE timestamp > now() - INTERVAL 10 MINUTE GROUP BY source_type ORDER BY source_type"))
except Exception as e:
    print(f"raw_logs error: {e}")

# Check Kafka consumer group lag (via triage logs)
print("\n=== Triage total processed from all time ===")
print(q("SELECT count() FROM triage_scores"))
