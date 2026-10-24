"""Detailed results check."""
import os
import urllib.request, urllib.parse

def q(sql):
    params = urllib.parse.urlencode({
        'user': 'clif_admin',
        'password': os.environ["CLICKHOUSE_PASSWORD"],
        'database': 'clif_logs',
        'query': sql,
    })
    return urllib.request.urlopen('http://localhost:8123/?' + params).read().decode()

print("=== CloudTrail (all time, no filter) ===")
print(q("SELECT action, count() AS cnt, round(avg(lgbm_score),4) AS avg_lgbm, round(max(lgbm_score),4) AS max_lgbm FROM triage_scores WHERE source_type='cloud' GROUP BY action ORDER BY action"))

print("=== CloudTrail total ===")
print(q("SELECT count() FROM triage_scores WHERE source_type='cloud'"))

print("=== DNS (last 5min) ===")
print(q("SELECT action, count() AS cnt, round(avg(lgbm_score),4) AS avg_lgbm, round(max(lgbm_score),4) AS max_lgbm FROM triage_scores WHERE source_type='dns' AND timestamp > now()-INTERVAL 5 MINUTE GROUP BY action ORDER BY action"))

print("=== SSH lgbm high scorers (model-detected) ===")
print(q("SELECT round(lgbm_score,4), round(combined_score,4), action FROM triage_scores WHERE source_type='syslog' AND timestamp > now()-INTERVAL 5 MINUTE AND lgbm_score > 0.5 ORDER BY lgbm_score DESC LIMIT 15"))

print("=== SSH combined score distribution ===")
print(q("""SELECT
    multiIf(combined_score < 0.1, '<0.1',
            combined_score < 0.4, '0.1-0.4',
            combined_score < 0.9, '0.4-0.9',
            combined_score < 0.92, '0.9-0.92',
            '>=0.92') AS bucket,
    count() AS cnt
FROM triage_scores
WHERE source_type='syslog' AND timestamp > now()-INTERVAL 5 MINUTE
GROUP BY bucket
ORDER BY bucket"""))
