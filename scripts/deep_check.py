"""Deep SSH analysis after brute force rule deployment."""
import os
import urllib.request
import urllib.parse

CH_URL = "http://localhost:8123/"
CH_USER = "clif_admin"
CH_PASS = os.environ["CLICKHOUSE_PASSWORD"]
CH_DB = "clif_logs"

def query(sql):
    params = urllib.parse.urlencode({
        'user': CH_USER,
        'password': CH_PASS,
        'database': CH_DB,
        'query': sql,
    })
    url = f"{CH_URL}?{params}"
    return urllib.request.urlopen(url).read().decode()

# 1. SSH action breakdown
print("=== SSH Action Breakdown ===")
print(query("""
    SELECT action,
           count() AS cnt,
           round(avg(lgbm_score), 4) AS avg_lgbm,
           round(max(lgbm_score), 4) AS max_lgbm,
           round(avg(combined_score), 4) AS avg_combined,
           round(max(combined_score), 4) AS max_combined
    FROM triage_scores
    WHERE timestamp > now() - INTERVAL 4 MINUTE
      AND source_type = 'syslog'
    GROUP BY action
    ORDER BY action
"""))

# 2. SSH lgbm score distribution
print("=== SSH LightGBM Score Buckets ===")
print(query("""
    SELECT
        multiIf(lgbm_score < 0.01, '<0.01',
                lgbm_score < 0.1, '0.01-0.1',
                lgbm_score < 0.5, '0.1-0.5',
                lgbm_score < 0.9, '0.5-0.9',
                '>=0.9') AS bucket,
        count() AS cnt
    FROM triage_scores
    WHERE timestamp > now() - INTERVAL 4 MINUTE
      AND source_type = 'syslog'
    GROUP BY bucket
    ORDER BY bucket
"""))

# 3. Sample of escalated syslog events
print("=== Sample Escalated SSH (top 10) ===")
print(query("""
    SELECT lgbm_score, combined_score, message
    FROM triage_scores
    WHERE timestamp > now() - INTERVAL 4 MINUTE
      AND source_type = 'syslog'
      AND action = 'escalate'
    ORDER BY lgbm_score DESC
    LIMIT 10
"""))

# 4. Sample of discarded syslog events
print("=== Sample Discarded SSH (top 5) ===")
print(query("""
    SELECT lgbm_score, combined_score, message
    FROM triage_scores
    WHERE timestamp > now() - INTERVAL 4 MINUTE
      AND source_type = 'syslog'
      AND action = 'discard'
    ORDER BY lgbm_score DESC
    LIMIT 5
"""))

# 5. CloudTrail (all-time since timestamps are 2017)
print("=== CloudTrail (all time) ===")
print(query("""
    SELECT action,
           count() AS cnt,
           round(avg(lgbm_score), 4) AS avg_lgbm,
           round(max(lgbm_score), 4) AS max_lgbm
    FROM triage_scores
    WHERE source_type = 'cloud'
      AND timestamp > '2017-01-01'
    GROUP BY action
    ORDER BY action
"""))
