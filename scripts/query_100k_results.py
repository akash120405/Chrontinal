#!/usr/bin/env python3
"""Query ClickHouse for 100K test results."""
import os
import subprocess, sys

CH_CMD = [
    "docker", "exec", "clif-clickhouse01", "clickhouse-client",
    "--user", "clif_admin", "--password", os.environ["CLICKHOUSE_PASSWORD"],
    "-d", "clif_logs", "--format", "PrettyCompact",
]

queries = [
    # 1. Overall action breakdown
    """
    SELECT action, count(*) as cnt,
           round(avg(combined_score), 4) as avg_score,
           round(avg(lgbm_score), 4) as avg_lgbm,
           round(max(combined_score), 4) as max_score
    FROM triage_scores
    WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
    GROUP BY action ORDER BY avg_score DESC
    """,

    # 2. Score distribution buckets
    """
    SELECT
        multiIf(combined_score >= 0.9, '0.90-1.00 (escalate)',
                combined_score >= 0.7, '0.70-0.89 (high)',
                combined_score >= 0.4, '0.40-0.69 (monitor)',
                combined_score >= 0.1, '0.10-0.39 (low)',
                                       '0.00-0.09 (benign)') as score_bucket,
        count(*) as cnt,
        round(count(*) * 100.0 / (SELECT count(*) FROM triage_scores WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'), 2) as pct
    FROM triage_scores
    WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
    GROUP BY score_bucket ORDER BY score_bucket DESC
    """,

    # 3. Top 15 highest scored events (likely attack detections)
    """
    SELECT combined_score, lgbm_score, action,
           substring(raw_event, 1, 120) as event_preview
    FROM triage_scores
    WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
    ORDER BY combined_score DESC LIMIT 15
    """,

    # 4. Total count
    """
    SELECT count(*) as total,
           round(countIf(combined_score >= 0.4) * 100.0 / count(*), 2) as suspicious_pct,
           round(countIf(combined_score >= 0.9) * 100.0 / count(*), 2) as escalation_pct
    FROM triage_scores
    WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
    """,
]

headers = [
    "=== 1. Action Breakdown ===",
    "\n=== 2. Score Distribution ===",
    "\n=== 3. Top 15 Highest Scored Events ===",
    "\n=== 4. Overall Summary ===",
]

for header, query in zip(headers, queries):
    print(header)
    result = subprocess.run(CH_CMD + ["-q", query.strip()],
                          capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("ERR:", result.stderr[:200])
