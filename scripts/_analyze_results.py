#!/usr/bin/env python3
"""Quick ClickHouse analysis of triage results."""
import subprocess

def ch_query(q):
    r = subprocess.run(
        ['docker','exec','clif-clickhouse01','clickhouse-client',
         '--user','clif_admin','--password','Cl1f_Ch@ngeM3_2026!',
         '--database','clif_logs','-q', q],
        capture_output=True, text=True
    )
    return r.stdout.strip()

queries = {
    "ACTION RANGES": """
        SELECT action,
            round(min(combined_score),4) as min_c,
            round(max(combined_score),4) as max_c,
            round(avg(combined_score),4) as avg_c,
            round(min(lgbm_score),4) as min_lgbm,
            round(max(lgbm_score),4) as max_lgbm
        FROM triage_scores GROUP BY action ORDER BY action
    """,
    "SYSLOG BREAKDOWN": """
        SELECT action, round(avg(combined_score),4) as avg_c,
            round(avg(lgbm_score),4) as avg_lgbm, count() as cnt
        FROM triage_scores WHERE source_type='syslog'
        GROUP BY action ORDER BY action
    """,
    "WINDOWS BREAKDOWN": """
        SELECT action, round(avg(combined_score),4) as avg_c,
            round(avg(lgbm_score),4) as avg_lgbm, count() as cnt
        FROM triage_scores WHERE source_type='windows_event'
        GROUP BY action ORDER BY action
    """,
    "PROCESS BREAKDOWN": """
        SELECT action, round(avg(combined_score),4) as avg_c,
            round(avg(lgbm_score),4) as avg_lgbm, count() as cnt
        FROM triage_scores WHERE source_type='process'
        GROUP BY action ORDER BY action
    """,
    "CLOUD BREAKDOWN": """
        SELECT action, round(avg(combined_score),4) as avg_c,
            round(avg(lgbm_score),4) as avg_lgbm, count() as cnt
        FROM triage_scores WHERE source_type='cloudtrail'
        GROUP BY action ORDER BY action
    """,
    "ESCALATE ADJUSTMENTS": """
        SELECT adjustments, count() as cnt
        FROM triage_scores WHERE action='escalate'
        GROUP BY adjustments ORDER BY cnt DESC LIMIT 10
    """,
    "COMBINED SCORE DIST (escalated)": """
        SELECT round(combined_score, 2) as bucket, count() as cnt
        FROM triage_scores WHERE action='escalate'
        GROUP BY bucket ORDER BY bucket LIMIT 20
    """,
}

for name, q in queries.items():
    print(f"\n=== {name} ===")
    print(ch_query(q))
