#!/usr/bin/env python3
"""Query top scored events from the 100K test."""
import subprocess

CH_CMD = [
    "docker", "exec", "clif-clickhouse01", "clickhouse-client",
    "--user", "clif_admin", "--password", "Cl1f_Ch@ngeM3_2026!",
    "-d", "clif_logs", "--format", "PrettyCompact",
]

# Top 15 highest scored events
q1 = """
SELECT combined_score, lgbm_score, action, hostname, source_ip, user_id, mitre_tactic
FROM triage_scores
WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
ORDER BY combined_score DESC LIMIT 15
"""

# Score histogram by level and source data
q2 = """
SELECT
  multiIf(hostname LIKE '%bastion%' OR hostname LIKE '%jump%', 'bastion/jump',
          hostname LIKE '%web%', 'web-server',
          hostname LIKE '%app%', 'app-server',
          hostname LIKE '%db%', 'database',
          hostname LIKE '%k8s%', 'kubernetes',
          hostname LIKE '%ci%', 'ci-runner',
          hostname LIKE '%vpn%', 'vpn/proxy',
          'other') as host_group,
  count(*) as total,
  countIf(action = 'escalate') as esc,
  countIf(action = 'monitor') as mon,
  countIf(action = 'discard') as disc,
  round(avg(combined_score), 4) as avg_score,
  round(max(combined_score), 4) as max_score
FROM triage_scores
WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
GROUP BY host_group ORDER BY avg_score DESC
"""

# Detection by MITRE tactic
q3 = """
SELECT mitre_tactic, count(*) as cnt,
       round(avg(combined_score), 4) as avg_score,
       round(max(combined_score), 4) as max_score
FROM triage_scores
WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
  AND mitre_tactic != ''
GROUP BY mitre_tactic ORDER BY avg_score DESC
"""

# Events with shap features
q4 = """
SELECT combined_score, action, shap_top_features
FROM triage_scores
WHERE timestamp >= '2026-03-26 11:30:00' AND timestamp < '2026-03-26 11:31:00'
  AND combined_score > 0.9
ORDER BY combined_score DESC LIMIT 10
"""

for title, q in [
    ("Top 15 Scored Events", q1),
    ("Score by Host Group", q2),
    ("Detection by MITRE Tactic", q3),
    ("SHAP Features (top escalated)", q4),
]:
    print(f"\n=== {title} ===")
    r = subprocess.run(CH_CMD + ["-q", q.strip()], capture_output=True, text=True)
    if r.stdout.strip():
        print(r.stdout)
    else:
        print("  (no results)")
    if r.returncode:
        print(f"  ERR: {r.stderr[:200]}")
