"""Query ClickHouse for triage results from real-log test."""
import clickhouse_connect
import sys

client = clickhouse_connect.get_client(
    host="10.52.166.221", port=8123,
    username="clif_admin", password="Cl1f_Ch@ngeM3_2026!",
    database="clif_logs",
)

minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 5

# Summary by source_type
q = f"""
SELECT source_type, count(*) as total,
       countIf(action = 'escalate') as escalated,
       countIf(action = 'monitor') as monitored,
       countIf(action = 'discard') as discarded,
       round(avg(combined_score), 4) as avg_score,
       round(max(combined_score), 4) as max_score
FROM triage_scores
WHERE timestamp > now() - INTERVAL {minutes} MINUTE
GROUP BY source_type
ORDER BY source_type
"""
rows = client.query(q)
print(f"=== Triage Score Summary (last {minutes} min) ===")
print(f"{'type':<15} {'total':>7} {'esc':>7} {'mon':>7} {'disc':>7} {'avg':>8} {'max':>8}")
for r in rows.result_rows:
    st, total, esc, mon, disc, avg_s, max_s = r
    print(f"{st:<15} {total:>7,} {esc:>7,} {mon:>7,} {disc:>7,} {avg_s:>8.4f} {max_s:>8.4f}")

# Action breakdown
q2 = f"""
SELECT source_type, action, count(*) as cnt
FROM triage_scores
WHERE timestamp > now() - INTERVAL {minutes} MINUTE
GROUP BY source_type, action
ORDER BY source_type, action
"""
rows2 = client.query(q2)
print(f"\n=== Detailed Action Counts ===")
for r in rows2.result_rows:
    print(f"  {r[0]:<15} {r[1]:<12} {r[2]:>7,}")

# Top scores by source_type
for st in ["syslog", "cloud", "dns", "ad", "cloudtrail", "windows"]:
    q3 = f"""
    SELECT combined_score, lgbm_score, action
    FROM triage_scores
    WHERE timestamp > now() - INTERVAL {minutes} MINUTE
      AND source_type = '{st}'
    ORDER BY combined_score DESC
    LIMIT 5
    """
    rows3 = client.query(q3)
    if rows3.result_rows:
        print(f"\n=== Top 5 scores for {st} ===")
        for r in rows3.result_rows:
            print(f"  combined={r[0]:.4f}  lgbm={r[1]:.4f}  action={r[2]}")

# All distinct source types
q4 = f"""
SELECT DISTINCT source_type FROM triage_scores
WHERE timestamp > now() - INTERVAL {minutes} MINUTE
"""
rows4 = client.query(q4)
print(f"\n=== All source_types in last {minutes} min ===")
for r in rows4.result_rows:
    print(f"  {r[0]}")
