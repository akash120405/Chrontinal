"""Quick check of triage results."""
import clickhouse_connect, sys

c = clickhouse_connect.get_client(
    host="10.52.166.221", port=8123,
    username="clif_admin", password="Cl1f_Ch@ngeM3_2026!",
    database="clif_logs",
)
mins = int(sys.argv[1]) if len(sys.argv) > 1 else 3

r = c.query(f"""
SELECT source_type, count(*) as total,
       countIf(action='escalate') as esc,
       countIf(action='monitor') as mon,
       countIf(action='discard') as disc,
       round(avg(combined_score),4) as avg_s,
       round(max(combined_score),4) as max_s,
       round(max(lgbm_score),4) as max_lgbm
FROM triage_scores
WHERE timestamp > now() - INTERVAL {mins} MINUTE
GROUP BY source_type ORDER BY source_type
""")
print(f"\n=== Triage Results (last {mins} min) ===")
fmt = "{:<15} {:>7} {:>7} {:>7} {:>7} {:>8} {:>8} {:>8}"
print(fmt.format("type", "total", "esc", "mon", "disc", "avg", "max", "maxLGBM"))
for row in r.result_rows:
    print(fmt.format(row[0], row[1], row[2], row[3], row[4],
                     f"{row[5]:.4f}", f"{row[6]:.4f}", f"{row[7]:.4f}"))

# Top 5 per type
for st in ["syslog", "dns", "cloudtrail", "cloud"]:
    r2 = c.query(f"""
    SELECT combined_score, lgbm_score, action
    FROM triage_scores
    WHERE timestamp > now() - INTERVAL {mins} MINUTE AND source_type = '{st}'
    ORDER BY combined_score DESC LIMIT 5
    """)
    if r2.result_rows:
        print(f"\n--- Top 5 {st} ---")
        for row in r2.result_rows:
            print(f"  combined={row[0]:.4f}  lgbm={row[1]:.4f}  action={row[2]}")

# All distinct source types
r3 = c.query(f"SELECT DISTINCT source_type FROM triage_scores WHERE timestamp > now() - INTERVAL {mins} MINUTE")
print(f"\n--- All source_types ---")
for row in r3.result_rows:
    print(f"  {row[0]}")
