"""Benchmark ClickHouse queries used by the dashboard to find slow ones."""
import urllib.request, json, time

queries = {
    "total_events": """SELECT (SELECT count() FROM clif_logs.raw_logs) +
        (SELECT count() FROM clif_logs.security_events) +
        (SELECT count() FROM clif_logs.process_events) +
        (SELECT count() FROM clif_logs.network_events) AS cnt""",

    "triage_full_scan": """SELECT toString(action) AS action, count() AS cnt,
        round(avg(adjusted_score),4) AS avg_score
        FROM clif_logs.triage_scores GROUP BY action""",

    "hunter_full_scan": """SELECT finding_type, count() AS cnt
        FROM clif_logs.hunter_investigations GROUP BY finding_type""",

    "verifier_full_scan": """SELECT verdict, count() AS cnt, avg(confidence) AS avg_conf
        FROM clif_logs.verifier_results GROUP BY verdict""",

    "alerts_join": """SELECT toString(se.event_id) AS event_id, se.timestamp, se.severity
        FROM clif_logs.security_events AS se
        LEFT JOIN (
          SELECT event_id, argMax(adjusted_score, timestamp) AS adjusted_score
          FROM clif_logs.triage_scores
          WHERE timestamp >= now() - INTERVAL 30 DAY
          GROUP BY event_id
        ) AS ts ON ts.event_id = se.event_id
        WHERE se.severity >= 2 AND se.timestamp >= now() - INTERVAL 30 DAY
        ORDER BY se.timestamp DESC LIMIT 100""",

    "table_counts": """SELECT 'raw_logs' AS tbl, count() AS cnt FROM clif_logs.raw_logs
        UNION ALL SELECT 'security_events', count() FROM clif_logs.security_events
        UNION ALL SELECT 'process_events', count() FROM clif_logs.process_events
        UNION ALL SELECT 'network_events', count() FROM clif_logs.network_events
        UNION ALL SELECT 'triage_scores', count() FROM clif_logs.triage_scores
        UNION ALL SELECT 'hunter_investigations', count() FROM clif_logs.hunter_investigations
        UNION ALL SELECT 'verifier_results', count() FROM clif_logs.verifier_results""",

    "risky_entities": """SELECT entity, entity_type, toUInt32(sum(weight)) AS risk FROM (
        SELECT user_id AS entity, 'user' AS entity_type,
               multiIf(severity=4,25,severity=3,10,severity=2,4,severity=1,1,0) AS weight
        FROM clif_logs.security_events
        WHERE user_id != '' AND timestamp >= now() - INTERVAL 24 HOUR
        UNION ALL
        SELECT hostname AS entity, 'host' AS entity_type,
               multiIf(severity=4,25,severity=3,10,severity=2,4,severity=1,1,0) AS weight
        FROM clif_logs.security_events
        WHERE hostname != '' AND timestamp >= now() - INTERVAL 24 HOUR
      ) GROUP BY entity, entity_type ORDER BY risk DESC LIMIT 8""",

    "severity_hourly": """SELECT severity, sum(event_count) AS cnt
        FROM clif_logs.security_severity_hourly
        WHERE severity >= 2 AND hour >= now() - INTERVAL 24 HOUR
        GROUP BY severity ORDER BY severity""",

    "mitre_tactic_heatmap": """SELECT mitre_tactic AS tactic,
        uniqExact(mitre_technique) AS techniques, count() AS alerts
        FROM clif_logs.security_events
        WHERE mitre_tactic != '' AND timestamp >= now() - INTERVAL 24 HOUR
        GROUP BY mitre_tactic ORDER BY alerts DESC""",

    "evidence_anchors": """SELECT count() AS batches, sum(event_count) AS anchored
        FROM clif_logs.evidence_anchors""",
}

url_base = "http://localhost:8123/?database=clif_logs&default_format=JSON&user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!"

print(f"{'Query':<25} {'Time':>8} {'Rows Read':>12} {'Result':>8}")
print("-" * 60)

for name, sql in queries.items():
    start = time.time()
    try:
        req = urllib.request.Request(url_base, data=sql.encode(), method="POST")
        req.add_header("Content-Type", "text/plain")
        resp = urllib.request.urlopen(req, timeout=120)
        data = json.loads(resp.read())
        elapsed = time.time() - start
        rows_read = data.get("statistics", {}).get("rows_read", "?")
        result_rows = data.get("rows", "?")
        flag = " *** SLOW" if elapsed > 2.0 else ""
        print(f"{name:<25} {elapsed:>7.2f}s {rows_read:>12} {result_rows:>8}{flag}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"{name:<25} FAILED {elapsed:.2f}s  {str(e)[:80]}")
