import os
import urllib.parse
import urllib.request

URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))

def ch(q):
    r = urllib.request.urlopen(urllib.request.Request(URL, data=q.encode()))
    return r.read().decode().strip()

print("=== PIPELINE COUNTS ===")
print("Triage total:", ch("SELECT count() FROM triage_scores"))
print("  Escalated:", ch("SELECT count() FROM triage_scores WHERE action='escalate'"))
print("  Monitored:", ch("SELECT count() FROM triage_scores WHERE action='monitor'"))
print("  Discarded:", ch("SELECT count() FROM triage_scores WHERE action='discard'"))
print()

print("Hunter:", ch("SELECT count() FROM hunter_investigations"))
print("  CONFIRMED_ATTACK:", ch("SELECT count() FROM hunter_investigations WHERE finding_type='CONFIRMED_ATTACK'"))
print("  Other:", ch("SELECT count() FROM hunter_investigations WHERE finding_type!='CONFIRMED_ATTACK'"))
print()

print("Verifier:", ch("SELECT count() FROM verifier_results"))
print("  true_positive:", ch("SELECT count() FROM verifier_results WHERE verdict='true_positive'"))
print("  false_positive:", ch("SELECT count() FROM verifier_results WHERE verdict='false_positive'"))
print("  Avg confidence:", ch("SELECT round(avg(confidence),4) FROM verifier_results"))
print()

print("Evidence anchors:", ch("SELECT count() FROM evidence_anchors"))
print()

print("=== SCORE STATS ===")
print("Escalated avg:", ch("SELECT round(avg(combined_score),4) FROM triage_scores WHERE action='escalate'"))
print("Escalated min:", ch("SELECT round(min(combined_score),4) FROM triage_scores WHERE action='escalate'"))
print("Escalated max:", ch("SELECT round(max(combined_score),4) FROM triage_scores WHERE action='escalate'"))
print("Monitored avg:", ch("SELECT round(avg(combined_score),4) FROM triage_scores WHERE action='monitor'"))
print("Discarded avg:", ch("SELECT round(avg(combined_score),4) FROM triage_scores WHERE action='discard'"))
print()

print("=== MITRE TACTIC x ACTION ===")
print(ch("SELECT mitre_tactic, action, count() as c, round(avg(combined_score),4) as avg_score FROM triage_scores GROUP BY mitre_tactic, action ORDER BY mitre_tactic, action FORMAT TabSeparated"))
print()

print("=== SECURITY EVENT CATEGORIES ===")
print(ch("SELECT JSONExtractString(metadata, 'category') as cat, count() as c FROM security_events GROUP BY cat ORDER BY c DESC FORMAT TabSeparated"))
print()

print("=== RAW COUNTS ===")
print("security_events:", ch("SELECT count() FROM security_events"))
print("network_events:", ch("SELECT count() FROM network_events"))
print("raw_logs:", ch("SELECT count() FROM raw_logs"))
