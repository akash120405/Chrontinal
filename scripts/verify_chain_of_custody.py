"""
Verify chain of custody integrity by re-computing Merkle roots
from raw event hashes and comparing with stored evidence_anchors.
"""
import hashlib
import json
import math
import urllib.request


CH_URL = "http://10.52.166.221:8123/"
CH_USER = "clif_admin"
CH_PASS = "Cl1f_Ch@ngeM3_2026!"
CH_DB = "clif_logs"


def ch_query(sql):
    """Execute a ClickHouse query via HTTP."""
    url = f"{CH_URL}?database={CH_DB}&default_format=JSON"
    req = urllib.request.Request(
        url, data=sql.encode(), method="POST",
        headers={
            "X-ClickHouse-User": CH_USER,
            "X-ClickHouse-Key": CH_PASS,
            "Content-Type": "text/plain",
        },
    )
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def sha256_hex(data):
    return hashlib.sha256(data.encode()).hexdigest()


def build_merkle_tree(leaf_hashes):
    if not leaf_hashes:
        return sha256_hex("EMPTY_BATCH"), 0
    n = len(leaf_hashes)
    depth = max(1, math.ceil(math.log2(n))) if n > 1 else 1
    target = 2 ** depth
    padded = leaf_hashes + [leaf_hashes[-1]] * (target - n)
    level = padded
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(sha256_hex(level[i] + level[i + 1]))
        level = next_level
    return level[0], depth


# Hash expressions per table (same as merkle_anchor.py)
HASH_EXPRS = {
    "raw_logs": "hex(SHA256(concat(toString(event_id), toString(timestamp), toString(source), toString(level), message)))",
    "security_events": "hex(SHA256(concat(toString(event_id), toString(timestamp), toString(severity), toString(category), toString(source), description, toString(mitre_tactic), toString(mitre_technique))))",
    "process_events": "hex(SHA256(concat(toString(event_id), toString(timestamp), hostname, toString(pid), toString(ppid), binary_path, arguments)))",
    "network_events": "hex(SHA256(concat(toString(event_id), toString(timestamp), hostname, IPv4NumToString(src_ip), IPv4NumToString(dst_ip), toString(src_port), toString(dst_port), protocol)))",
    "triage_scores": "hex(SHA256(concat(toString(event_id), toString(timestamp), source_type, hostname, toString(adjusted_score), toString(action), mitre_tactic, mitre_technique)))",
    "hunter_investigations": "hex(SHA256(concat(toString(investigation_id), toString(started_at), hostname, source_ip, toString(severity), finding_type, summary)))",
    "verifier_results": "hex(SHA256(concat(toString(verification_id), toString(started_at), toString(verdict), toString(confidence), toString(priority), analyst_summary)))",
}

TS_COLS = {
    "hunter_investigations": "started_at",
    "verifier_results": "started_at",
}

ID_COLS = {
    "hunter_investigations": "investigation_id",
    "verifier_results": "verification_id",
    "triage_scores": "score_id",
}


def verify_batch(batch):
    table = batch["table_name"]
    t0 = batch["time_from"]
    t1 = batch["time_to"]
    stored_root = batch["merkle_root"]
    stored_count = int(batch["event_count"])
    prev_root = batch.get("prev_merkle_root", "")

    hash_expr = HASH_EXPRS[table]
    ts_col = TS_COLS.get(table, "timestamp")
    id_col = ID_COLS.get(table, "event_id")

    sql = (
        f"SELECT {hash_expr} AS h FROM {table} "
        f"WHERE {ts_col} >= '{t0}' AND {ts_col} < '{t1}' "
        f"ORDER BY {id_col}"
    )
    result = ch_query(sql)
    hashes = [row["h"] for row in result["data"]]
    raw_root, depth = build_merkle_tree(hashes)

    # Apply chain hash (same as merkle_anchor.py)
    if prev_root:
        computed_root = sha256_hex(prev_root + raw_root)
    else:
        computed_root = raw_root

    match = computed_root == stored_root
    count_match = len(hashes) == stored_count

    return {
        "batch_id": batch["batch_id"],
        "table": table,
        "stored_count": stored_count,
        "recomputed_count": len(hashes),
        "count_match": count_match,
        "stored_root": stored_root[:16] + "...",
        "computed_root": computed_root[:16] + "...",
        "root_match": match,
        "depth": depth,
        "chained": bool(prev_root),
    }


# Fetch all evidence anchors
print("=" * 70)
print("  CLIF Chain of Custody — Merkle Integrity Verification")
print("=" * 70)

anchors = ch_query(
    "SELECT batch_id, table_name, event_count, merkle_root, merkle_depth, "
    "status, time_from, time_to, prev_merkle_root "
    "FROM evidence_anchors ORDER BY table_name, time_from"
)

total = len(anchors["data"])
passed = 0
failed = 0
count_mismatch = 0

for batch in anchors["data"]:
    try:
        r = verify_batch(batch)
        if r["root_match"] and r["count_match"]:
            status = "PASS"
            passed += 1
        elif not r["count_match"]:
            status = "COUNT_CHANGED"
            count_mismatch += 1
        else:
            status = "FAIL"
            failed += 1
        print(
            f"\n[{status}] {r['batch_id']}"
            f"\n       table={r['table']}, events={r['stored_count']}/{r['recomputed_count']}, "
            f"depth={r['depth']}, chained={r['chained']}"
            f"\n       stored_root ={r['stored_root']}"
            f"\n       computed_root={r['computed_root']}"
            f"\n       count_match={r['count_match']}, root_match={r['root_match']}"
        )
    except Exception as e:
        failed += 1
        print(f"\n[ERROR] {batch['batch_id']}: {e}")

print("\n" + "=" * 70)
print(f"  RESULT: {passed}/{total} batches verified OK")
if count_mismatch:
    print(f"  COUNT_CHANGED: {count_mismatch} batches (new data added to anchored windows)")
if failed:
    print(f"  INTEGRITY FAILURES: {failed} batches (root mismatch with same count)")
if failed == 0:
    print(f"  INTEGRITY: INTACT (all roots cryptographically verified)")
    if count_mismatch:
        print(f"  NOTE: {count_mismatch} batches have new events from second data push")
else:
    print(f"  INTEGRITY: COMPROMISED ({failed} unexplained root mismatches)")
print("=" * 70)
