"""Debug a specific batch's hash mismatch."""
import hashlib
import json
import math
import urllib.request

CH_URL = "http://10.52.166.221:8123/"
CH_USER = "clif_admin"
CH_PASS = "Cl1f_Ch@ngeM3_2026!"
CH_DB = "clif_logs"

def ch_query(sql):
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

# Check batch 5: raw_logs, 28 events
print("=== Debugging Batch 5: raw_logs ===")
sql = """SELECT hex(SHA256(concat(toString(event_id), toString(timestamp), toString(source), toString(level), message))) AS h 
FROM raw_logs 
WHERE timestamp >= '2026-03-23 19:56:13.000' AND timestamp < '2026-03-23 19:57:44.000' 
ORDER BY event_id"""

r = ch_query(sql)
hashes = [row["h"] for row in r["data"]]
print(f"Hash count from HTTP node1: {len(hashes)}")
root, depth = build_merkle_tree(hashes)
print(f"Computed root: {root[:32]}...")
print(f"Expected root: cc124ecdc932bce7...")
print()

# Now try same query on node2
CH_URL2 = "http://10.52.166.221:8124/"
def ch_query2(sql):
    url = f"{CH_URL2}?database={CH_DB}&default_format=JSON"
    req = urllib.request.Request(
        url, data=sql.encode(), method="POST",
        headers={
            "X-ClickHouse-User": CH_USER,
            "X-ClickHouse-Key": CH_PASS,
            "Content-Type": "text/plain",
        },
    )
    return json.loads(urllib.request.urlopen(req, timeout=30).read())

r2 = ch_query2(sql)
hashes2 = [row["h"] for row in r2["data"]]
print(f"Hash count from HTTP node2: {len(hashes2)}")
root2, depth2 = build_merkle_tree(hashes2)
print(f"Computed root (node2): {root2[:32]}...")
print(f"Same as node1? {root == root2}")
print(f"Hash lists equal? {hashes == hashes2}")

# Check what the merkle service on PC2 would see (native TCP to which host?)
# Let's check the stored root from evidence_anchors
batch = ch_query(
    "SELECT merkle_root, event_count FROM evidence_anchors "
    "WHERE batch_id = 'BATCH-raw_logs-20260323-195613'"
)
stored = batch["data"][0]
print(f"\nStored root:   {stored['merkle_root'][:32]}...")
print(f"Stored count:  {stored['event_count']}")

# Try lowercased hashes
hashes_lower = [h.lower() for h in hashes]
root_lower, _ = build_merkle_tree(hashes_lower)
print(f"\nWith lowercased leaves: {root_lower[:32]}...")
print(f"Matches stored? {root_lower[:16] == stored['merkle_root'][:16]}")
