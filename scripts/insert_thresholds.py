import os
import urllib.parse
import urllib.request

URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))

def ch(q):
    return urllib.request.urlopen(urllib.request.Request(URL, data=q.encode())).read().decode().strip()

# Re-insert source thresholds
q = "INSERT INTO source_thresholds (source_type, suspicious_threshold, anomalous_threshold) VALUES ('security-events', 0.10, 0.35), ('network-events', 0.10, 0.35), ('raw-logs', 0.15, 0.40), ('socket', 0.10, 0.35)"
ch(q)
print('Source thresholds re-inserted')
print(ch('SELECT * FROM source_thresholds FORMAT TabSeparated'))
