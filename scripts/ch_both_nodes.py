import os
import urllib.request, urllib.parse

tables = ['raw_logs','security_events','network_events','process_events','triage_scores','hunter_investigations','verifier_results']

for port in [8123, 8124]:
    print(f'=== ClickHouse port {port} ===')
    for tbl in tables:
        try:
            q = urllib.parse.urlencode({
                'user': 'clif_admin',
                'password': os.environ["CLICKHOUSE_PASSWORD"],
                'database': 'clif_logs',
                'query': f'SELECT count() FROM {tbl}'
            })
            r = urllib.request.urlopen(f'http://localhost:{port}/?{q}', timeout=10)
            print(f'  {tbl}: {r.read().decode().strip()}')
        except Exception as e:
            print(f'  {tbl}: ERROR {e}')
