#!/usr/bin/env python3
"""
Real-Data Benchmark: Ingest 2M real events via TCP → Vector:9514
Monitor ClickHouse ingestion + triage/hunter/verifier pipeline
Produce benchmark report.

Usage:
  python3 /opt/clif/benchmark_real.py [--workers 8] [--file /opt/clif/real_2m_payload.ndjson]
"""
import os
import urllib.parse
import socket, time, threading, urllib.request, json, sys, os
from datetime import datetime, timezone
from collections import defaultdict

# ── Config ──────────────────────────────────────────────────────────────
VECTOR_HOST = "127.0.0.1"
VECTOR_PORT = 9514
WORKERS = 8
CHUNK_LINES = 500
FILE = "/opt/clif/real_2m_payload.ndjson"
CH_URL = ("http://localhost:8123/?" + urllib.parse.urlencode({"user": os.getenv("CLICKHOUSE_USER", "clif_admin"), "password": os.environ["CLICKHOUSE_PASSWORD"], "database": os.getenv("CLICKHOUSE_DB", "clif_logs")}))

# Parse CLI args
for i, a in enumerate(sys.argv[1:], 1):
    if a == "--workers" and i < len(sys.argv) - 1:
        WORKERS = int(sys.argv[i + 1])
    if a == "--file" and i < len(sys.argv) - 1:
        FILE = sys.argv[i + 1]


def ch(q, timeout=30):
    try:
        r = urllib.request.urlopen(urllib.request.Request(CH_URL, data=q.encode()), timeout=timeout)
        return r.read().decode().strip()
    except Exception as e:
        return f"ERR:{e}"


# ── Shared state ────────────────────────────────────────────────────────
sent_count = 0
error_count = 0
finished = False
lock = threading.Lock()
start_time = 0


# ── Worker ──────────────────────────────────────────────────────────────
def send_worker(worker_id, lines):
    global sent_count, error_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((VECTOR_HOST, VECTOR_PORT))
    except Exception as e:
        print(f"  Worker {worker_id}: connect failed: {e}")
        with lock:
            error_count += len(lines)
        return

    batch = []
    for line in lines:
        batch.append(line)
        if len(batch) >= CHUNK_LINES:
            payload = "".join(batch)
            try:
                sock.sendall(payload.encode())
                with lock:
                    sent_count += len(batch)
            except Exception as e:
                with lock:
                    error_count += len(batch)
            batch = []

    if batch:
        try:
            sock.sendall("".join(batch).encode())
            with lock:
                sent_count += len(batch)
        except Exception as e:
            with lock:
                error_count += len(batch)

    sock.close()


# ── Monitor ─────────────────────────────────────────────────────────────
def monitor():
    prev = 0
    while not finished:
        time.sleep(5)
        now_sent = sent_count
        elapsed = time.time() - start_time
        eps = (now_sent - prev) / 5 if prev > 0 else now_sent / max(elapsed, 1)
        prev = now_sent

        # Query ClickHouse counts
        try:
            raw = int(ch("SELECT count() FROM raw_logs", 5) or 0)
        except:
            raw = 0
        try:
            sec = int(ch("SELECT count() FROM security_events", 5) or 0)
        except:
            sec = 0
        try:
            net = int(ch("SELECT count() FROM network_events", 5) or 0)
        except:
            net = 0
        try:
            proc = int(ch("SELECT count() FROM process_events", 5) or 0)
        except:
            proc = 0
        try:
            triage = int(ch("SELECT count() FROM triage_scores", 5) or 0)
        except:
            triage = 0
        try:
            hunter = int(ch("SELECT count() FROM hunter_investigations", 5) or 0)
        except:
            hunter = 0
        try:
            verifier = int(ch("SELECT count() FROM verifier_results", 5) or 0)
        except:
            verifier = 0

        ch_total = raw + sec + net + proc
        print(f"  [{elapsed:6.1f}s] Sent:{now_sent:>9,}  EPS:{eps:>8,.0f}  "
              f"CH:{ch_total:>9,} (raw={raw} sec={sec} net={net} proc={proc})  "
              f"Triage:{triage:>7,}  Hunter:{hunter}  Verifier:{verifier}  "
              f"Errors:{error_count}", flush=True)


# ── Main ────────────────────────────────────────────────────────────────
def main():
    global sent_count, error_count, finished, start_time

    print(f"=== CLIF Real-Data Benchmark ===")
    print(f"File: {FILE}")
    print(f"Workers: {WORKERS}")

    # Load lines
    print("Loading payload...")
    t0 = time.time()
    with open(FILE, "r") as f:
        lines = f.readlines()
    total = len(lines)
    size_mb = os.path.getsize(FILE) / (1024 * 1024)
    print(f"Loaded {total:,} events ({size_mb:.1f} MB) in {time.time()-t0:.1f}s")

    # Check CH is empty
    pre_count = ch("SELECT count() FROM raw_logs")
    print(f"Pre-check: raw_logs={pre_count}")

    # Split lines among workers
    chunk_size = len(lines) // WORKERS
    chunks = []
    for i in range(WORKERS):
        start = i * chunk_size
        end = start + chunk_size if i < WORKERS - 1 else len(lines)
        chunks.append(lines[start:end])

    # Start monitor
    mon = threading.Thread(target=monitor, daemon=True)
    mon.start()

    # Start workers
    print(f"\nStarting {WORKERS} TCP workers...")
    start_time = time.time()
    threads = []
    for i, chunk in enumerate(chunks):
        t = threading.Thread(target=send_worker, args=(i, chunk))
        t.start()
        threads.append(t)

    # Wait for all workers
    for t in threads:
        t.join()

    send_elapsed = time.time() - start_time
    finished = True
    time.sleep(1)

    send_eps = sent_count / max(send_elapsed, 1)
    print(f"\n=== SEND COMPLETE ===")
    print(f"Sent: {sent_count:,} events in {send_elapsed:.1f}s")
    print(f"Send EPS: {send_eps:,.0f}")
    print(f"Errors: {error_count:,}")

    # Wait for pipeline to process everything (poll for 5 min)
    print("\nWaiting for pipeline to process...")
    stable_count = 0
    prev_total = 0
    for i in range(60):  # 5 min max
        time.sleep(5)
        try:
            raw = int(ch("SELECT count() FROM raw_logs", 5))
            sec = int(ch("SELECT count() FROM security_events", 5))
            net = int(ch("SELECT count() FROM network_events", 5))
            proc = int(ch("SELECT count() FROM process_events", 5))
            triage = int(ch("SELECT count() FROM triage_scores", 5))
            hunter = int(ch("SELECT count() FROM hunter_investigations", 5))
            verifier = int(ch("SELECT count() FROM verifier_results", 5))
        except:
            continue

        ch_total = raw + sec + net + proc
        elapsed = time.time() - start_time
        print(f"  [{elapsed:6.1f}s] CH:{ch_total:>9,}  Triage:{triage:>9,}  Hunter:{hunter:>6}  Verifier:{verifier:>6}", flush=True)

        if ch_total == prev_total and ch_total > 0:
            stable_count += 1
        else:
            stable_count = 0
        prev_total = ch_total

        if stable_count >= 3:  # 15s stable = done
            break

    total_elapsed = time.time() - start_time
    e2e_eps = ch_total / max(total_elapsed, 1)

    # Final counts
    print(f"\n{'='*70}")
    print(f"       CLIF REAL-DATA BENCHMARK RESULTS")
    print(f"{'='*70}")

    raw = int(ch("SELECT count() FROM raw_logs") or 0)
    sec = int(ch("SELECT count() FROM security_events") or 0)
    net = int(ch("SELECT count() FROM network_events") or 0)
    proc = int(ch("SELECT count() FROM process_events") or 0)
    triage = int(ch("SELECT count() FROM triage_scores") or 0)
    hunter = int(ch("SELECT count() FROM hunter_investigations") or 0)
    verifier = int(ch("SELECT count() FROM verifier_results") or 0)
    dead = int(ch("SELECT count() FROM dead_letter_events") or 0)
    ch_total = raw + sec + net + proc

    # Triage stats
    suspicious = int(ch("SELECT count() FROM triage_scores WHERE is_suspicious=1") or 0)
    anomalous = int(ch("SELECT count() FROM triage_scores WHERE is_anomalous=1") or 0)

    # Source types
    src_types = ch("SELECT source_type, count() as c FROM raw_logs GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")
    src_sec = ch("SELECT source_type, count() as c FROM security_events GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")
    src_net = ch("SELECT source_type, count() as c FROM network_events GROUP BY source_type ORDER BY c DESC FORMAT TabSeparated")

    data_loss = max(0, total - ch_total) / total * 100 if total > 0 else 0

    # Grade
    if e2e_eps >= 200000 and data_loss < 0.1:
        grade = "A+"
    elif e2e_eps >= 100000 and data_loss < 1:
        grade = "A"
    elif e2e_eps >= 50000 and data_loss < 2:
        grade = "B+"
    elif e2e_eps >= 30000 and data_loss < 5:
        grade = "B"
    elif e2e_eps >= 10000 and data_loss < 10:
        grade = "C"
    else:
        grade = "D"

    print(f"""
  Data Source:        100% REAL logs (16 datasets, 11 source types)
  Events Sent:        {sent_count:>12,}
  Send Time:          {send_elapsed:>12.1f}s
  Send EPS:           {send_eps:>12,.0f}
  Total Time:         {total_elapsed:>12.1f}s
  E2E EPS:            {e2e_eps:>12,.0f}
  
  ClickHouse Ingested:
    raw_logs:         {raw:>12,}
    security_events:  {sec:>12,}
    network_events:   {net:>12,}
    process_events:   {proc:>12,}
    TOTAL:            {ch_total:>12,}
    dead_letter:      {dead:>12,}
  
  Data Loss:          {data_loss:>11.2f}%
  
  AI Pipeline:
    Triage Scored:    {triage:>12,}
    - Suspicious:     {suspicious:>12,}
    - Anomalous:      {anomalous:>12,}
    Hunter Investig:  {hunter:>12,}
    Verifier Results: {verifier:>12,}
  
  GRADE:              {grade}
""")

    # Source type breakdown
    print("  ClickHouse Source Types:")
    print("  raw_logs:")
    for line in (src_types or "").strip().split("\n"):
        if line.strip():
            print(f"    {line}")
    print("  security_events:")
    for line in (src_sec or "").strip().split("\n"):
        if line.strip():
            print(f"    {line}")
    print("  network_events:")
    for line in (src_net or "").strip().split("\n"):
        if line.strip():
            print(f"    {line}")

    print(f"\n{'='*70}")
    print(f"  Benchmark completed at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
