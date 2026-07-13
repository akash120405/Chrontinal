#!/usr/bin/env python3
"""
Chrontinal Benchmark Service — HTTP trigger for 2M log benchmark.
Runs on the VM, allows remote clients to start/monitor/view benchmark results.

Endpoints:
  GET  /health          → service status
  POST /start           → start benchmark (optional: ?workers=8)
  GET  /status          → live progress
  GET  /results         → final results (after completion)
  POST /reset           → clear ClickHouse tables for fresh run

Runs on port 5050, proxied via nginx at /benchmark/
"""
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

PORT = 5050
VECTOR_HOST = "127.0.0.1"
VECTOR_PORT = 9514
BENCHMARK_FILE = "/opt/clif/real_2m_payload.ndjson"
CH_URL = "http://localhost:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!&database=clif_logs"

# ── Shared state ──────────────────────────────────────────────────────
state = {
    "running": False,
    "phase": "idle",
    "sent": 0,
    "errors": 0,
    "total_lines": 0,
    "start_time": 0,
    "send_elapsed": 0,
    "workers": 8,
    "ch_counts": {},
    "triage_counts": {},
    "results": None,
    "error_msg": None,
}
lock = threading.Lock()


def ch(query, timeout=10):
    try:
        req = urllib.request.Request(CH_URL, data=query.encode())
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.read().decode().strip()
    except Exception as e:
        return ""


def ch_int(query, timeout=10):
    v = ch(query, timeout)
    try:
        return int(v)
    except:
        return 0


def get_ch_counts():
    raw = ch_int("SELECT count() FROM raw_logs", 5)
    sec = ch_int("SELECT count() FROM security_events", 5)
    net = ch_int("SELECT count() FROM network_events", 5)
    proc = ch_int("SELECT count() FROM process_events", 5)
    triage = ch_int("SELECT count() FROM triage_scores", 5)
    hunter = ch_int("SELECT count() FROM hunter_investigations", 5)
    verifier = ch_int("SELECT count() FROM verifier_results", 5)
    suspicious = ch_int("SELECT count() FROM triage_scores WHERE action = 'monitor'", 5)
    anomalous = ch_int("SELECT count() FROM triage_scores WHERE action = 'escalate'", 5)
    dead = ch_int("SELECT count() FROM dead_letter_events", 5)
    return {
        "raw_logs": raw,
        "security_events": sec,
        "network_events": net,
        "process_events": proc,
        "total_ingested": raw + sec + net + proc,
        "triage_scored": triage,
        "suspicious": suspicious,
        "anomalous": anomalous,
        "hunter_investigations": hunter,
        "verifier_results": verifier,
        "dead_letter": dead,
    }


# ── TCP send worker ──────────────────────────────────────────────────
def send_worker(worker_id, lines):
    global state
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((VECTOR_HOST, VECTOR_PORT))
    except Exception as e:
        with lock:
            state["errors"] += len(lines)
        return

    batch = []
    chunk_size = 500
    for line in lines:
        batch.append(line)
        if len(batch) >= chunk_size:
            try:
                sock.sendall("".join(batch).encode())
                with lock:
                    state["sent"] += len(batch)
            except:
                with lock:
                    state["errors"] += len(batch)
            batch = []
    if batch:
        try:
            sock.sendall("".join(batch).encode())
            with lock:
                state["sent"] += len(batch)
        except:
            with lock:
                state["errors"] += len(batch)
    sock.close()


# ── Benchmark runner ─────────────────────────────────────────────────
def run_benchmark(workers):
    global state
    with lock:
        state["running"] = True
        state["phase"] = "loading"
        state["sent"] = 0
        state["errors"] = 0
        state["results"] = None
        state["error_msg"] = None
        state["workers"] = workers

    try:
        # Load file
        if not os.path.exists(BENCHMARK_FILE):
            with lock:
                state["running"] = False
                state["phase"] = "error"
                state["error_msg"] = f"Payload file not found: {BENCHMARK_FILE}"
            return

        with open(BENCHMARK_FILE, "r") as f:
            lines = f.readlines()

        with lock:
            state["total_lines"] = len(lines)
            state["phase"] = "sending"
            state["start_time"] = time.time()

        # Split among workers
        chunk_size = len(lines) // workers
        chunks = []
        for i in range(workers):
            start = i * chunk_size
            end = start + chunk_size if i < workers - 1 else len(lines)
            chunks.append(lines[start:end])

        # Start workers
        threads = []
        for i, chunk in enumerate(chunks):
            t = threading.Thread(target=send_worker, args=(i, chunk))
            t.start()
            threads.append(t)

        # Wait for all workers
        for t in threads:
            t.join()

        with lock:
            state["send_elapsed"] = time.time() - state["start_time"]
            state["phase"] = "processing"

        # Wait for pipeline to stabilize (5 min max)
        prev_total = 0
        stable = 0
        for _ in range(60):
            time.sleep(5)
            counts = get_ch_counts()
            with lock:
                state["ch_counts"] = counts
            if counts["total_ingested"] == prev_total and counts["total_ingested"] > 0:
                stable += 1
            else:
                stable = 0
            prev_total = counts["total_ingested"]
            if stable >= 2:
                break

        # Final results
        total_elapsed = time.time() - state["start_time"]
        final = get_ch_counts()
        data_loss = max(0, state["total_lines"] - final["total_ingested"]) / max(state["total_lines"], 1) * 100
        e2e_eps = final["total_ingested"] / max(total_elapsed, 1)
        send_eps = state["sent"] / max(state["send_elapsed"], 1)

        # Grade (based on send_eps = actual pipeline throughput)
        if send_eps >= 200000 and data_loss < 0.1:
            grade = "A+"
        elif send_eps >= 100000 and data_loss < 1:
            grade = "A"
        elif send_eps >= 50000 and data_loss < 2:
            grade = "B+"
        elif send_eps >= 30000 and data_loss < 5:
            grade = "B"
        elif send_eps >= 10000 and data_loss < 10:
            grade = "C"
        else:
            grade = "D"

        # Source type breakdown
        src_raw = ch("SELECT source_type, count() as c FROM raw_logs GROUP BY source_type ORDER BY c DESC FORMAT JSON", 10)
        src_sec = ch("SELECT source_type, count() as c FROM security_events GROUP BY source_type ORDER BY c DESC FORMAT JSON", 10)

        results = {
            "events_sent": state["sent"],
            "send_errors": state["errors"],
            "send_time_sec": round(state["send_elapsed"], 1),
            "send_eps": round(send_eps),
            "total_time_sec": round(total_elapsed, 1),
            "e2e_eps": round(e2e_eps),
            "workers": workers,
            "clickhouse": final,
            "data_loss_pct": round(data_loss, 2),
            "grade": grade,
            "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        with lock:
            state["results"] = results
            state["phase"] = "done"
            state["running"] = False

    except Exception as e:
        with lock:
            state["running"] = False
            state["phase"] = "error"
            state["error_msg"] = str(e)


# ── HTTP Handler ─────────────────────────────────────────────────────
class BenchmarkHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logs

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        if path == "/health" or path == "":
            self.send_json({"service": "benchmark", "status": "ok"})

        elif path == "/status":
            elapsed = time.time() - state["start_time"] if state["start_time"] > 0 and state["running"] else 0
            counts = get_ch_counts() if state["running"] else state.get("ch_counts", {})
            pct = (state["sent"] / max(state["total_lines"], 1)) * 100 if state["total_lines"] > 0 else 0
            self.send_json({
                "phase": state["phase"],
                "running": state["running"],
                "sent": state["sent"],
                "total": state["total_lines"],
                "progress_pct": round(pct, 1),
                "errors": state["errors"],
                "elapsed_sec": round(elapsed, 1),
                "eps": round(state["sent"] / max(elapsed, 1)) if elapsed > 0 else 0,
                "clickhouse": counts,
                "workers": state["workers"],
            })

        elif path == "/results":
            if state["results"]:
                self.send_json(state["results"])
            elif state["phase"] == "error":
                self.send_json({"error": state["error_msg"]}, 500)
            else:
                self.send_json({"error": "No results yet", "phase": state["phase"]}, 404)

        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")

        if path == "/start":
            if state["running"]:
                self.send_json({"error": "Benchmark already running", "phase": state["phase"]}, 409)
                return

            # Parse workers param
            workers = 8
            if "?" in self.path:
                for param in self.path.split("?")[1].split("&"):
                    if param.startswith("workers="):
                        try:
                            workers = int(param.split("=")[1])
                            workers = max(1, min(workers, 16))
                        except:
                            pass

            t = threading.Thread(target=run_benchmark, args=(workers,), daemon=True)
            t.start()
            self.send_json({"status": "started", "workers": workers})

        elif path == "/reset":
            if state["running"]:
                self.send_json({"error": "Cannot reset while benchmark is running"}, 409)
                return

            tables = ["raw_logs", "security_events", "network_events", "process_events",
                       "triage_scores", "hunter_investigations", "verifier_results", "dead_letter_events"]
            for t in tables:
                ch(f"TRUNCATE TABLE IF EXISTS {t}")

            with lock:
                state["phase"] = "idle"
                state["sent"] = 0
                state["errors"] = 0
                state["total_lines"] = 0
                state["start_time"] = 0
                state["ch_counts"] = {}
                state["results"] = None
                state["error_msg"] = None

            self.send_json({"status": "reset", "tables_cleared": tables})

        else:
            self.send_json({"error": "Not found"}, 404)


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), BenchmarkHandler)
    print(f"Benchmark service listening on :{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
