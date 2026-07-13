#!/usr/bin/env python3
"""
CLIF 50k Normal/Benign Pipeline Test — Zero Bias
==================================================
Sends 50k purely benign events via TCP JSON to Vector port 9514.
All events are realistic, normal operational logs with NO attack patterns.

Design:
  - Only INFO/DEBUG severity (severity_numeric 0-1)
  - No failed auth, no sudo, no privilege escalation
  - Standard binaries only (no /tmp, /dev/shm)
  - Normal DNS domains (.com, .org, .net)
  - Standard HTTP GETs to well-known paths
  - No SQL injection, XSS, path traversal in messages
  - Normal network: HTTPS/HTTP/DNS on standard ports
  - No suspicious IPs or keywords

Usage:
  python scripts/test_50k_normal.py
  python scripts/test_50k_normal.py --count 50000
"""

import argparse
import json
import random
import socket
import time

VECTOR_HOST = "localhost"
VECTOR_PORT = 9514
BATCH_SIZE = 500

# ── Benign hostnames ─────────────────────────────────────────────────────

HOSTNAMES = [
    "web-srv-01", "web-srv-02", "web-srv-03",
    "app-srv-01", "app-srv-02", "app-srv-03",
    "db-primary", "db-replica-01", "cache-01",
    "worker-01", "worker-02", "worker-03",
    "proxy-01", "scheduler-01", "monitor-01",
    "k8s-node-01", "k8s-node-02", "ci-runner-01",
]

# Only internal, well-known IPs
INTERNAL_IPS = [
    "10.0.1.{}".format(i) for i in range(1, 30)
] + [
    "192.168.1.{}".format(i) for i in range(1, 20)
]

# Benign DNS domains only (.com, .org, .net — low TLD risk)
BENIGN_DOMAINS = [
    "api.example.com", "cdn.example.com", "static.example.com",
    "updates.microsoft.com", "github.com", "pypi.org",
    "registry.npmjs.org", "fonts.googleapis.com",
    "docs.example.com", "internal.corp.net",
    "metrics.monitor.local", "logs.internal.corp.net",
    "storage.googleapis.com", "packages.debian.org",
    "mirror.centos.org", "archive.ubuntu.com",
]

NORMAL_USERS = ["deploy", "appuser", "www-data", "nginx", "node"]

# ── RAW LOG (45%) — pure operational, benign messages ────────────────────

RAW_MESSAGES = [
    "Application startup complete in {ms}ms",
    "Health check passed: all dependencies OK",
    "Configuration reloaded successfully",
    "Request processed in {ms}ms: GET /api/v1/health",
    "Request processed in {ms}ms: GET /api/v1/status",
    "Request processed in {ms}ms: GET /api/v1/metrics",
    "Request processed in {ms}ms: GET /api/v1/version",
    "Cache hit ratio: {pct}% over last 60s",
    "Connection pool stats: active={active} idle={idle}",
    "Batch job finished: processed {count} records in {ms}ms",
    "Scheduled cleanup completed: {count} stale entries removed",
    "Log rotation completed: {count} files archived successfully",
    "Service registered with discovery: {svc}",
    "Database connection pool refreshed: {active} connections active",
    "Memory utilization: {pct}% ({used}MB / {total}MB) — normal",
    "Disk usage: {pct}% on /data — within threshold",
    "CPU load average: {load} — nominal",
    "Heartbeat sent to cluster coordinator",
    "TLS certificate valid: {domain} expires in {days} days",
    "Backup completed: {count} tables, {size}MB compressed",
    "Index rebuild completed in {ms}ms",
    "Queue depth: {count} messages pending — within limits",
    "Worker thread pool: {active} active, {idle} idle",
    "Upstream health: all {count} backends responding",
    "Rate limiter stats: {count} requests allowed, 0 throttled",
    "Session cleanup: {count} expired sessions purged",
    "DNS resolution cache: {count} entries, {pct}% hit rate",
    "Prometheus scrape completed in {ms}ms",
    "Grafana dashboard rendered in {ms}ms",
    "Alert evaluation completed: 0 new alerts",
]

def make_raw_event(ts):
    tmpl = random.choice(RAW_MESSAGES)
    msg = tmpl.format(
        ms=random.randint(1, 500),
        pct=round(random.uniform(10, 70), 1),
        active=random.randint(1, 20),
        idle=random.randint(0, 10),
        count=random.randint(1, 500),
        svc=random.choice(["web", "api", "worker", "cache"]),
        domain=random.choice(BENIGN_DOMAINS[:4]),
        days=random.randint(30, 365),
        used=random.randint(100, 4000),
        total=random.choice([8192, 16384]),
        load=round(random.uniform(0.1, 2.0), 2),
        size=random.randint(10, 500),
    )
    return {
        "timestamp": ts,
        "message": msg,
        "source": random.choice(["myapp", "nginx", "redis", "systemd", "cron"]),
        "level": random.choice(["INFO", "INFO", "INFO", "INFO", "DEBUG"]),
        "hostname": random.choice(HOSTNAMES),
    }

# ── SECURITY EVENT (20%) — benign only: successful logins, sessions ──────

BENIGN_SECURITY = [
    "Accepted publickey for {user} from {ip} port {port} ssh2",
    "session opened for user {user} by (uid=1000)",
    "session closed for user {user}",
    "pam_unix(sshd:session): session opened for user {user}",
    "pam_unix(cron:session): session opened for user {user}",
    "pam_unix(cron:session): session closed for user {user}",
    "New session {sid} of user {user}",
    "Removed session {sid}",
    "User {user} logged in from {ip}",
    "TLS handshake completed with {ip} using TLS 1.3",
    "Certificate verification passed for {ip}",
    "Authorized connection from {ip} to port {port}",
    "User {user} session refreshed, idle timeout reset",
    "SSH key rotation completed for user {user}",
    "Authentication succeeded for {user} via kerberos",
]

def make_security_event(ts):
    tmpl = random.choice(BENIGN_SECURITY)
    ip = random.choice(INTERNAL_IPS)
    msg = tmpl.format(
        user=random.choice(NORMAL_USERS),
        ip=ip,
        port=random.randint(49152, 65535),
        sid=random.randint(1, 999),
    )
    return {
        "timestamp": ts,
        "message": msg,
        "source": random.choice(["sshd", "pam", "systemd-logind"]),
        "level": "INFO",
        "hostname": random.choice(HOSTNAMES),
        "ip_address": ip,
        "user_id": random.choice(NORMAL_USERS),
    }

# ── PROCESS EVENT (15%) — normal system binaries ────────────────────────

NORMAL_BINARIES = [
    "/usr/bin/python3", "/usr/bin/bash", "/usr/sbin/cron",
    "/usr/sbin/nginx", "/usr/bin/node", "/usr/bin/java",
    "/usr/bin/git", "/usr/bin/systemctl", "/usr/bin/journalctl",
    "/usr/sbin/sshd", "/usr/bin/docker", "/usr/bin/redis-server",
    "/usr/bin/postgres", "/usr/bin/mongod", "/usr/bin/prometheus",
    "/usr/bin/grafana-server", "/usr/bin/containerd",
]

def make_process_event(ts):
    binary = random.choice(NORMAL_BINARIES)
    pid = random.randint(1000, 32000)
    return {
        "timestamp": ts,
        "message": random.choice(["Process started", "Process exited normally"]),
        "pid": pid,
        "ppid": random.randint(1, pid),
        "uid": random.choice([1000, 1001, 33, 65534]),  # non-root UIDs
        "binary_path": binary,
        "hostname": random.choice(HOSTNAMES),
        "source": "tetragon",
        "exit_code": 0,  # always clean exit
    }

# ── NETWORK EVENT (20%) — standard ports, internal traffic ───────────────

def make_network_event(ts):
    dst_port = random.choice([80, 443, 443, 443, 53, 8080, 8443, 9090, 3000])
    src_ip = random.choice(INTERNAL_IPS)
    dst_ip = random.choice(INTERNAL_IPS)
    return {
        "timestamp": ts,
        "message": random.choice([
            "TCP connection established",
            "Connection closed",
            "TLS handshake complete",
            "DNS query resolved",
        ]),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": dst_port,
        "protocol": "TCP",
        "hostname": random.choice(HOSTNAMES),
        "source": "netflow",
        "bytes_sent": random.randint(100, 50000),
        "bytes_recv": random.randint(100, 100000),
        "dns_query": random.choice(BENIGN_DOMAINS) if dst_port == 53 else None,
    }

# Event generators weighted by type
GENERATORS = [
    (make_raw_event, 0.45),
    (make_security_event, 0.20),
    (make_process_event, 0.15),
    (make_network_event, 0.20),
]

def generate_batch(batch_size):
    events = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    for _ in range(batch_size):
        r = random.random()
        cumulative = 0
        for gen_fn, weight in GENERATORS:
            cumulative += weight
            if r <= cumulative:
                evt = gen_fn(ts)
                evt = {k: v for k, v in evt.items() if v is not None}
                events.append(evt)
                break
    return events


def send_batch_tcp(sock, events):
    payload = b""
    for evt in events:
        payload += json.dumps(evt).encode("utf-8") + b"\n"
    sock.sendall(payload)


def main():
    parser = argparse.ArgumentParser(description="CLIF 50k Normal/Benign Pipeline Test")
    parser.add_argument("--count", type=int, default=50_000)
    parser.add_argument("--batch", type=int, default=500)
    parser.add_argument("--host", type=str, default=VECTOR_HOST)
    parser.add_argument("--port", type=int, default=VECTOR_PORT)
    args = parser.parse_args()

    total = args.count
    batch_size = args.batch

    print(f"\n{'=' * 60}")
    print(f"  CLIF Normal/Benign Test — {total:,} events via TCP NDJSON")
    print(f"{'=' * 60}")
    print(f"  Target:     {args.host}:{args.port}")
    print(f"  Strategy:   100% benign — no attack patterns")
    print(f"  Severity:   INFO/DEBUG only")
    print(f"  Auth:       success only, no failures")
    print(f"  Binaries:   standard /usr paths only")
    print(f"  Network:    internal IPs, standard ports")
    print(f"{'=' * 60}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    try:
        sock.connect((args.host, args.port))
        print(f"  Connected to {args.host}:{args.port}")
    except Exception as e:
        print(f"  ERROR: Cannot connect to Vector: {e}")
        return 1

    sent = 0
    errors = 0
    t_start = time.monotonic()
    last_report = t_start

    try:
        while sent < total:
            remaining = total - sent
            current_batch = min(batch_size, remaining)
            events = generate_batch(current_batch)
            try:
                send_batch_tcp(sock, events)
                sent += current_batch
            except Exception as e:
                errors += 1
                print(f"  Send error: {e}")
                try:
                    sock.close()
                except Exception:
                    pass
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.connect((args.host, args.port))
                continue

            now = time.monotonic()
            if now - last_report >= 2.0:
                elapsed = now - t_start
                eps = sent / elapsed if elapsed > 0 else 0
                pct = (sent / total) * 100
                print(f"  [{pct:5.1f}%] {sent:>8,} / {total:,}  |  {eps:,.0f} EPS  |  errors: {errors}")
                last_report = now

    except KeyboardInterrupt:
        print("\n  Interrupted!")
    finally:
        sock.close()

    elapsed = time.monotonic() - t_start
    avg_eps = sent / elapsed if elapsed > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    print(f"  Events sent:  {sent:>12,}")
    print(f"  Errors:       {errors:>12}")
    print(f"  Duration:     {elapsed:>12.1f}s")
    print(f"  Avg EPS:      {avg_eps:>12,.0f}")
    print(f"{'=' * 60}")
    print(f"\n  Expected distribution:")
    print(f"    Raw logs:      ~{int(sent * 0.45):,} (45%)")
    print(f"    Security:      ~{int(sent * 0.20):,} (20%)")
    print(f"    Process:       ~{int(sent * 0.15):,} (15%)")
    print(f"    Network:       ~{int(sent * 0.20):,} (20%)")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
