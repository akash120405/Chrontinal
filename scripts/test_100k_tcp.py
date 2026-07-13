#!/usr/bin/env python3
"""
CLIF 100k Pipeline Test — TCP NDJSON to Vector port 9514
=========================================================
Sends ~100k diverse events via TCP JSON socket (newline-delimited JSON).
Covers all 4 event types: raw, security, process, network.

Usage:
  python scripts/test_100k_tcp.py                     # 100k events
  python scripts/test_100k_tcp.py --count 50000       # custom count
  python scripts/test_100k_tcp.py --host 10.52.166.221  # remote Vector
"""

import argparse
import json
import random
import socket
import time
import uuid

VECTOR_HOST = "localhost"
VECTOR_PORT = 9514
BATCH_SIZE = 500  # events per TCP send

# ── Realistic event templates across all 4 types ─────────────────────────

HOSTNAMES = [
    "web-srv-01", "web-srv-02", "app-srv-01", "app-srv-02", "app-srv-03",
    "db-primary", "db-replica-01", "cache-01", "cache-02",
    "bastion-01", "jump-srv-01", "worker-01", "worker-02", "worker-03",
    "proxy-01", "proxy-02", "scheduler-01", "monitor-01",
    "k8s-node-01", "k8s-node-02", "k8s-master", "ci-runner-01",
    "mail-srv-01", "dns-01", "nfs-01", "vpn-gw-01",
]

USERS = [
    "deploy", "admin", "root", "jsmith", "agarcia", "mchen",
    "svc-backup", "svc-monitor", "svc-ci", "nobody", "www-data",
]

IPS = [
    "10.0.1.{}".format(i) for i in range(1, 50)
] + [
    "192.168.1.{}".format(i) for i in range(1, 30)
] + [
    "172.16.0.{}".format(i) for i in range(1, 20)
] + [
    # External / suspicious IPs
    "45.33.32.156", "185.220.101.1", "91.92.109.87", "23.129.64.100",
    "198.51.100.10", "203.0.113.50", "104.248.50.87",
]

DNS_QUERIES = [
    "api.example.com", "cdn.example.com", "auth.internal.corp",
    "updates.microsoft.com", "github.com", "pypi.org",
    "malware-c2.evil.com", "exfil.bad-domain.xyz",
    "legit-service.cloud.internal", "metrics.grafana.local",
]

# ── RAW LOG templates (~40% of traffic) ──────────────────────────────────
RAW_TEMPLATES = [
    "Application startup complete in {ms}ms",
    "Cache miss ratio: {pct}% over last 60s",
    "Garbage collection paused {ms}ms",
    "Configuration reloaded successfully",
    "Scheduled task completed: {task}",
    "Health check passed: all dependencies OK",
    "Connection pool stats: active={active} idle={idle} max={maxc}",
    "Request processed in {ms}ms: GET /api/v1/{endpoint}",
    "Batch job finished: processed {count} records",
    "Certificate renewal: {domain} valid for {days} more days",
    "Disk usage: {pct}% on /var/log",
    "Memory utilization: {pct}% ({used}MB / {total}MB)",
    "Cron job executed: /etc/cron.daily/{task}",
    "Service {svc} registered with consul",
    "Log rotation completed: {count} files archived",
]

# ── SECURITY EVENT templates (~25% of traffic) ──────────────────────────
SECURITY_TEMPLATES = [
    {"msg": "Failed password for {user} from {ip} port {port} ssh2", "sev": "WARNING",
     "log_type": "syslog", "status": "fail", "auth_type": "password"},
    {"msg": "Accepted publickey for {user} from {ip} port {port} ssh2", "sev": "INFO",
     "log_type": "syslog", "status": "success", "auth_type": "password"},
    {"msg": "Invalid user {user} from {ip} port {port}", "sev": "WARNING",
     "log_type": "syslog", "status": "fail", "auth_type": "password"},
    {"msg": "pam_unix(sshd:auth): authentication failure; logname= uid=0 user={user} rhost={ip}", "sev": "WARNING",
     "log_type": "syslog", "status": "fail", "auth_type": "password"},
    {"msg": "session opened for user {user} by (uid=0)", "sev": "INFO",
     "log_type": "syslog", "status": "success"},
    {"msg": "session closed for user {user}", "sev": "INFO",
     "log_type": "syslog", "status": "success"},
    {"msg": "Firewall DENY: SRC={ip} DST={dst_ip} PROTO=TCP DPT={port}", "sev": "WARNING",
     "log_type": "firewall", "status": "deny"},
    {"msg": "Firewall ALLOW: SRC={ip} DST={dst_ip} PROTO=TCP DPT={port}", "sev": "INFO",
     "log_type": "firewall", "status": "allow"},
    {"msg": "sudo: {user} : TTY=pts/0 ; PWD=/root ; COMMAND=/bin/{cmd}", "sev": "WARNING",
     "log_type": "syslog"},
    {"msg": "Multiple failed login attempts detected from {ip}: {count} attempts in 60s", "sev": "CRITICAL",
     "log_type": "syslog", "status": "fail", "auth_type": "password"},
    {"msg": "New SSH key added for user {user} from {ip}", "sev": "WARNING",
     "log_type": "syslog"},
    {"msg": "Account locked after {count} failed attempts: {user}", "sev": "ERROR",
     "log_type": "syslog", "status": "fail", "auth_type": "password"},
    {"msg": "Privilege escalation detected: {user} executed {cmd} as root", "sev": "CRITICAL",
     "log_type": "syslog"},
    {"msg": "Anomalous login: user={user} src_ip={ip} geo=unexpected_country", "sev": "ERROR",
     "log_type": "syslog", "status": "success", "auth_type": "password"},
    {"msg": "TLS certificate mismatch on {host}: expected CN={domain}", "sev": "ERROR",
     "log_type": "syslog"},
]

# ── PROCESS EVENT templates (~15% of traffic) ───────────────────────────
PROCESS_BINARIES = [
    "/usr/bin/python3", "/usr/bin/bash", "/usr/sbin/cron", "/usr/bin/curl",
    "/usr/bin/wget", "/usr/bin/ssh", "/usr/sbin/nginx", "/usr/bin/node",
    "/usr/bin/java", "/usr/bin/docker", "/usr/sbin/sshd", "/usr/bin/git",
    "/usr/bin/make", "/usr/bin/grep", "/usr/bin/find", "/usr/bin/cat",
    "/tmp/suspicious_binary", "/dev/shm/.hidden_proc",
]

# ── NETWORK EVENT templates (~20% of traffic) ───────────────────────────
PROTOCOLS = ["TCP", "UDP", "TCP", "TCP", "TCP", "UDP"]  # weighted toward TCP

def make_raw_event(ts):
    tmpl = random.choice(RAW_TEMPLATES)
    msg = tmpl.format(
        ms=random.randint(1, 5000), pct=random.uniform(0.1, 99.9),
        task=random.choice(["backup", "cleanup", "sync", "rotate", "prune"]),
        active=random.randint(1, 50), idle=random.randint(0, 20),
        maxc=random.randint(50, 200), count=random.randint(1, 10000),
        endpoint=random.choice(["users", "events", "metrics", "health", "alerts"]),
        domain=random.choice(["api.example.com", "*.internal.corp"]),
        days=random.randint(1, 365), used=random.randint(100, 16000),
        total=random.choice([8192, 16384, 32768]),
        svc=random.choice(["web", "api", "worker", "cache", "queue"]),
    )
    return {
        "timestamp": ts,
        "message": msg,
        "source": random.choice(["myapp", "nginx", "redis", "jvm", "systemd", "cron"]),
        "level": random.choice(["INFO", "INFO", "INFO", "DEBUG", "WARNING"]),
        "hostname": random.choice(HOSTNAMES),
        "log_type": "syslog",
    }

def make_security_event(ts):
    tmpl = random.choice(SECURITY_TEMPLATES)
    ip = random.choice(IPS)
    user = random.choice(USERS)
    msg = tmpl["msg"].format(
        user=user, ip=ip,
        dst_ip=random.choice(IPS), port=random.randint(1024, 65535),
        count=random.randint(3, 50), cmd=random.choice(["bash", "su", "rm", "chmod", "systemctl"]),
        host=random.choice(HOSTNAMES), domain=random.choice(DNS_QUERIES[:6]),
    )
    event = {
        "timestamp": ts,
        "message": msg,
        "source": random.choice(["sshd", "pam", "iptables", "sudo", "auth"]),
        "level": tmpl["sev"],
        "hostname": random.choice(HOSTNAMES),
        "ip_address": ip,
        "user_id": user,
        "log_type": tmpl["log_type"],
    }
    if "status" in tmpl:
        event["status"] = tmpl["status"]
    if "auth_type" in tmpl:
        event["auth_type"] = tmpl["auth_type"]
    return event

def make_process_event(ts):
    binary = random.choice(PROCESS_BINARIES)
    pid = random.randint(100, 65535)
    action = random.choice(["Process started", "Process exited", "Process exec"])
    return {
        "timestamp": ts,
        "message": f"{action}: {binary} (pid={pid})",
        "pid": pid,
        "ppid": random.randint(1, pid),
        "uid": random.choice([0, 1000, 1001, 65534]),
        "binary_path": binary,
        "hostname": random.choice(HOSTNAMES),
        "source": "tetragon",
        "log_type": "syslog",
        "exit_code": random.choice([0, 0, 0, 1, 127, 137]),
    }

def make_network_event(ts):
    proto = random.choice(PROTOCOLS)
    dst_port = random.choice([22, 53, 80, 443, 443, 443, 3306, 5432, 6379, 8080, 8443, 9090])
    return {
        "timestamp": ts,
        "message": random.choice([
            "TCP connection established", "Connection closed",
            "DNS query resolved", "TLS handshake complete",
            "Connection refused", "Connection timeout",
        ]),
        "src_ip": random.choice(IPS),
        "dst_ip": random.choice(IPS),
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": proto,
        "hostname": random.choice(HOSTNAMES),
        "source": "netflow",
        "log_type": "netflow",
        "bytes_sent": random.randint(0, 1000000),
        "bytes_recv": random.randint(0, 5000000),
        "dns_query": random.choice(DNS_QUERIES) if dst_port == 53 else None,
    }

# Event generators weighted by type distribution
GENERATORS = [
    (make_raw_event, 0.40),
    (make_security_event, 0.25),
    (make_process_event, 0.15),
    (make_network_event, 0.20),
]

def generate_batch(batch_size):
    """Generate a batch of diverse events."""
    events = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    for _ in range(batch_size):
        r = random.random()
        cumulative = 0
        for gen_fn, weight in GENERATORS:
            cumulative += weight
            if r <= cumulative:
                evt = gen_fn(ts)
                # Remove None values
                evt = {k: v for k, v in evt.items() if v is not None}
                events.append(evt)
                break
    return events


def send_batch_tcp(sock, events):
    """Send events as NDJSON over TCP."""
    payload = b""
    for evt in events:
        payload += json.dumps(evt).encode("utf-8") + b"\n"
    sock.sendall(payload)


def main():
    parser = argparse.ArgumentParser(description="CLIF 100k TCP Pipeline Test")
    parser.add_argument("--count", type=int, default=100_000, help="Total events to send")
    parser.add_argument("--batch", type=int, default=500, help="Events per TCP send")
    parser.add_argument("--host", type=str, default=VECTOR_HOST, help="Vector host")
    parser.add_argument("--port", type=int, default=VECTOR_PORT, help="Vector TCP JSON port")
    args = parser.parse_args()

    total = args.count
    batch_size = args.batch

    print(f"\n{'=' * 60}")
    print(f"  CLIF Pipeline Test — {total:,} events via TCP NDJSON")
    print(f"{'=' * 60}")
    print(f"  Target:     {args.host}:{args.port}")
    print(f"  Batch size: {batch_size}")
    print(f"  Batches:    {total // batch_size}")
    print(f"{'=' * 60}\n")

    # Connect
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
                # Reconnect
                try:
                    sock.close()
                except Exception:
                    pass
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.connect((args.host, args.port))
                continue

            # Report progress every 2 seconds
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
    print(f"{'=' * 60}\n")

    # Distribution
    print(f"  Expected distribution:")
    print(f"    Raw logs:      ~{int(sent * 0.40):,} (40%)")
    print(f"    Security:      ~{int(sent * 0.25):,} (25%)")
    print(f"    Process:       ~{int(sent * 0.15):,} (15%)")
    print(f"    Network:       ~{int(sent * 0.20):,} (20%)")
    print()
    return 0


if __name__ == "__main__":
    exit(main())
