#!/usr/bin/env python3
"""
CLIF 50k Realistic Benign Pipeline Test
=========================================
Sends 50k benign events that closely match the training data distributions.
Events include proper field populations matching what the feature extractor expects.

Key differences from test_50k_normal.py:
  - Network events: realistic byte counts, durations, packet-like distributions
  - Security events: include auth_type, status=success, proper EventIDs
  - Process events: include proper PIDs, UIDs, binary paths
  - Raw events: include proper source_type, structured messages
  - All events include fields that the feature extractor uses for log_type detection

Training data reference:
  - Syslog/LANL: auth events with auth_type, status, src/dst users
  - Syslog/SSH: accepted/session events with source_ip, username
  - Firewall: network flows with bytes, packets, duration, ports, protocol
  - NetFlow: similar to firewall with flow-level fields
  - Windows: EventIDs, logon types, authentication packages
  - AD: Active Directory auth with kerberos/ntlm
  - Cloud: CloudTrail-style API calls
  - DNS: domain lookups with query names

Usage:
  python scripts/test_50k_realistic.py
  python scripts/test_50k_realistic.py --count 50000
"""

import argparse
import json
import random
import socket
import time
import math

VECTOR_HOST = "localhost"
VECTOR_PORT = 9514
BATCH_SIZE = 500

# ── Hostnames (different from previous tests) ───────────────────────────

HOSTNAMES = [
    "dc-prod-01", "dc-prod-02", "exchange-01",
    "sql-prod-01", "sql-prod-02", "iis-web-01", "iis-web-02",
    "file-srv-01", "file-srv-02", "print-srv-01",
    "vpn-gw-01", "radius-01", "ad-fs-01",
    "sccm-srv-01", "wsus-srv-01", "backup-exec-01",
    "citrix-xd-01", "hyperv-host-01", "hyperv-host-02",
    "linux-jump-01", "linux-app-01", "linux-db-01",
]

INTERNAL_IPS = (
    [f"10.10.{s}.{h}" for s in range(1, 6) for h in range(1, 20)]
    + [f"172.16.{s}.{h}" for s in range(1, 4) for h in range(1, 15)]
)

DOMAIN_USERS = [
    "jsmith", "mwilliams", "kbrown", "ljones", "dgarcia",
    "rmartin", "slee", "cthompson", "awhite", "bharris",
    "svc_backup", "svc_sql", "svc_exchange", "svc_sccm",
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
]

# Standard benign domains
BENIGN_DOMAINS = [
    "windowsupdate.microsoft.com", "ctldl.windowsupdate.com",
    "login.microsoftonline.com", "graph.microsoft.com",
    "time.windows.com", "wpad.corp.local", "dc-prod-01.corp.local",
    "dc-prod-02.corp.local", "exchange-01.corp.local",
    "autodiscover.corp.local", "crl.microsoft.com",
    "ocsp.digicert.com", "download.windowsupdate.com",
    "settings-win.data.microsoft.com",
]

# Common benign AWS API calls
BENIGN_AWS_EVENTS = [
    ("DescribeInstances", "ec2.amazonaws.com", True),
    ("DescribeSecurityGroups", "ec2.amazonaws.com", True),
    ("GetCallerIdentity", "sts.amazonaws.com", True),
    ("ListBuckets", "s3.amazonaws.com", True),
    ("GetObject", "s3.amazonaws.com", True),
    ("ListRoles", "iam.amazonaws.com", True),
    ("DescribeRegions", "ec2.amazonaws.com", True),
    ("DescribeAvailabilityZones", "ec2.amazonaws.com", True),
    ("DescribeVpcs", "ec2.amazonaws.com", True),
    ("DescribeSubnets", "ec2.amazonaws.com", True),
]


# ═══════════════════════════════════════════════════════════════════════════
# EVENT GENERATORS — match training data field populations
# ═══════════════════════════════════════════════════════════════════════════

def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


# ── 1. NETWORK EVENTS (25%) — benign flows matching firewall/netflow training
def make_network_flow(ts):
    """Benign network flow — matches 03_Firewall and 09_NetFlow training data."""
    proto = random.choice(["TCP", "TCP", "TCP", "UDP", "UDP"])
    if proto == "TCP":
        dst_port = random.choice([80, 443, 443, 443, 445, 389, 636, 3389, 8080, 8443, 1433, 3306, 5432, 25, 587, 993, 143])
    else:
        dst_port = random.choice([53, 53, 123, 161, 514, 5353, 67, 68])

    # Benign byte distributions — match training: moderate volumes, balanced ratios
    if dst_port in (80, 443, 8080, 8443):
        # Web browsing: small request, larger response
        bytes_sent = random.randint(200, 5000)
        bytes_received = random.randint(1000, 500000)
        duration_ms = random.randint(50, 30000)
    elif dst_port in (445, 389, 636):
        # SMB/LDAP: moderate both directions
        bytes_sent = random.randint(500, 20000)
        bytes_received = random.randint(500, 50000)
        duration_ms = random.randint(10, 5000)
    elif dst_port == 53:
        # DNS: small request, small response
        bytes_sent = random.randint(40, 200)
        bytes_received = random.randint(60, 500)
        duration_ms = random.randint(1, 100)
    elif dst_port in (3389,):
        # RDP: sustained moderate traffic
        bytes_sent = random.randint(5000, 100000)
        bytes_received = random.randint(10000, 500000)
        duration_ms = random.randint(60000, 3600000)
    else:
        bytes_sent = random.randint(100, 10000)
        bytes_received = random.randint(100, 10000)
        duration_ms = random.randint(10, 10000)

    src_ip = random.choice(INTERNAL_IPS)
    dst_ip = random.choice(INTERNAL_IPS)

    return {
        "timestamp": ts,
        "hostname": random.choice(HOSTNAMES),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": dst_port,
        "protocol": proto,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "duration_ms": duration_ms,
        "direction": "outbound",
        "source_type": "netflow",
        "level": "info",
        "message": f"{proto} {src_ip}:{random.randint(49152,65535)} -> {dst_ip}:{dst_port} {bytes_sent}B/{bytes_received}B {duration_ms}ms",
    }


# ── 2. SECURITY EVENTS — Windows auth (25%) — matches 02_Windows training
def make_windows_auth(ts):
    """Benign Windows auth events — matches 02_Windows and 04_AD training data."""
    event_type = random.choices(
        ["logon_success", "logon_session", "kerberos_tgt", "kerberos_tgs",
         "logoff", "special_logon", "group_membership"],
        weights=[30, 15, 15, 10, 15, 10, 5],
    )[0]

    user = random.choice(DOMAIN_USERS[:10])
    src_ip = random.choice(INTERNAL_IPS[:20])
    hostname = random.choice(HOSTNAMES)

    if event_type == "logon_success":
        # Windows Event 4624 — successful logon
        logon_type = random.choice([2, 3, 3, 3, 10])  # interactive, network, rdp
        auth_pkg = random.choice(["Kerberos", "NTLM", "Negotiate"])
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"An account was successfully logged on. Subject: {user} Logon Type: {logon_type} Auth Package: {auth_pkg}",
            "EventID": 4624,
            "windows_event_id": 4624,
            "windows_logon_type": logon_type,
            "AuthenticationPackageName": auth_pkg,
            "user": user,
            "status": "Success",
            "source_type": "windows_event",
            "level": "info",
            "ip_address": src_ip,
            "severity": 1,
        }
    elif event_type == "logon_session":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"A logon session was created. Subject: {user}",
            "EventID": 4648,
            "windows_event_id": 4648,
            "user": user,
            "status": "Success",
            "source_type": "windows_event",
            "level": "info",
            "ip_address": src_ip,
            "severity": 1,
        }
    elif event_type == "kerberos_tgt":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"A Kerberos authentication ticket (TGT) was requested. Account: {user}",
            "EventID": 4768,
            "windows_event_id": 4768,
            "AuthenticationPackageName": "Kerberos",
            "auth_type": "kerberos",
            "user": user,
            "status": "0x0",  # success
            "source_type": "windows_event",
            "level": "info",
            "ip_address": src_ip,
            "severity": 1,
        }
    elif event_type == "kerberos_tgs":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"A Kerberos service ticket was requested. Account: {user} Service: krbtgt/CORP.LOCAL",
            "EventID": 4769,
            "windows_event_id": 4769,
            "AuthenticationPackageName": "Kerberos",
            "auth_type": "kerberos",
            "user": user,
            "status": "0x0",
            "source_type": "windows_event",
            "level": "info",
            "ip_address": src_ip,
            "severity": 1,
        }
    elif event_type == "logoff":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"An account was logged off. Subject: {user}",
            "EventID": 4634,
            "windows_event_id": 4634,
            "user": user,
            "status": "Success",
            "source_type": "windows_event",
            "level": "info",
            "severity": 0,
        }
    elif event_type == "special_logon":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"Special privileges assigned to new logon. Subject: {user}",
            "EventID": 4672,
            "windows_event_id": 4672,
            "user": user,
            "status": "Success",
            "source_type": "windows_event",
            "level": "info",
            "ip_address": src_ip,
            "severity": 1,
        }
    else:
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"A member was added to a security-enabled local group. Subject: SYSTEM Group: Users Member: {user}",
            "EventID": 4732,
            "windows_event_id": 4732,
            "user": "SYSTEM",
            "status": "Success",
            "source_type": "windows_event",
            "level": "info",
            "severity": 1,
        }


# ── 3. SYSLOG/AUTH EVENTS (20%) — matches 01_Syslog/LANL and SSH training
def make_syslog_auth(ts):
    """Benign syslog auth events — matches LANL auth_syslog and SSH training."""
    event_type = random.choices(
        ["ssh_accept", "session_open", "session_close", "cron_session",
         "lanl_auth_success", "pam_session"],
        weights=[25, 20, 20, 10, 15, 10],
    )[0]

    user = random.choice(DOMAIN_USERS[:10])
    src_ip = random.choice(INTERNAL_IPS[:20])
    hostname = random.choice(HOSTNAMES[-3:])  # linux hosts

    if event_type == "ssh_accept":
        auth = random.choice(["publickey", "password"])
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"Accepted {auth} for {user} from {src_ip} port {random.randint(49152,65535)} ssh2",
            "source": "sshd",
            "source_type": "syslog",
            "level": "info",
            "auth_type": "password",
            "status": "success",
            "user": user,
            "ip_address": src_ip,
        }
    elif event_type == "session_open":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
            "source": "sshd",
            "source_type": "syslog",
            "level": "info",
            "status": "success",
            "user": user,
        }
    elif event_type == "session_close":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"pam_unix(sshd:session): session closed for user {user}",
            "source": "sshd",
            "source_type": "syslog",
            "level": "info",
            "status": "success",
            "user": user,
        }
    elif event_type == "cron_session":
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"pam_unix(cron:session): session opened for user {random.choice(['root', user])} by (uid=0)",
            "source": "cron",
            "source_type": "syslog",
            "level": "info",
            "status": "success",
        }
    elif event_type == "lanl_auth_success":
        # LANL-style: src_user → dst_user with auth_type
        dst_user = random.choice(DOMAIN_USERS[:10])
        auth = random.choice(["kerberos", "ntlm", "negotiate"])
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"auth {auth} logon success {user} -> {dst_user}",
            "source": "auth",
            "source_type": "syslog",
            "level": "info",
            "auth_type": auth,
            "status": "success",
            "user": user,
            "src_computer": hostname,
            "dst_computer": random.choice(HOSTNAMES[:3]),
        }
    else:  # pam_session
        return {
            "timestamp": ts,
            "hostname": hostname,
            "message": f"pam_unix(login:session): session opened for user {user}",
            "source": "login",
            "source_type": "syslog",
            "level": "info",
            "status": "success",
            "user": user,
        }


# ── 4. DNS EVENTS (10%) — matches 05_DNS benign training
def make_dns_event(ts):
    """Benign DNS lookups — matches 05_DNS/DGA, DoH, Exfil benign training."""
    domain = random.choice(BENIGN_DOMAINS)
    hostname = random.choice(HOSTNAMES)
    src_ip = random.choice(INTERNAL_IPS[:20])

    return {
        "timestamp": ts,
        "hostname": hostname,
        "message": f"DNS query: {domain} A IN from {src_ip}",
        "dns_query_name": domain,
        "source_type": "dns",
        "src_ip": src_ip,
        "dst_ip": "10.10.1.1",  # internal DNS server
        "dst_port": 53,
        "protocol": "UDP",
        "bytes_sent": random.randint(40, 120),
        "bytes_received": random.randint(60, 300),
        "level": "info",
    }


# ── 5. CLOUD EVENTS (10%) — matches 06_Cloud benign training
def make_cloud_event(ts):
    """Benign CloudTrail events — matches 06_Cloud training."""
    event_name, event_source, is_read = random.choice(BENIGN_AWS_EVENTS)
    user = random.choice(["arn:aws:iam::123456789012:user/deploy-bot",
                          "arn:aws:iam::123456789012:role/lambda-exec",
                          "arn:aws:iam::123456789012:user/admin-readonly"])
    return {
        "timestamp": ts,
        "hostname": "aws-account-prod",
        "message": f"CloudTrail: {event_name} by {user} from {event_source}",
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
        "userIdentity": {"type": "AssumedRole", "arn": user},
        "readOnly": is_read,
        "errorCode": "",
        "source_type": "cloudtrail",
        "level": "info",
    }


# ── 6. PROCESS EVENTS (10%) — with pid for proper routing
def make_process_event(ts):
    """Benign process events — standard system processes."""
    binaries = [
        ("/usr/sbin/sshd", "sshd -D"),
        ("/usr/sbin/cron", "-f"),
        ("/usr/lib/systemd/systemd", "--system"),
        ("/usr/sbin/rsyslogd", "-n -iNONE"),
        ("/usr/bin/containerd", ""),
        ("/usr/sbin/ntpd", "-n -u ntp:ntp"),
        ("/usr/bin/python3", "/opt/app/server.py"),
        ("/usr/bin/node", "/opt/app/index.js"),
        ("/usr/sbin/nginx", "-g daemon off"),
        ("/usr/bin/postgres", "-D /var/lib/postgresql/data"),
    ]
    binary, args = random.choice(binaries)
    pid = random.randint(1000, 65000)
    uid = random.choice([0, 33, 65534, 1000, 1001, 999])

    return {
        "timestamp": ts,
        "hostname": random.choice(HOSTNAMES[-3:]),
        "message": f"Process started: {binary} {args}",
        "pid": pid,
        "ppid": random.randint(1, pid),
        "uid": uid,
        "binary_path": binary,
        "arguments": args,
        "exit_code": 0,
        "source_type": "process",
        "level": "info",
    }


# ── Event generators weighted by type ────────────────────────────────────

GENERATORS = [
    (make_network_flow, 0.25),
    (make_windows_auth, 0.25),
    (make_syslog_auth, 0.20),
    (make_dns_event, 0.10),
    (make_cloud_event, 0.10),
    (make_process_event, 0.10),
]


def generate_batch(batch_size):
    events = []
    ts = _ts()
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
    parser = argparse.ArgumentParser(description="CLIF 50k Realistic Benign Pipeline Test")
    parser.add_argument("--count", type=int, default=50_000)
    parser.add_argument("--batch", type=int, default=500)
    parser.add_argument("--host", type=str, default=VECTOR_HOST)
    parser.add_argument("--port", type=int, default=VECTOR_PORT)
    args = parser.parse_args()

    total = args.count
    batch_size = args.batch

    print(f"\n{'=' * 65}")
    print(f"  CLIF Realistic Benign Test — {total:,} events via TCP NDJSON")
    print(f"{'=' * 65}")
    print(f"  Target:     {args.host}:{args.port}")
    print(f"  Strategy:   Training-distribution-matched benign events")
    print(f"  Mix:        25% network, 25% windows-auth, 20% syslog-auth,")
    print(f"              10% DNS, 10% cloud, 10% process")
    print(f"  Key fields: auth_type, status, EventID, bytes, protocol, etc.")
    print(f"{'=' * 65}\n")

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
                eps = sent / (now - t_start) if (now - t_start) > 0 else 0
                pct = sent / total * 100
                print(f"  [{pct:5.1f}%] Sent {sent:,} / {total:,}  ({eps:,.0f} EPS)")
                last_report = now

    except KeyboardInterrupt:
        print(f"\n  Interrupted after {sent:,} events")

    finally:
        try:
            sock.close()
        except Exception:
            pass

    elapsed = time.monotonic() - t_start
    eps = sent / elapsed if elapsed > 0 else 0
    print(f"\n  {'=' * 55}")
    print(f"  DONE: {sent:,} events in {elapsed:.1f}s ({eps:,.0f} EPS)")
    if errors:
        print(f"  Reconnects: {errors}")
    print(f"  {'=' * 55}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
