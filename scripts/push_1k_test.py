"""Push exactly 1000 test logs (250 per topic) into Redpanda for end-to-end testing."""
import json, random, string, time
from datetime import datetime, timezone, timedelta
from confluent_kafka import Producer

BROKER = "localhost:19092,localhost:29092,localhost:39092"
TAG = f"test-{int(time.time())}"

def _now_iso(offset_sec=0):
    dt = datetime.now(timezone.utc) - timedelta(seconds=offset_sec)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _rand_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _rand_id(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

# ── Generators ──

def gen_raw_log(i):
    return {
        "timestamp": _now_iso(random.randint(0, 300)),
        "level": random.choice(["INFO", "INFO", "INFO", "WARN", "ERROR", "CRITICAL"]),
        "source": random.choice(["web-server", "api-gateway", "auth-service", "firewall", "dns-resolver"]),
        "message": f"Request processed for user u{random.randint(1000,9999)} from {_rand_ip()} status={random.choice([200,200,200,301,403,404,500])}",
        "metadata": {
            "user_id": f"u{random.randint(1000,9999)}",
            "ip_address": _rand_ip(),
            "request_id": f"{TAG}-raw-{i}",
        },
        "ip_address": _rand_ip(),
    }

def gen_security_event(i):
    categories = ["auth-failure", "brute-force", "malware-detected", "privilege-escalation", "lateral-movement", "data-exfiltration"]
    tactics = ["initial-access", "execution", "persistence", "privilege-escalation", "lateral-movement", "exfiltration"]
    descs = [
        "Failed SSH login attempt from external IP",
        "Multiple authentication failures detected",
        "Suspicious binary execution in /tmp",
        "Unusual outbound data transfer detected",
        "Port scan detected from internal host",
        "Registry modification by non-admin process",
    ]
    sev = random.choices([1, 2, 3, 4], weights=[30, 35, 25, 10])[0]
    cat_idx = random.randint(0, len(categories) - 1)
    return {
        "timestamp": _now_iso(random.randint(0, 300)),
        "severity": sev,
        "category": categories[cat_idx],
        "source": random.choice(["sshd", "windows-defender", "suricata", "osquery", "sysmon"]),
        "description": descs[cat_idx % len(descs)],
        "user_id": f"u{random.randint(1000,9999)}",
        "ip_address": _rand_ip(),
        "hostname": f"srv-{random.randint(1,20):02d}",
        "mitre_tactic": tactics[cat_idx % len(tactics)],
        "mitre_technique": f"T{random.randint(1001,1599)}",
        "ai_confidence": round(random.uniform(0.15, 0.98), 2),
        "ai_explanation": f"Model flagged {categories[cat_idx]} with high entropy score",
        "metadata": {"request_id": f"{TAG}-sec-{i}"},
    }

def gen_process_event(i):
    bins = ["/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl", "/bin/sh", "/usr/bin/wget", "/tmp/suspicious.elf"]
    return {
        "timestamp": _now_iso(random.randint(0, 300)),
        "hostname": f"srv-{random.randint(1,20):02d}",
        "pid": random.randint(100, 65535),
        "ppid": random.randint(1, 1000),
        "uid": random.choice([0, 1000, 1001, 33, 65534]),
        "gid": random.choice([0, 1000, 1001, 33, 65534]),
        "binary_path": random.choice(bins),
        "arguments": f"--config /etc/app.conf --tag {TAG}",
        "cwd": random.choice(["/tmp", "/home/user", "/var/log", "/opt/app"]),
        "exit_code": random.choice([0, 0, 0, 1, -1, 137]),
        "container_id": _rand_id(16),
        "pod_name": f"pod-{_rand_id(6)}",
        "namespace": "production",
        "syscall": random.choice(["execve", "fork", "clone", "open", "connect"]),
        "is_suspicious": 1 if random.random() < 0.15 else 0,
        "detection_rule": "sigma-proc-tmp-exec" if random.random() < 0.1 else "",
        "metadata": {"tag": f"{TAG}-proc-{i}"},
    }

def gen_network_event(i):
    return {
        "timestamp": _now_iso(random.randint(0, 300)),
        "hostname": f"srv-{random.randint(1,20):02d}",
        "src_ip": _rand_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_ip": _rand_ip(),
        "dst_port": random.choice([80, 443, 8080, 8443, 53, 22, 3389]),
        "protocol": random.choice(["TCP", "TCP", "TCP", "UDP"]),
        "direction": random.choice(["outbound", "inbound"]),
        "bytes_sent": random.randint(64, 100000),
        "bytes_received": random.randint(64, 500000),
        "duration_ms": random.randint(1, 5000),
        "pid": random.randint(100, 65535),
        "binary_path": random.choice(["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/ssh", "/usr/bin/nc"]),
        "container_id": _rand_id(16),
        "pod_name": f"pod-{_rand_id(6)}",
        "namespace": "production",
        "dns_query": random.choice(["api.example.com", "cdn.assets.net", "evil-c2.bad.io", "update.microsoft.com", ""]),
        "geo_country": random.choice(["US", "US", "DE", "JP", "RU", "CN", "BR"]),
        "is_suspicious": 1 if random.random() < 0.12 else 0,
        "detection_rule": "sigma-net-c2-beacon" if random.random() < 0.08 else "",
        "metadata": {"tag": f"{TAG}-net-{i}"},
    }


TOPICS = {
    "raw-logs": gen_raw_log,
    "security-events": gen_security_event,
    "process-events": gen_process_event,
    "network-events": gen_network_event,
}

COUNT_PER_TOPIC = 250

def main():
    p = Producer({"bootstrap.servers": BROKER, "linger.ms": 5, "batch.num.messages": 500})
    total = 0
    for topic, gen in TOPICS.items():
        for i in range(COUNT_PER_TOPIC):
            msg = json.dumps(gen(i)).encode()
            p.produce(topic, msg)
            total += 1
            if total % 200 == 0:
                p.poll(0)
        print(f"  Produced {COUNT_PER_TOPIC} → {topic}")
    remaining = p.flush(30)
    print(f"\n✓ Total produced: {total} messages (unflushed: {remaining})")
    print(f"  Tag: {TAG}")

if __name__ == "__main__":
    main()
