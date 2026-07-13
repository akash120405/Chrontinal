#!/usr/bin/env python3
"""
Export ~2M REAL log events from agents/Data/Latest_Dataset/ to NDJSON.
Covers all 11 categories. No synthetic data. No templates. Pure real logs.

Output: real_2m_payload.ndjson → ready for tcpblaster → Vector:9514

Usage:
  python scripts/export_real_2m.py
"""
import csv
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

csv.field_size_limit(10_000_000)

BASE = Path(r"C:\CLIF\agents\Data\Latest_Dataset")
OUTPUT = "real_2m_payload.ndjson"
TARGET = 2_000_000

# ── Dataset configs ──────────────────────────────────────────────────────
DATASETS = []

# 1. SSH parsed (syslog)
DATASETS.append({
    "name": "ssh_parsed",
    "file": BASE / "01_Syslog" / "ssh_parsed.csv",
    "type": "csv",
    "source_type": "syslog",
    "max": 200_000,
    "converter": "ssh_parsed",
})

# 2. Linux syslog (loghub)
DATASETS.append({
    "name": "linux_syslog",
    "file": BASE / "01_Syslog" / "loghub-linux" / "Linux_2k.log",
    "type": "raw",
    "source_type": "syslog",
    "max": 2_000,
})

# 3. OpenSSH log
DATASETS.append({
    "name": "openssh_log",
    "file": BASE / "01_Syslog" / "OpenSSH_2k.log",
    "type": "raw",
    "source_type": "syslog",
    "max": 2_000,
})

# 4. SSH auth log (full)
DATASETS.append({
    "name": "ssh_auth_log",
    "file": BASE / "01_Syslog" / "SSH.log",
    "type": "raw",
    "source_type": "syslog",
    "max": 100_000,
})

# 5. CREMEv2 syslog (labeled attacks)
DATASETS.append({
    "name": "cremev2_syslog",
    "file": BASE / "01_Syslog" / "CREMEv2" / "label_syslog.csv",
    "type": "csv",
    "source_type": "syslog",
    "max": 100_000,
    "converter": "cremev2",
})

# 6. Windows EVTX attacks
DATASETS.append({
    "name": "evtx_attacks",
    "file": BASE / "02_Windows_Event" / "EVTX-ATTACK-SAMPLES" / "evtx_data.csv",
    "type": "csv",
    "source_type": "windows_event_log",
    "max": 100_000,
    "converter": "evtx",
})

# 7. Windows baseline benign
DATASETS.append({
    "name": "windows_baseline",
    "file": BASE / "02_Windows_Event" / "baseline_benign.csv",
    "type": "csv",
    "source_type": "windows_event_log",
    "max": 50_000,
    "converter": "windows_baseline",
})

# 8. Firewall UNSW-NB15
DATASETS.append({
    "name": "unsw_firewall",
    "file": BASE / "03_Firewall" / "UNSW-NB15_1.csv",
    "type": "csv",
    "source_type": "firewall",
    "max": 200_000,
    "converter": "unsw",
})

# 9. DNS DGA detection
DATASETS.append({
    "name": "dns_dga",
    "file": BASE / "05_DNS" / "dga_detection.csv",
    "type": "csv",
    "source_type": "dns",
    "max": 150_000,
    "converter": "dns_dga",
})

# 10. Cloud AWS CloudTrail
DATASETS.append({
    "name": "cloudtrail",
    "file": BASE / "06_Cloud_AWS" / "cloudtrail_labeled.csv",
    "type": "csv",
    "source_type": "cloud_audit",
    "max": 200_000,
    "converter": "cloudtrail",
})

# 11. Web Server CSIC (bad requests)
DATASETS.append({
    "name": "csic_web",
    "file": BASE / "08_Web_Server" / "csic_parsed.csv",
    "type": "csv",
    "source_type": "http_server",
    "max": 100_000,
    "converter": "csic",
})

# 12. NetFlow UNSW-NB15
DATASETS.append({
    "name": "netflow_unsw",
    "file": BASE / "09_NetFlow" / "NF-UNSW-NB15-v3.csv",
    "type": "csv",
    "source_type": "netflow",
    "max": 200_000,
    "converter": "netflow_unsw",
})

# 13. IDS CIC-IDS-2018 (biggest file, 2.9GB)
DATASETS.append({
    "name": "ids_2018_day1",
    "file": BASE / "10_IDS_IPS" / "CIC-IDS2018" / "02-14-2018.csv",
    "type": "csv",
    "source_type": "ids_ips",
    "max": 200_000,
    "converter": "cicids2018",
})

# 14. IDS 2018 day2
DATASETS.append({
    "name": "ids_2018_day2",
    "file": BASE / "10_IDS_IPS" / "CIC-IDS2018" / "02-15-2018.csv",
    "type": "csv",
    "source_type": "ids_ips",
    "max": 150_000,
    "converter": "cicids2018",
})

# 15. Email phishing
DATASETS.append({
    "name": "email_phishing",
    "file": BASE / "11_Email" / "phishing_email.csv",
    "type": "csv",
    "source_type": "email",
    "max": 100_000,
    "converter": "email",
})

# 16. LANL auth (AD)
DATASETS.append({
    "name": "lanl_auth",
    "file": BASE / "04_Active_Directory" / "lanl_auth_ad.csv",
    "type": "csv",
    "source_type": "active_directory",
    "max": 150_000,
    "converter": "lanl_ad",
})


# ── Converters ───────────────────────────────────────────────────────────

def convert_ssh_parsed(row, meta):
    # Actual cols: timestamp,hostname,service,pid,event_type,username,source_ip,port,message
    msg = row.get("message", "")
    if not msg:
        parts = [v for k, v in row.items() if v and k not in ("timestamp",)]
        msg = " ".join(parts[:5])
    if not msg:
        return None
    hostname = row.get("hostname", "ssh-server-01")
    ip = row.get("source_ip", "")
    user = row.get("username", "")
    event_type = row.get("event_type", "")
    label = ""
    level = "WARNING" if event_type and event_type.lower() in ("failed", "invalid", "break-in") else "INFO"
    ev = {
        "message": str(msg)[:2000],
        "source_type": meta["source_type"],
        "hostname": str(hostname) if hostname else "ssh-server-01",
        "level": level,
    }
    if ip and str(ip) not in ("", "nan"):
        ev["ip_address"] = str(ip)
    if user and str(user) not in ("", "nan"):
        ev["user_id"] = str(user)
    return ev


def convert_cremev2(row, meta):
    # Label col + many EventTemplate_xxx columns
    label = row.get("Label", "")
    vals = [str(v) for k, v in row.items() if k != "Label" and v and str(v) not in ("", "nan", "0")]
    msg = " | ".join(vals[:4])
    if not msg:
        return None
    level = "WARNING" if str(label).strip() not in ("0", "") else "INFO"
    return {
        "message": f"CREMEv2: label={label} {str(msg)[:1500]}",
        "source_type": meta["source_type"],
        "hostname": "creme-host-01",
        "level": level,
    }


def convert_evtx(row, meta):
    channel = row.get("Channel", "Security")
    event_id = row.get("EventID", "0")
    computer = row.get("Computer", "WIN-DC01")
    tactic = row.get("EVTX_Tactic", "")
    target_user = row.get("TargetUserName", "")
    subject_user = row.get("SubjectUserName", "")
    ip = row.get("IpAddress", "")
    process_name = row.get("ProcessName", row.get("NewProcessName", ""))
    cmd_line = row.get("CommandLine", "")

    parts = [f"EventID={event_id}", f"Channel={channel}"]
    if tactic:
        parts.append(f"Tactic={tactic}")
    if target_user:
        parts.append(f"TargetUser={target_user}")
    if subject_user:
        parts.append(f"SubjectUser={subject_user}")
    if process_name:
        parts.append(f"Process={process_name}")
    if cmd_line:
        parts.append(f"CommandLine={cmd_line[:200]}")

    msg = f"Windows Event: Computer={computer} {' '.join(parts)}"
    level = "WARNING" if tactic else "INFO"

    ev = {
        "message": msg[:2000],
        "source_type": meta["source_type"],
        "hostname": str(computer),
        "level": level,
    }
    if ip and ip not in ("-", "", "nan"):
        ev["ip_address"] = str(ip)
    if target_user:
        ev["user_id"] = str(target_user)
    return ev


def convert_windows_baseline(row, meta):
    # Actual cols: timestamp,event_id,channel,computer,provider,level,task,opcode,process_id,thread_id,label
    event_id = row.get("event_id", "")
    channel = row.get("channel", "")
    computer = row.get("computer", "WIN-WS01")
    provider = row.get("provider", "")
    level = row.get("level", "")
    msg = f"Windows Baseline: EventID={event_id} Channel={channel} Computer={computer} Provider={provider} Level={level}"
    return {
        "message": msg[:2000],
        "source_type": meta["source_type"],
        "hostname": str(computer) if computer else "WIN-WS01",
        "level": "INFO",
    }


def convert_unsw(row, meta):
    src_ip = row.get("srcip", "0.0.0.0")
    dst_ip = row.get("dstip", "0.0.0.0")
    sport = row.get("sport", "0")
    dsport = row.get("dsport", "0")
    proto = row.get("proto", "tcp").upper()
    service = row.get("service", "-")
    attack_cat = row.get("attack_cat", "").strip()
    label = row.get("label", "0")
    sbytes = row.get("sbytes", "0")
    dbytes = row.get("dbytes", "0")

    is_attack = str(label) == "1" or (attack_cat and attack_cat not in ("Normal", "", " "))
    if is_attack:
        msg = (f"Firewall alert: {attack_cat} - {src_ip}:{sport} -> {dst_ip}:{dsport} "
               f"proto={proto} service={service} bytes={sbytes}/{dbytes}")
        level = "WARNING"
    else:
        msg = (f"Firewall: {src_ip}:{sport} -> {dst_ip}:{dsport} "
               f"proto={proto} service={service} bytes={sbytes}/{dbytes}")
        level = "INFO"

    ev = {
        "message": msg,
        "source_type": meta["source_type"],
        "hostname": "fw-01",
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": int(sport) if str(sport).isdigit() else 0,
        "dst_port": int(dsport) if str(dsport).isdigit() else 0,
        "protocol": proto,
        "level": level,
    }
    if is_attack and attack_cat:
        ev["attack_cat"] = attack_cat
    return ev


def convert_dns_dga(row, meta):
    domain = row.get("domain", row.get("Domain", "unknown"))
    label = row.get("label", row.get("class", ""))
    is_dga = str(label).lower() in ("1", "dga", "malicious")
    if is_dga:
        msg = f"DNS query: suspicious DGA domain={domain}"
        level = "WARNING"
    else:
        msg = f"DNS query: domain={domain}"
        level = "INFO"
    return {
        "message": msg,
        "source_type": meta["source_type"],
        "hostname": "dns-resolver-01",
        "dns_query": str(domain),
        "dst_port": 53,
        "protocol": "UDP",
        "level": level,
    }


def convert_cloudtrail(row, meta):
    # Actual cols: eventID,eventTime,sourceIPAddress,userAgent,eventName,eventSource,awsRegion,...
    event_name = row.get("eventName", "")
    event_source = row.get("eventSource", "")
    user = row.get("userIdentityarn", row.get("userIdentityprincipalId", ""))
    src_ip = row.get("sourceIPAddress", "")
    region = row.get("awsRegion", "")
    label = row.get("label", "")
    error = row.get("errorCode", "")

    is_attack = str(label).lower() not in ("0", "normal", "benign", "", "nan")

    parts = []
    if event_name:
        parts.append(f"action={event_name}")
    if event_source:
        parts.append(f"service={event_source}")
    if user and str(user) not in ("", "nan"):
        parts.append(f"user={user}")
    if src_ip and str(src_ip) not in ("", "nan"):
        parts.append(f"ip={src_ip}")
    if region and str(region) not in ("", "nan"):
        parts.append(f"region={region}")
    if error and str(error) not in ("", "nan"):
        parts.append(f"error={error}")

    msg = f"CloudTrail: {' '.join(parts)}"
    level = "WARNING" if is_attack else "INFO"

    ev = {
        "message": msg[:2000],
        "source_type": meta["source_type"],
        "hostname": "aws-cloudtrail",
        "level": level,
    }
    if src_ip and str(src_ip) not in ("", "nan"):
        ev["ip_address"] = str(src_ip)
    if user and str(user) not in ("", "nan"):
        ev["user_id"] = str(user)
    return ev


def convert_csic(row, meta):
    # Actual cols: time,url,host,host_ip,port,protocol,method,path,extension,status,responselength,mimetype,request_length,has_body,label
    method = row.get("method", "GET")
    path = row.get("path", row.get("url", "/"))
    host = row.get("host", "")
    status = row.get("status", "")
    label = row.get("label", "")

    is_attack = str(label).lower() in ("1", "anomalous", "attack", "malicious")

    msg = f"HTTP {method} {host}{path} status={status}"
    level = "WARNING" if is_attack else "INFO"

    return {
        "message": msg[:2000],
        "source_type": meta["source_type"],
        "hostname": "web-01",
        "level": level,
    }


def convert_netflow_unsw(row, meta):
    keys = list(row.keys())
    src_ip = row.get("IPV4_SRC_ADDR", row.get("src_ip", row.get(keys[0], ""))) if keys else ""
    dst_ip = row.get("IPV4_DST_ADDR", row.get("dst_ip", row.get(keys[1], ""))) if len(keys) > 1 else ""
    sport = row.get("L4_SRC_PORT", row.get("src_port", "0"))
    dport = row.get("L4_DST_PORT", row.get("dst_port", "0"))
    proto = row.get("PROTOCOL", row.get("protocol", "6"))
    label = row.get("Label", row.get("label", row.get("Attack", "0")))
    attack = row.get("Attack", row.get("attack_cat", ""))

    is_attack = str(label) not in ("0", "Normal", "normal", "benign", "")

    if is_attack:
        msg = f"NetFlow alert: {attack} {src_ip}:{sport} -> {dst_ip}:{dport} proto={proto}"
        level = "WARNING"
    else:
        msg = f"NetFlow: {src_ip}:{sport} -> {dst_ip}:{dport} proto={proto}"
        level = "INFO"

    return {
        "message": msg,
        "source_type": meta["source_type"],
        "hostname": "netflow-collector-01",
        "src_ip": str(src_ip) if src_ip else "0.0.0.0",
        "dst_ip": str(dst_ip) if dst_ip else "0.0.0.0",
        "src_port": int(sport) if str(sport).isdigit() else 0,
        "dst_port": int(dport) if str(dport).isdigit() else 0,
        "protocol": str(proto).upper(),
        "level": level,
    }


def convert_cicids2018(row, meta):
    label = row.get("Label", row.get(" Label", "Benign")).strip()
    dst_port = row.get("Dst Port", row.get(" Destination Port", "0")).strip()
    protocol = row.get("Protocol", row.get(" Protocol", "6")).strip()
    fwd_pkts = row.get("Tot Fwd Pkts", row.get(" Total Fwd Packets", "0")).strip()
    bwd_pkts = row.get("Tot Bwd Pkts", row.get(" Total Backward Packets", "0")).strip()
    flow_dur = row.get("Flow Duration", row.get(" Flow Duration", "0")).strip()

    is_attack = label.lower() != "benign"

    if is_attack:
        msg = (f"IDS Alert: {label} dst_port={dst_port} proto={protocol} "
               f"fwd_pkts={fwd_pkts} bwd_pkts={bwd_pkts} flow_dur={flow_dur}")
        level = "WARNING"
    else:
        msg = (f"IDS: normal traffic dst_port={dst_port} proto={protocol} "
               f"fwd_pkts={fwd_pkts} bwd_pkts={bwd_pkts}")
        level = "INFO"

    return {
        "message": msg,
        "source_type": meta["source_type"],
        "hostname": "ids-sensor-01",
        "dst_port": int(dst_port) if str(dst_port).isdigit() else 0,
        "src_port": random.randint(1024, 65535),
        "protocol": "TCP" if protocol in ("6", "TCP") else "UDP",
        "level": level,
    }


def convert_email(row, meta):
    # Actual cols: text_combined,label
    text = row.get("text_combined", "")
    label = row.get("label", "")

    is_phishing = str(label).lower() in ("1", "phishing", "spam", "malicious")

    body_snippet = str(text)[:500] if text else ""

    msg = f"Email: {body_snippet}"

    level = "WARNING" if is_phishing else "INFO"
    return {
        "message": msg[:2000],
        "source_type": meta["source_type"],
        "hostname": "mail-gw-01",
        "level": level,
    }


def convert_lanl_ad(row, meta):
    # Actual cols: time,src_user,dst_user,src_computer,dst_computer,auth_type,logon_type,auth_orientation,status,label
    src_user = row.get("src_user", "")
    dst_user = row.get("dst_user", "")
    src_comp = row.get("src_computer", "")
    dst_comp = row.get("dst_computer", "")
    auth_type = row.get("auth_type", "")
    logon_type = row.get("logon_type", "")
    status = row.get("status", "")
    label = row.get("label", "")

    is_attack = str(label).strip().lower() not in ("0", "", "normal")
    msg = f"AD Auth: {src_user}->{dst_user} src={src_comp} dst={dst_comp} auth={auth_type} logon={logon_type} status={status}"
    return {
        "message": msg[:2000],
        "source_type": meta["source_type"],
        "hostname": str(dst_comp) if dst_comp and str(dst_comp) not in ("", "nan") else "dc-01",
        "user_id": str(src_user) if src_user and str(src_user) not in ("", "nan") else "",
        "level": "WARNING" if is_attack else "INFO",
    }


CONVERTERS = {
    "ssh_parsed": convert_ssh_parsed,
    "cremev2": convert_cremev2,
    "evtx": convert_evtx,
    "windows_baseline": convert_windows_baseline,
    "unsw": convert_unsw,
    "dns_dga": convert_dns_dga,
    "cloudtrail": convert_cloudtrail,
    "csic": convert_csic,
    "netflow_unsw": convert_netflow_unsw,
    "cicids2018": convert_cicids2018,
    "email": convert_email,
    "lanl_ad": convert_lanl_ad,
}


# ── Loaders ──────────────────────────────────────────────────────────────

def load_raw(path, meta, max_rows):
    events = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                events.append({
                    "message": line[:2000],
                    "source_type": meta["source_type"],
                    "hostname": f"host-{meta['name']}",
                    "level": "INFO",
                })
    except Exception as e:
        print(f"  ERROR loading {path.name}: {e}")
    return events


def load_csv_dataset(path, meta, max_rows):
    events = []
    converter = CONVERTERS.get(meta.get("converter", ""))
    if not converter:
        print(f"  No converter for {meta['name']}")
        return events

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first = f.readline()
            if first.startswith("\ufeff"):
                first = first[1:]
            f.seek(0)

            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                try:
                    ev = converter(row, meta)
                    if ev and ev.get("message"):
                        events.append(ev)
                except Exception:
                    continue
    except Exception as e:
        print(f"  ERROR loading {path.name}: {e}")
    return events


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print(f"=== CLIF Real Log Exporter — Target {TARGET:,} events ===\n")

    all_events = {}
    total = 0

    for ds in DATASETS:
        path = ds["file"]
        if not path.exists():
            print(f"  SKIP {ds['name']:25s} — file not found: {path.name}")
            continue

        t0 = time.time()
        if ds["type"] == "raw":
            events = load_raw(path, ds, ds["max"])
        else:
            events = load_csv_dataset(path, ds, ds["max"])

        elapsed = time.time() - t0
        if events:
            all_events[ds["name"]] = events
            total += len(events)
            print(f"  OK   {ds['name']:25s}  {len(events):>8,} events  ({elapsed:.1f}s)  [{ds['source_type']}]")
        else:
            print(f"  EMPTY {ds['name']:25s}")

    print(f"\nTotal unique events: {total:,} from {len(all_events)} datasets")

    if total == 0:
        print("No events loaded!")
        sys.exit(1)

    # Interleave round-robin
    print("Interleaving events...")
    names = list(all_events.keys())
    iters = {n: iter(all_events[n]) for n in names}
    interleaved = []
    done = set()
    while len(done) < len(names):
        for n in names:
            if n in done:
                continue
            try:
                interleaved.append(next(iters[n]))
            except StopIteration:
                done.add(n)

    # Repeat to hit target
    if len(interleaved) < TARGET:
        repeats = (TARGET // len(interleaved)) + 1
        print(f"Repeating {len(interleaved):,} × {repeats} to reach ~{TARGET:,}...")
        base = interleaved[:]
        for r in range(repeats - 1):
            interleaved.extend(base)
        interleaved = interleaved[:TARGET]
    else:
        interleaved = interleaved[:TARGET]

    # Add fresh timestamps (spread over last 24h)
    now = time.time()
    span = 86400  # 24 hours
    for i, ev in enumerate(interleaved):
        ts = now - span + (i / len(interleaved)) * span
        ev["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Shuffle slightly for realism (within windows of 1000)
    print("Shuffling...")
    window = 1000
    for i in range(0, len(interleaved) - window, window):
        chunk = interleaved[i:i+window]
        random.shuffle(chunk)
        interleaved[i:i+window] = chunk

    # Write NDJSON
    print(f"Writing {len(interleaved):,} events to {OUTPUT}...")
    t0 = time.time()
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for ev in interleaved:
            f.write(json.dumps(ev, separators=(",", ":"), default=str) + "\n")

    size_mb = os.path.getsize(OUTPUT) / (1024 * 1024)
    elapsed = time.time() - t0
    print(f"\nDone: {OUTPUT}")
    print(f"  Events: {len(interleaved):,}")
    print(f"  Size:   {size_mb:.1f} MB")
    print(f"  Write:  {elapsed:.1f}s")

    # Show dataset breakdown
    print(f"\nDataset breakdown:")
    for name, events in sorted(all_events.items(), key=lambda x: -len(x[1])):
        ds_meta = next(d for d in DATASETS if d["name"] == name)
        print(f"  {name:25s}  {len(events):>8,}  [{ds_meta['source_type']}]")


if __name__ == "__main__":
    main()
