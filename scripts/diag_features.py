#!/usr/bin/env python3
"""Compare feature values: training data vs hand-crafted 86 security logs."""
import sys, json
from pathlib import Path
import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "agents" / "Data" / "training_v8"
sys.path.insert(0, str(ROOT / "agents" / "triage"))
from feature_extractor import FeatureExtractor, FEATURE_NAMES

test = pd.read_parquet(DATA_DIR / "test.parquet")

# ── Training data: SSH attack + benign features ─────────────────────────
ssh_atk = test[(test["source_dataset"] == "syslog_ssh") & (test["is_malicious"] == 1)]
ssh_bn = test[(test["source_dataset"] == "syslog_ssh") & (test["is_malicious"] == 0)]

auth_feats = [
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "is_off_hours",
    "log_type", "severity_numeric", "message_length_log", "message_entropy",
    "auth_type_encoded", "status_is_fail", "is_admin", "src_dst_match",
    "is_remote", "fail_rate", "unique_targets", "event_frequency",
]

print("=" * 80)
print("  FEATURE COMPARISON: Training SSH vs Security Logs SSH")
print("=" * 80)

print(f"\n  Training SSH: {len(ssh_atk)} attack, {len(ssh_bn)} benign")
hdr = f"  {'Feature':<24} {'TrainAtk':>10} {'TrainBen':>10} {'Delta':>10}"
print(f"\n{hdr}")
print(f"  {'-' * 56}")
for fn in auth_feats:
    am = ssh_atk[fn].mean()
    bm = ssh_bn[fn].mean()
    print(f"  {fn:<24} {am:>10.4f} {bm:>10.4f} {am-bm:>+10.4f}")

# ── IDS features ────────────────────────────────────────────────────────
ids_atk = test[(test["source_dataset"].isin(["ids_2017","ids_2018","ids_kdd"])) & (test["is_malicious"] == 1)]
ids_bn = test[(test["source_dataset"].isin(["ids_2017","ids_2018","ids_kdd"])) & (test["is_malicious"] == 0)]

ids_feats = FEATURE_NAMES[:24]  # L1+L2
print(f"\n\n  Training IDS: {len(ids_atk)} attack, {len(ids_bn)} benign")
print(f"\n  {'Feature':<24} {'TrainAtk':>10} {'TrainBen':>10} {'Delta':>10}")
print(f"  {'-' * 56}")
for fn in ids_feats:
    am = ids_atk[fn].mean()
    bm = ids_bn[fn].mean()
    print(f"  {fn:<24} {am:>10.4f} {bm:>10.4f} {am-bm:>+10.4f}")

# ── Now extract features from hand-crafted logs ────────────────────────
import re
logfile = r"C:\Users\reddy\Downloads\security_logs_unlabeled.txt"
fe = FeatureExtractor()

RE_SSH = re.compile(
    r"^(?P<ts>\w+ \d+ [\d:]+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<msg>.+)"
)
RE_IDS = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}-[\d:.]+)\s+\[\*\*\] \[(?P<sid>[^\]]+)\] "
    r"(?P<sig>.+?) \[\*\*\] \[Classification: (?P<class>[^\]]+)\] "
    r"\[Priority: (?P<pri>\d+)\] \{(?P<proto>\w+)\} "
    r"(?P<src_ip>[\d.]+(?:/\d+)?):?(?P<src_port>\d+)?\s*->\s*"
    r"(?P<dst_ip>[\d.]+(?:/\d+)?):?(?P<dst_port>\d+)?"
)

print("\n\n" + "=" * 80)
print("  HAND-CRAFTED LOG FEATURES")
print("=" * 80)

ssh_logs = []
ids_logs = []
with open(logfile, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        m = RE_SSH.match(line)
        if m and "Failed password" in m.group("msg"):
            msg = m.group("msg")
            user_m = re.search(r"(?:for|user)\s+(\S+)", msg)
            user = user_m.group(1) if user_m else ""
            if user == "invalid":
                user_m = re.search(r"invalid user (\S+)", msg)
                user = user_m.group(1) if user_m else "invalid"
            ip_m = re.search(r"from\s+([\d.]+)", msg)
            event = {
                "timestamp": "2025-06-14T00:15:22.000Z",
                "hostname": m.group("host"),
                "source_type": "syslog",
                "message": line,
                "level": "WARNING",
                "auth_type": "password",
                "status": "fail",
                "user": user, "username": user,
                "event_type": "ssh_login",
            }
            if ip_m:
                event["source_ip"] = ip_m.group(1)
                event["src_ip"] = ip_m.group(1)
            feats = fe.extract(event, "raw-logs")
            ssh_logs.append(feats)
            if len(ssh_logs) >= 3:
                break

        m = RE_IDS.match(line)
        if m:
            event = {
                "timestamp": "2025-06-14T00:13:45.000Z",
                "hostname": "ids-sensor",
                "source_type": "ids",
                "message": line,
                "level": "WARNING",
                "src_ip": m.group("src_ip").split("/")[0],
                "dst_ip": m.group("dst_ip").split("/")[0],
                "src_port": int(m.group("src_port") or 0),
                "dst_port": int(m.group("dst_port") or 0),
                "protocol": m.group("proto"),
                "signature": m.group("sig"),
                "classification": m.group("class"),
                "priority": int(m.group("pri")),
            }
            feats = fe.extract(event, "network-events")
            ids_logs.append(feats)
            if len(ids_logs) >= 3:
                break

print(f"\n  SSH Failed-password logs extracted: {len(ssh_logs)}")
if ssh_logs:
    print(f"\n  {'Feature':<24} {'SecLog#1':>10} {'SecLog#2':>10} {'TrainAtk':>10} {'TrainBen':>10}")
    print(f"  {'-' * 68}")
    for fn in auth_feats:
        v1 = ssh_logs[0].get(fn, 0.0)
        v2 = ssh_logs[1].get(fn, 0.0) if len(ssh_logs) > 1 else 0
        am = ssh_atk[fn].mean()
        bm = ssh_bn[fn].mean()
        flag = " <<<" if abs(v1 - am) > 2.0 * max(ssh_atk[fn].std(), 0.01) else ""
        print(f"  {fn:<24} {v1:>10.4f} {v2:>10.4f} {am:>10.4f} {bm:>10.4f}{flag}")

print(f"\n  IDS logs extracted: {len(ids_logs)}")
if ids_logs:
    print(f"\n  {'Feature':<24} {'SecLog#1':>10} {'SecLog#2':>10} {'TrainAtk':>10} {'TrainBen':>10}")
    print(f"  {'-' * 68}")
    for fn in ids_feats:
        v1 = ids_logs[0].get(fn, 0.0)
        v2 = ids_logs[1].get(fn, 0.0) if len(ids_logs) > 1 else 0
        am = ids_atk[fn].mean()
        bm = ids_bn[fn].mean()
        flag = " <<<" if abs(v1 - am) > 2.0 * max(ids_atk[fn].std(), 0.01) else ""
        print(f"  {fn:<24} {v1:>10.4f} {v2:>10.4f} {am:>10.4f} {bm:>10.4f}{flag}")
