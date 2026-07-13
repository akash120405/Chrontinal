#!/usr/bin/env python3
"""Quick feature comparison for debugging LightGBM predictions."""
import sys, json, numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents" / "triage"))
from feature_extractor import FeatureExtractor, FEATURE_NAMES

fe = FeatureExtractor()

cases = [
    ("BENIGN cloud (lgbm=0.9984)", "raw-logs", {
        "timestamp": "2026-03-22T10:34:00.000Z", "hostname": "aws-account-prod",
        "eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1", "readOnly": True, "errorCode": "",
        "userIdentity": {"type": "AssumedRole"},
        "source_type": "cloudtrail", "level": "info",
        "message": "CloudTrail: DescribeInstances",
    }),
    ("ATTACK cloud CreateKey (lgbm=0.30)", "raw-logs", {
        "timestamp": "2026-03-22T03:40:00.000Z", "hostname": "aws-account-prod",
        "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1", "readOnly": False, "errorCode": "",
        "userIdentity": {"type": "IAMUser"},
        "source_type": "cloudtrail", "level": "warning",
        "message": "CloudTrail: CreateAccessKey from iam.amazonaws.com",
    }),
    ("ATTACK StopLogging (lgbm=0.04)", "raw-logs", {
        "timestamp": "2026-03-22T03:41:00.000Z", "hostname": "aws-account-prod",
        "eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "us-east-1", "readOnly": False, "errorCode": "",
        "userIdentity": {"type": "IAMUser"},
        "source_type": "cloudtrail", "level": "warning",
        "message": "CloudTrail: StopLogging",
    }),
    ("ATTACK SSH brute (lgbm=0.02)", "raw-logs", {
        "timestamp": "2026-03-22T03:15:00.000Z", "hostname": "linux-jump-01",
        "source": "sshd", "source_type": "syslog", "level": "warning",
        "auth_type": "password", "status": "fail", "user": "root",
        "ip_address": "185.220.101.34",
        "message": "Failed password for root from 185.220.101.34 port 44321 ssh2",
    }),
    ("BENIGN SSH accept (lgbm=0.44)", "raw-logs", {
        "timestamp": "2026-03-22T10:33:00.000Z", "hostname": "linux-app-01",
        "source": "sshd", "source_type": "syslog", "level": "info",
        "auth_type": "publickey", "status": "success", "user": "deploy",
        "ip_address": "10.10.1.30",
        "message": "Accepted publickey for deploy from 10.10.1.30 port 52000 ssh2",
    }),
]

for title, topic, event in cases:
    feat = fe.extract(event, topic)
    vec = fe.to_numpy(feat)
    lt = feat.get("_log_type", "?")
    print(f"\n{'='*60}")
    print(f"{title}  (detected log_type={lt})")
    print(f"{'='*60}")
    for i, fn in enumerate(FEATURE_NAMES):
        if vec[i] != 0.0:
            print(f"  {fn:30s} = {vec[i]:12.4f}")
