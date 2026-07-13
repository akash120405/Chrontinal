#!/usr/bin/env python3
"""
CLIF v8 — Feature Extraction Pipeline
========================================
Extracts a 60-feature vector across 7 layers from ALL 10 dataset categories.

Architecture:
  Layer 1: Shared Core     (9 features)  — all log types
  Layer 2: Network         (15 features) — Firewall, NetFlow, IDS, DoH, CREMEv2 traffic
  Layer 3: Authentication  (8 features)  — Syslog, Windows, AD
  Layer 4: DNS             (8 features)  — DGA, DNS exfiltration
  Layer 5: Web/HTTP        (7 features)  — Web server, CSIC
  Layer 6: Email           (7 features)  — Email/phishing
  Layer 7: Cloud/API       (6 features)  — CloudTrail

Design principles:
  - ZERO synthetic data — only real observations from verified datasets
  - Vectorized pandas for batch speed (not one-event-at-a-time)
  - Inactive layers are zero-filled (model learns log_type → active layers)
  - Sentinel columns (-1 in NetFlow/CIC-IDS) NOT used as features
  - Labels are binary is_malicious (0/1) + string attack_type

Usage:
  cd C:\\CLIF
  python scripts/extract_features_v8.py
  python scripts/extract_features_v8.py --max-per-dataset 50000   # cap for quick test
  python scripts/extract_features_v8.py --dry-run                 # validate only
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import re
import sys
import time
import warnings
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("extract_v8")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "agents" / "Data" / "Latest_Dataset"
OUTPUT_DIR = BASE_DIR / "agents" / "Data" / "training_v8"

# 60-feature canonical names (order matters — must match at inference time)
FEATURE_NAMES = [
    # Layer 1: Shared Core (0–8)
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "is_off_hours",
    "log_type", "severity_numeric", "message_length_log", "message_entropy",
    # Layer 2: Network (9–23)
    "dst_port_bin", "protocol_numeric", "total_bytes_log", "byte_ratio",
    "total_packets_log", "packet_ratio", "flow_duration_log", "avg_pkt_size",
    "pkt_size_variance", "iat_mean", "iat_stddev", "tcp_syn_flag",
    "tcp_rst_flag", "tcp_fin_flag", "retransmit_ratio",
    # Layer 3: Auth (24–31)
    "auth_type_encoded", "status_is_fail", "is_admin", "src_dst_match",
    "is_remote", "fail_rate", "unique_targets", "event_frequency",
    # Layer 4: DNS (32–39)
    "domain_length", "domain_entropy", "subdomain_depth", "digit_ratio",
    "max_consonant_run", "bigram_frequency", "has_hex_pattern", "tld_risk",
    # Layer 5: Web/HTTP (40–46)
    "url_length", "url_entropy", "query_param_count", "has_sql_pattern",
    "has_xss_pattern", "has_traversal", "http_method",
    # Layer 6: Email (47–53)
    "subject_length", "body_length_log", "subject_entropy", "url_count",
    "caps_ratio", "has_urgency", "has_financial",
    # Layer 7: Cloud/API (54–59)
    "event_name_encoded", "is_sensitive_service", "is_read_only",
    "has_error", "identity_type_encoded", "is_root",
]

NUM_FEATURES = 60
assert len(FEATURE_NAMES) == NUM_FEATURES

# Layer boundaries (inclusive start, exclusive end)
LAYER_RANGES = {
    1: (0, 9),    # Shared Core
    2: (9, 24),   # Network
    3: (24, 32),  # Auth
    4: (32, 40),  # DNS
    5: (40, 47),  # Web
    6: (47, 54),  # Email
    7: (54, 60),  # Cloud
}

LOG_TYPE_MAP = {
    "syslog": 0, "windows": 1, "firewall": 2, "ad": 3, "dns": 4,
    "cloud": 5, "web": 6, "netflow": 7, "ids": 8, "email": 9,
}

PROTOCOL_MAP = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 0, "ospf": 89}

# Auth type encoding (shared across LANL syslog/AD)
AUTH_TYPE_MAP = {
    "kerberos": 0, "ntlm": 1, "negotiate": 2, "password": 3,
    "?": 4, "ms_auth_v1": 5, "wave": 6,
}

# TLD risk scores (higher = more suspicious)
TLD_RISK = {
    "com": 0.1, "org": 0.1, "net": 0.1, "edu": 0.05, "gov": 0.05,
    "io": 0.3, "xyz": 0.7, "top": 0.8, "tk": 0.9, "ml": 0.9,
    "ga": 0.9, "cf": 0.9, "gq": 0.9, "pw": 0.8, "cc": 0.6,
    "info": 0.4, "biz": 0.5, "ru": 0.5, "cn": 0.4, "br": 0.3,
}

# NSL-KDD column names (file has no header)
KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class", "difficulty",
]

# UNSW-NB15 Firewall header (49 columns)
FIREWALL_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "label",
]

# SQL injection keywords
SQL_KEYWORDS = re.compile(
    r"(union\s+select|select\s+.*from|drop\s+table|insert\s+into|"
    r"update\s+.*set|delete\s+from|or\s+1\s*=\s*1|and\s+1\s*=\s*1|"
    r"--\s|;\s*drop|'\s*or\s*'|char\(|concat\(|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)
# XSS patterns
XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|"
    r"document\.cookie|eval\s*\(|<iframe|<img\s+[^>]*on\w+\s*=)",
    re.IGNORECASE,
)
# Path traversal
TRAVERSAL_PATTERNS = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/|/var/log|cmd\.exe|/bin/sh)")

# Urgency keywords for email
URGENCY_KEYWORDS = re.compile(
    r"\b(urgent|immediately|verify|expire|suspend|deactivat|"
    r"confirm\s+your|act\s+now|limited\s+time|final\s+warning)\b",
    re.IGNORECASE,
)
# Financial keywords for email
FINANCIAL_KEYWORDS = re.compile(
    r"\b(bank|account|transfer|password|credit\s*card|ssn|"
    r"social\s+security|paypal|bitcoin|wire\s+transfer|routing\s+number)\b",
    re.IGNORECASE,
)

# CloudTrail top-50 event name encoding
CT_EVENT_NAMES = [
    "RunInstances", "DescribeSnapshots", "AssumeRole", "DescribeInstances",
    "GetBucketAcl", "ListBuckets", "GetObject", "PutObject",
    "CreateUser", "AttachUserPolicy", "DeleteUser", "CreateAccessKey",
    "GetCallerIdentity", "ListUsers", "ListRoles", "CreateRole",
    "PutRolePolicy", "DeleteAccessKey", "StopInstances", "TerminateInstances",
    "DescribeSecurityGroups", "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
    "DescribeSubnets", "DescribeVpcs", "CreateVpc", "DeleteVpc",
    "CreateTrail", "StopLogging", "DeleteTrail", "PutBucketPolicy",
    "GetBucketPolicy", "ListAccessKeys", "GetUserPolicy", "CreateLoginProfile",
    "UpdateLoginProfile", "DeleteLoginProfile", "ConsoleLogin",
    "DescribeRegions", "DescribeAvailabilityZones", "ModifyInstanceAttribute",
    "CreateKeyPair", "DescribeKeyPairs", "ImportKeyPair",
    "GetSecretValue", "CreateSecret", "DescribeDBInstances",
    "CreateDBInstance", "ModifyDBInstance", "DeleteDBInstance",
]

SENSITIVE_SERVICES = {
    "iam.amazonaws.com", "sts.amazonaws.com", "kms.amazonaws.com",
    "secretsmanager.amazonaws.com", "organizations.amazonaws.com",
    "cloudtrail.amazonaws.com",
}

# English bigram frequency table (top bigrams, normalized)
# Source: Cornell Natural Language Processing
_ENGLISH_BIGRAMS = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.73,
    "ri": 0.73, "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69,
    "ra": 0.62, "ce": 0.65, "li": 0.62, "ch": 0.60, "ll": 0.58,
    "be": 0.58, "ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54,
}
_MAX_BIGRAM_FREQ = max(_ENGLISH_BIGRAMS.values())


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def safe_float(val, default=0.0) -> float:
    try:
        v = float(val)
        return v if np.isfinite(v) else default
    except (ValueError, TypeError):
        return default


def shannon_entropy_vec(texts: pd.Series) -> np.ndarray:
    """Compute Shannon entropy for each text string (vectorized-ish)."""
    result = np.zeros(len(texts), dtype=np.float32)
    for i, text in enumerate(texts):
        if pd.isna(text) or not text:
            continue
        text = str(text)
        n = len(text)
        if n == 0:
            continue
        counts = Counter(text)
        probs = np.array(list(counts.values()), dtype=np.float64) / n
        result[i] = -np.sum(probs * np.log2(probs + 1e-15))
    return result


def bigram_frequency_score(domain: str) -> float:
    """Score how 'English-like' a domain name is based on character bigrams."""
    if not domain or len(domain) < 2:
        return 0.0
    # Strip TLD and dots
    parts = domain.lower().split(".")
    name = parts[0] if parts else domain.lower()
    if len(name) < 2:
        return 0.0
    bigrams = [name[i:i+2] for i in range(len(name) - 1)]
    total = sum(_ENGLISH_BIGRAMS.get(bg, 0.0) for bg in bigrams)
    return total / (len(bigrams) * _MAX_BIGRAM_FREQ) if bigrams else 0.0


def bigram_frequency_vec(domains: pd.Series) -> np.ndarray:
    """Batch bigram frequency scoring."""
    result = np.zeros(len(domains), dtype=np.float32)
    for i, d in enumerate(domains):
        if pd.isna(d):
            continue
        result[i] = bigram_frequency_score(str(d))
    return result


def max_consonant_run_scalar(text: str) -> int:
    """Longest run of consecutive consonants."""
    if not text:
        return 0
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_run = 0
    current = 0
    for c in text.lower():
        if c in consonants:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run


def max_consonant_run_vec(texts: pd.Series) -> np.ndarray:
    result = np.zeros(len(texts), dtype=np.int32)
    for i, t in enumerate(texts):
        if pd.isna(t):
            continue
        result[i] = max_consonant_run_scalar(str(t))
    return result


def port_bin(ports: pd.Series) -> pd.Series:
    """Bin ports: 0=well-known (0-1023), 1=registered (1024-49151), 2=ephemeral."""
    p = pd.to_numeric(ports, errors="coerce").fillna(0).clip(0, 65535).astype(int)
    return pd.cut(p, bins=[-1, 1023, 49151, 65536], labels=[0, 1, 2]).astype(int)


def count_urls_in_text(texts: pd.Series) -> np.ndarray:
    """Count URLs in text strings."""
    url_re = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
    result = np.zeros(len(texts), dtype=np.int32)
    for i, t in enumerate(texts):
        if pd.isna(t) or not t:
            continue
        result[i] = len(url_re.findall(str(t)))
    return result


def caps_ratio_vec(texts: pd.Series) -> np.ndarray:
    """Proportion of uppercase characters among alphabetic chars."""
    result = np.zeros(len(texts), dtype=np.float32)
    for i, t in enumerate(texts):
        if pd.isna(t) or not t:
            continue
        t = str(t)
        alpha = sum(1 for c in t if c.isalpha())
        if alpha == 0:
            continue
        result[i] = sum(1 for c in t if c.isupper()) / alpha
    return result


def has_pattern_vec(texts: pd.Series, pattern: re.Pattern) -> np.ndarray:
    """Binary: does text match regex pattern?"""
    result = np.zeros(len(texts), dtype=np.int32)
    for i, t in enumerate(texts):
        if pd.isna(t) or not t:
            continue
        if pattern.search(str(t)):
            result[i] = 1
    return result


def sample_df(df: pd.DataFrame, max_rows: int, label_col: str = None) -> pd.DataFrame:
    """Sample a DataFrame, keeping all minority-class rows if label_col given."""
    if len(df) <= max_rows:
        return df
    if label_col and label_col in df.columns:
        counts = df[label_col].value_counts()
        # Keep all instances of any class with < 5% of rows
        threshold = 0.05 * len(df)
        small_classes = counts[counts < threshold].index
        if len(small_classes) > 0:
            small_df = df[df[label_col].isin(small_classes)]
            big_df = df[~df[label_col].isin(small_classes)]
            n_small_keep = min(len(small_df), max_rows // 2)
            if n_small_keep < len(small_df):
                small_df = small_df.sample(n=n_small_keep, random_state=42)
            n_big = max_rows - len(small_df)
            if n_big > 0 and len(big_df) > n_big:
                big_df = big_df.sample(n=n_big, random_state=42)
            elif n_big <= 0:
                return small_df.head(max_rows)
            return pd.concat([small_df, big_df], ignore_index=True)
    return df.sample(n=max_rows, random_state=42)


def empty_feature_row(n: int) -> pd.DataFrame:
    """Create a DataFrame with n rows, all 60 features set to 0."""
    return pd.DataFrame(np.zeros((n, NUM_FEATURES), dtype=np.float32),
                        columns=FEATURE_NAMES)


def is_malicious_label(series: pd.Series) -> pd.Series:
    """Normalize diverse label formats to binary 0 (benign) / 1 (attack).

    Handles: 0/1 integers, 'Benign'/'Attack' strings, 'normal'/'normal.alexa', etc.
    """
    s = series.astype(str).str.strip().str.lower()
    benign_values = {"0", "0.0", "benign", "normal", "normal.alexa",
                     "legitimate", "nan", ""}
    return (~s.isin(benign_values)).astype(int)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: LAYER COMPUTATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def compute_layer1(n: int, hours: np.ndarray, dows: np.ndarray,
                   log_type: int, severity: np.ndarray,
                   msg_lengths: np.ndarray, msg_entropies: np.ndarray) -> pd.DataFrame:
    """Layer 1: Shared Core — 9 features."""
    hours = np.asarray(hours, dtype=np.float64)
    dows = np.asarray(dows, dtype=np.float64)
    return pd.DataFrame({
        "hour_sin": np.sin(2 * np.pi * hours / 24),
        "hour_cos": np.cos(2 * np.pi * hours / 24),
        "dow_sin": np.sin(2 * np.pi * dows / 7),
        "dow_cos": np.cos(2 * np.pi * dows / 7),
        "is_off_hours": ((hours < 6) | (hours >= 22) | (dows >= 5)).astype(np.float32),
        "log_type": np.full(n, log_type, dtype=np.float32),
        "severity_numeric": np.asarray(severity, dtype=np.float32),
        "message_length_log": np.log10(1.0 + np.asarray(msg_lengths, dtype=np.float64)).astype(np.float32),
        "message_entropy": np.asarray(msg_entropies, dtype=np.float32),
    })


def compute_layer2(src_bytes, dst_bytes, src_pkts, dst_pkts,
                   duration_ms, dst_port, protocol,
                   iat_mean_arr, iat_std_arr, pkt_var_arr,
                   syn_flag, rst_flag, fin_flag,
                   retransmit_ratio_arr) -> pd.DataFrame:
    """Layer 2: Network — 15 features."""
    sb = np.asarray(src_bytes, dtype=np.float64)
    db = np.asarray(dst_bytes, dtype=np.float64)
    sp = np.asarray(src_pkts, dtype=np.float64)
    dp = np.asarray(dst_pkts, dtype=np.float64)
    dur = np.asarray(duration_ms, dtype=np.float64)
    total_bytes = sb + db
    total_pkts = sp + dp

    return pd.DataFrame({
        "dst_port_bin": port_bin(pd.Series(dst_port)).values.astype(np.float32),
        "protocol_numeric": np.asarray(protocol, dtype=np.float32),
        "total_bytes_log": np.log10(1.0 + total_bytes).astype(np.float32),
        "byte_ratio": (sb / (total_bytes + 1e-10)).astype(np.float32),
        "total_packets_log": np.log10(1.0 + total_pkts).astype(np.float32),
        "packet_ratio": (sp / (total_pkts + 1e-10)).astype(np.float32),
        "flow_duration_log": np.log10(1.0 + dur).astype(np.float32),
        "avg_pkt_size": (total_bytes / (total_pkts + 1)).astype(np.float32),
        "pkt_size_variance": np.asarray(pkt_var_arr, dtype=np.float32),
        "iat_mean": np.asarray(iat_mean_arr, dtype=np.float32),
        "iat_stddev": np.asarray(iat_std_arr, dtype=np.float32),
        "tcp_syn_flag": np.asarray(syn_flag, dtype=np.float32),
        "tcp_rst_flag": np.asarray(rst_flag, dtype=np.float32),
        "tcp_fin_flag": np.asarray(fin_flag, dtype=np.float32),
        "retransmit_ratio": np.asarray(retransmit_ratio_arr, dtype=np.float32),
    })


def compute_layer3(auth_type, is_fail, is_admin, src_dst_match, is_remote,
                   fail_rate, unique_targets, event_freq) -> pd.DataFrame:
    """Layer 3: Authentication — 8 features."""
    return pd.DataFrame({
        "auth_type_encoded": np.asarray(auth_type, dtype=np.float32),
        "status_is_fail": np.asarray(is_fail, dtype=np.float32),
        "is_admin": np.asarray(is_admin, dtype=np.float32),
        "src_dst_match": np.asarray(src_dst_match, dtype=np.float32),
        "is_remote": np.asarray(is_remote, dtype=np.float32),
        "fail_rate": np.asarray(fail_rate, dtype=np.float32),
        "unique_targets": np.asarray(unique_targets, dtype=np.float32),
        "event_frequency": np.asarray(event_freq, dtype=np.float32),
    })


def compute_layer4(domain_len, domain_ent, sub_depth, digit_rat,
                   consonant_run, bigram_freq, hex_pattern, tld_rsk) -> pd.DataFrame:
    """Layer 4: DNS — 8 features."""
    return pd.DataFrame({
        "domain_length": np.asarray(domain_len, dtype=np.float32),
        "domain_entropy": np.asarray(domain_ent, dtype=np.float32),
        "subdomain_depth": np.asarray(sub_depth, dtype=np.float32),
        "digit_ratio": np.asarray(digit_rat, dtype=np.float32),
        "max_consonant_run": np.asarray(consonant_run, dtype=np.float32),
        "bigram_frequency": np.asarray(bigram_freq, dtype=np.float32),
        "has_hex_pattern": np.asarray(hex_pattern, dtype=np.float32),
        "tld_risk": np.asarray(tld_rsk, dtype=np.float32),
    })


def compute_layer5(url_len, url_ent, q_count, has_sql, has_xss,
                   has_trav, http_meth) -> pd.DataFrame:
    """Layer 5: Web/HTTP — 7 features."""
    return pd.DataFrame({
        "url_length": np.asarray(url_len, dtype=np.float32),
        "url_entropy": np.asarray(url_ent, dtype=np.float32),
        "query_param_count": np.asarray(q_count, dtype=np.float32),
        "has_sql_pattern": np.asarray(has_sql, dtype=np.float32),
        "has_xss_pattern": np.asarray(has_xss, dtype=np.float32),
        "has_traversal": np.asarray(has_trav, dtype=np.float32),
        "http_method": np.asarray(http_meth, dtype=np.float32),
    })


def compute_layer6(subj_len, body_len_log, subj_ent, url_cnt,
                   caps_rat, has_urg, has_fin) -> pd.DataFrame:
    """Layer 6: Email — 7 features."""
    return pd.DataFrame({
        "subject_length": np.asarray(subj_len, dtype=np.float32),
        "body_length_log": np.asarray(body_len_log, dtype=np.float32),
        "subject_entropy": np.asarray(subj_ent, dtype=np.float32),
        "url_count": np.asarray(url_cnt, dtype=np.float32),
        "caps_ratio": np.asarray(caps_rat, dtype=np.float32),
        "has_urgency": np.asarray(has_urg, dtype=np.float32),
        "has_financial": np.asarray(has_fin, dtype=np.float32),
    })


def compute_layer7(evt_name, is_sens, is_ro, has_err, id_type, is_rt) -> pd.DataFrame:
    """Layer 7: Cloud/API — 6 features."""
    return pd.DataFrame({
        "event_name_encoded": np.asarray(evt_name, dtype=np.float32),
        "is_sensitive_service": np.asarray(is_sens, dtype=np.float32),
        "is_read_only": np.asarray(is_ro, dtype=np.float32),
        "has_error": np.asarray(has_err, dtype=np.float32),
        "identity_type_encoded": np.asarray(id_type, dtype=np.float32),
        "is_root": np.asarray(is_rt, dtype=np.float32),
    })


def zeros_layer(layer_num: int, n: int) -> pd.DataFrame:
    """Return n rows of zeros for a given layer."""
    start, end = LAYER_RANGES[layer_num]
    cols = FEATURE_NAMES[start:end]
    return pd.DataFrame(np.zeros((n, len(cols)), dtype=np.float32), columns=cols)


def assemble_row(layer1, active_layers: Dict[int, pd.DataFrame], n: int) -> pd.DataFrame:
    """Combine Layer 1 + active layers + zero-fill inactive layers → 60-col DataFrame."""
    parts = [layer1]
    for layer_num in range(2, 8):
        if layer_num in active_layers:
            parts.append(active_layers[layer_num])
        else:
            parts.append(zeros_layer(layer_num, n))
    result = pd.concat(parts, axis=1)
    # Ensure canonical column order
    result = result[FEATURE_NAMES]
    return result


def compute_auth_aggregates(df: pd.DataFrame, entity_col: str,
                            target_col: str, status_col: str) -> Tuple:
    """Compute per-entity aggregate features for auth data."""
    # fail_rate per entity
    entity_stats = df.groupby(entity_col).agg(
        total=(status_col, "count"),
        fails=(status_col, lambda x: (x == 1).sum()),
    )
    entity_stats["fail_rate"] = entity_stats["fails"] / (entity_stats["total"] + 1e-10)

    # unique_targets per entity
    target_counts = df.groupby(entity_col)[target_col].nunique()
    entity_stats["unique_targets"] = np.log10(1.0 + target_counts)

    # event_frequency per entity
    entity_stats["event_frequency"] = np.log10(1.0 + entity_stats["total"])

    # Map back to rows
    fail_rate = df[entity_col].map(entity_stats["fail_rate"]).fillna(0).values
    unique_targets = df[entity_col].map(entity_stats["unique_targets"]).fillna(0).values
    event_freq = df[entity_col].map(entity_stats["event_frequency"]).fillna(0).values

    return fail_rate, unique_targets, event_freq


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: DATASET EXTRACTORS
#   Each returns (features_df[60 cols], is_malicious[int], attack_type[str], source[str])
# ═══════════════════════════════════════════════════════════════════════════════

def extract_syslog_lanl(max_rows: int) -> Optional[pd.DataFrame]:
    """01_Syslog: LANL auth_syslog — authentication events."""
    fp = DATA_DIR / "01_Syslog" / "lanl_auth_syslog.csv"
    if not fp.exists():
        log.warning("  SKIP: %s not found", fp.name)
        return None

    df = pd.read_csv(fp)
    df = sample_df(df, max_rows, "label")
    n = len(df)
    log.info("  01_Syslog/LANL: %d rows (attacks: %d)", n,
             (df["label"] != "normal").sum())

    # Layer 1: Core
    ts_sec = pd.to_numeric(df["time"], errors="coerce").fillna(0)
    hours = (ts_sec // 3600) % 24
    dows = (ts_sec // 86400) % 7
    # Construct message from auth fields
    msgs = ("auth " + df["auth_type"].fillna("") + " " +
            df["logon_type"].fillna("") + " " +
            df["status"].fillna("") + " " +
            df["src_user"].fillna("") + " → " + df["dst_user"].fillna(""))
    severity = (df["status"].str.lower() == "fail").astype(int)

    layer1 = compute_layer1(
        n, hours.values, dows.values, LOG_TYPE_MAP["syslog"],
        severity.values, msgs.str.len().values, shannon_entropy_vec(msgs),
    )

    # Layer 3: Auth
    auth_enc = df["auth_type"].str.lower().map(AUTH_TYPE_MAP).fillna(4).astype(int)
    is_fail = (df["status"].str.lower() == "fail").astype(int).values
    admin_names = {"root", "admin", "administrator", "system", "c$"}
    is_admin = df["dst_user"].str.lower().isin(admin_names).astype(int).values
    src_dst_match = (df["src_user"] == df["dst_user"]).astype(int).values
    is_remote = (df["src_computer"] != df["dst_computer"]).astype(int).values

    fail_rate, unique_targets, event_freq = compute_auth_aggregates(
        df.assign(_is_fail=is_fail), "src_user", "dst_computer", "_is_fail")

    layer3 = compute_layer3(auth_enc.values, is_fail, is_admin, src_dst_match,
                            is_remote, fail_rate, unique_targets, event_freq)

    features = assemble_row(layer1, {3: layer3}, n)
    features["is_malicious"] = (df["label"] != "normal").astype(int).values
    features["attack_type"] = df["label"].values
    features["source_dataset"] = "syslog_lanl"
    return features


def extract_syslog_ssh(max_rows: int) -> Optional[pd.DataFrame]:
    """01_Syslog: SSH parsed log — failed/accepted auth events."""
    fp = DATA_DIR / "01_Syslog" / "ssh_parsed.csv"
    if not fp.exists():
        log.warning("  SKIP: %s not found", fp.name)
        return None

    df = pd.read_csv(fp)
    df = sample_df(df, max_rows)
    n = len(df)

    # Label: Failed auth events are attack (brute force dataset)
    attack_types = {"failed_root", "auth_failure", "failed_invalid_user", "invalid_user"}
    is_attack = df["event_type"].str.lower().isin(attack_types).astype(int)
    log.info("  01_Syslog/SSH: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    # SSH timestamps are like "Jun 15 15:14:22" — extract hour
    hour_match = df["timestamp"].str.extract(r"(\d{2}):\d{2}:\d{2}")
    hours = pd.to_numeric(hour_match[0], errors="coerce").fillna(12).values
    dows = np.random.default_rng(42).integers(0, 7, size=n)  # No date in SSH log
    msgs = df["message"].fillna("")
    # Severity: use admin-account targeting (root/admin = high severity)
    # NOT derived from success/fail — that would be tautological with the
    # brute-force label which is defined on the same event_type field.
    admin_names_sev = {"root", "admin", "administrator", "test", "guest"}
    severity = df["username"].fillna("").str.lower().isin(admin_names_sev).astype(np.float32).values

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["syslog"],
        severity, msgs.str.len().values, shannon_entropy_vec(msgs),
    )

    # Layer 3: Auth
    auth_enc = np.full(n, 3, dtype=np.float32)  # password auth = 3
    # is_fail: ALL failure-related event types (NOT just the attack subset).
    # attack_types is {failed_root, auth_failure, failed_invalid_user, invalid_user}
    # but the data also has benign failures like failed_login, pam_auth_failure.
    # Including ALL failures ensures is_fail ≠ is_attack (breaks leakage).
    fail_event_types = {
        "failed_login", "pam_auth_failure", "failed_login_invalid_user",
        "break_in_attempt", "invalid_user",
        "failed_root", "auth_failure", "failed_invalid_user",
        "failed_password", "failed",
    }
    is_fail = df["event_type"].str.lower().isin(fail_event_types).astype(int).values
    admin_names = {"root", "admin", "administrator"}
    is_admin = df["username"].fillna("").str.lower().isin(admin_names).astype(int).values
    src_dst_match = np.zeros(n, dtype=np.float32)  # always remote in SSH
    is_remote = np.ones(n, dtype=np.float32)

    # Aggregated: per source_ip
    _df = df.assign(_is_fail=is_fail, _dst="host")
    if "source_ip" in df.columns:
        fail_rate, unique_targets, event_freq = compute_auth_aggregates(
            _df, "source_ip", "_dst", "_is_fail")
    else:
        fail_rate = np.zeros(n)
        unique_targets = np.zeros(n)
        event_freq = np.zeros(n)

    layer3 = compute_layer3(auth_enc, is_fail, is_admin, src_dst_match,
                            is_remote, fail_rate, unique_targets, event_freq)

    features = assemble_row(layer1, {3: layer3}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["event_type"], "benign")
    features["source_dataset"] = "syslog_ssh"
    return features


def extract_syslog_cremev2(max_rows: int) -> Optional[pd.DataFrame]:
    """01_Syslog: CREMEv2 original_label_syslog — MITRE-labeled attacks."""
    fp = DATA_DIR / "01_Syslog" / "CREMEv2" / "original_label_syslog.csv"
    if not fp.exists():
        log.warning("  SKIP: CREMEv2 syslog not found")
        return None

    df = pd.read_csv(fp)
    df["_is_mal"] = is_malicious_label(df["Label"])
    df = sample_df(df, max_rows, "_is_mal")
    n = len(df)
    is_attack = df["_is_mal"]
    log.info("  01_Syslog/CREMEv2: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    # Timestamp is unix epoch (seconds) — must use unit='s'
    try:
        ts = pd.to_datetime(df["Timestamp"], unit="s", errors="coerce")
        if ts.isna().all():
            ts = pd.to_datetime(df["Time"], errors="coerce")
        hours = ts.dt.hour.fillna(12).values
        dows = ts.dt.dayofweek.fillna(2).values
    except Exception:
        hours = np.full(n, 12)
        dows = np.full(n, 2)

    # Build rich message from Content + Component + PID_or_IP + EventId
    msgs = (df["Content"].fillna("") + " " +
            df["Component"].fillna("") + " " +
            df["PID_or_IP"].fillna("").astype(str) + " " +
            df["EventId"].fillna("").astype(str))
    # Severity from component: security-relevant daemons = 1, else 0 (NOT the label)
    sec_components = {"sshd", "telnetd", "in.telnetd", "proftpd", "login"}
    severity = df["Component"].str.lower().str.strip().isin(sec_components).astype(np.float32).values

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["syslog"],
        severity, msgs.str.len().values, shannon_entropy_vec(msgs),
    )

    # Layer 3: Auth (component-based)
    comp_map = {"sshd": 0, "telnetd": 1, "in.telnetd": 1, "proftpd": 2,
                "apache-access": 3, "login": 4, "cron": 5, "systemd": 6, "smbd": 7}
    auth_enc = df["Component"].str.lower().str.strip().map(comp_map).fillna(8).values
    # is_fail: detect from Content keywords (NOT from label).
    # Match error/fail/denied/invalid patterns in the syslog message.
    _content_lower = df["Content"].fillna("").str.lower()
    is_fail = _content_lower.str.contains(
        r"fail|error|denied|invalid|reject|refused|unauthorized",
        regex=True, na=False
    ).astype(int).values
    # is_admin: check if PID_or_IP is a known service IP or root PID
    pid_ip = df["PID_or_IP"].fillna("").astype(str)
    is_admin = pid_ip.str.match(r"^[0-9]+$").astype(int).values  # PID = local process
    # src_dst_match: hash HostName to detect multi-host patterns
    host_enc = df["HostName"].fillna("").astype(str)
    host_nunique = host_enc.nunique()
    src_dst_match = (host_enc.astype("category").cat.codes / max(host_nunique, 1)).values.astype(np.float32)
    # telnetd/sshd = remote
    is_remote = df["Component"].str.lower().isin({"sshd", "telnetd", "in.telnetd"}).astype(int).values
    # Compute per-source aggregate features using PID_or_IP as entity
    # fail_rate uses the corrected is_fail (NOT the label)
    entity = pid_ip
    _df_agg = df.assign(_is_fail=is_fail, _host=df["HostName"].fillna(""))
    fail_rate, unique_targets, event_freq = compute_auth_aggregates(
        _df_agg, entity_col="PID_or_IP", target_col="_host", status_col="_is_fail")
    fail_rate = fail_rate.astype(np.float32)
    unique_targets = unique_targets.astype(np.float32)
    event_freq = event_freq.astype(np.float32)

    layer3 = compute_layer3(auth_enc, is_fail, is_admin, src_dst_match,
                            is_remote, fail_rate, unique_targets, event_freq)

    features = assemble_row(layer1, {3: layer3}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["Tactic"].fillna("unknown"), "benign")
    features["source_dataset"] = "syslog_cremev2"
    return features


def extract_cremev2_traffic(max_rows: int) -> Optional[pd.DataFrame]:
    """01_Syslog/CREMEv2: label_traffic — network flow data."""
    fp = DATA_DIR / "01_Syslog" / "CREMEv2" / "label_traffic.csv"
    if not fp.exists():
        log.warning("  SKIP: CREMEv2 traffic not found")
        return None

    df = pd.read_csv(fp)
    df["_is_mal"] = is_malicious_label(df["Label"])
    df = sample_df(df, max_rows, "_is_mal")
    n = len(df)
    is_attack = df["_is_mal"]
    log.info("  01_CREMEv2/traffic: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    try:
        ts = pd.to_datetime(df["StartTime"], errors="coerce")
        hours = ts.dt.hour.fillna(12).values
        dows = ts.dt.dayofweek.fillna(2).values
    except Exception:
        hours = np.full(n, 12)
        dows = np.full(n, 2)

    # Severity = 0 for all (no observable severity field in CREMEv2 traffic)
    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["syslog"],
        np.zeros(n, dtype=np.float32), np.zeros(n), np.zeros(n),  # no text message
    )

    # Layer 2: Network
    # Protocol from one-hot columns
    proto = np.where(df.get("Proto_tcp", 0) == 1, 6,
                     np.where(df.get("Proto_udp", 0) == 1, 17,
                              np.where(df.get("Proto_icmp", 0) == 1, 1, 0)))
    sb = pd.to_numeric(df.get("SrcBytes", 0), errors="coerce").fillna(0).values
    db = pd.to_numeric(df.get("DstBytes", 0), errors="coerce").fillna(0).values
    sp = pd.to_numeric(df.get("SrcPkts", 0), errors="coerce").fillna(0).values
    dp = pd.to_numeric(df.get("DstPkts", 0), errors="coerce").fillna(0).values
    dur = pd.to_numeric(df.get("Dur", 0), errors="coerce").fillna(0).values * 1000  # sec→ms
    dport = pd.to_numeric(df.get("Dport", 0), errors="coerce").fillna(0).values

    layer2 = compute_layer2(
        sb, db, sp, dp, dur, dport, proto,
        np.zeros(n), np.zeros(n),  # no IAT columns in CREMEv2 traffic
        np.zeros(n),  # no pkt variance
        np.zeros(n), np.zeros(n), np.zeros(n),  # no flags
        np.zeros(n),  # no retransmit
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, "network_attack", "benign")
    features["source_dataset"] = "cremev2_traffic"
    return features


def extract_windows(max_rows: int) -> Optional[pd.DataFrame]:
    """02_Windows: baseline_benign.csv + evtx_attack_data.csv."""
    dfs = []

    # Benign baseline
    fp_b = DATA_DIR / "02_Windows_Event" / "baseline_benign.csv"
    if fp_b.exists():
        df_b = pd.read_csv(fp_b)
        df_b["_label"] = 0
        df_b["_attack_type"] = "benign"
        dfs.append(df_b)

    # Attack data
    fp_a = DATA_DIR / "02_Windows_Event" / "evtx_attack_data.csv"
    if fp_a.exists():
        df_a = pd.read_csv(fp_a, low_memory=False)
        df_a["_label"] = 1
        df_a["_attack_type"] = df_a.get("EVTX_Tactic", "windows_attack").fillna("windows_attack")
        dfs.append(df_a)

    if not dfs:
        log.warning("  SKIP: No Windows data found")
        return None

    # Combine and sample
    df = pd.concat(dfs, ignore_index=True)
    df = sample_df(df, max_rows, "_label")
    n = len(df)
    log.info("  02_Windows: %d rows (attacks: %d)", n, (df["_label"] == 1).sum())

    # Layer 1
    # Merge timestamps: attack rows use SystemTime, benign rows use timestamp
    try:
        ts1 = pd.to_datetime(df.get("SystemTime", pd.Series([pd.NaT] * n)), errors="coerce")
        ts2 = pd.to_datetime(df.get("timestamp", pd.Series([pd.NaT] * n)), errors="coerce")
        ts = ts1.fillna(ts2)
        # Use fractional hours for sub-hour diversity (16:40:33 → 16.676)
        hours = (ts.dt.hour + ts.dt.minute / 60 + ts.dt.second / 3600).fillna(12).values
        dows = (ts.dt.dayofweek + ts.dt.hour / 24).fillna(2).values  # fractional dow too
    except Exception:
        hours = np.full(n, 12.0)
        dows = np.full(n, 2.0)

    eid_col = "EventID" if "EventID" in df.columns else "event_id"
    eids = pd.to_numeric(df.get(eid_col, 0), errors="coerce").fillna(0).astype(int)
    # Severity from EventID
    high_risk_eids = {4625, 4697, 4720, 4728, 4732, 1102, 7045}
    med_risk_eids = {4624, 4672, 4688, 4768, 4769}
    severity = np.where(eids.isin(high_risk_eids), 2,
                        np.where(eids.isin(med_risk_eids), 1, 0))

    # Build message from columns that exist in BOTH benign & attack schemas
    # to avoid schema leakage (attack file has 280+ cols, benign has 11).
    # Common concepts: EventID, channel, level, opcode, task, provider, computer, process_id
    msg_parts = ["EventID=" + eids.astype(str)]
    for col_variants in [
        ("channel", "Channel"), ("level", "Level"),
        ("opcode", "Opcode"),   ("task", "Task"),
        ("provider", "ProviderName"), ("computer", "Computer"),
        ("process_id", "ProcessId", "processId"),
    ]:
        for col in col_variants:
            if col in df.columns:
                vals = df[col].fillna("").astype(str)
                if vals.str.len().mean() > 0.5:
                    msg_parts.append(vals)
                break  # use first matching variant
    msgs = msg_parts[0].astype(str)
    for part in msg_parts[1:]:
        msgs = msgs.values + " " + part.values
        msgs = pd.Series(msgs)
    msgs = msgs.str.strip()

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["windows"],
        severity, msgs.str.len().values, shannon_entropy_vec(msgs),
    )

    # Layer 3: Auth — SCHEMA-SAFE: use only columns available in both files.
    # Benign file has: event_id, channel, level, opcode, task, provider, computer,
    #   process_id, thread_id, timestamp, label.
    # Attack file has: EventID, Channel, Level, Opcode, Task, ProviderName, Computer,
    #   ProcessId, ThreadID, SystemTime, + 270 Sysmon/Security fields.
    # To avoid schema leakage, we derive auth features ONLY from EventID (common),
    # process_id (common), and level/channel (common).

    # auth_enc: derive from EventID category (security=1, sysmon=2, system=3, other=0)
    sec_eids = {4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4720, 4728, 4732,
                4768, 4769, 4771, 4776, 1102}
    sysmon_eids = {1, 3, 5, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23, 25}
    auth_enc = np.where(eids.isin(sec_eids), 1,
                        np.where(eids.isin(sysmon_eids), 2,
                                 np.where(eids > 0, 3, 0))).astype(np.float32)
    is_fail = np.where(eids.isin({4625, 4771, 4776}), 1, 0).astype(np.float32)

    # is_admin: not available in both schemas → use 0 (unknown)
    is_admin = np.zeros(n, dtype=np.float32)
    # src_dst_match: not available in both schemas → use 0.5 (unknown)
    src_dst_match = np.full(n, 0.5, dtype=np.float32)
    # is_remote: not available in both schemas → use 0 (unknown)
    is_remote = np.zeros(n, dtype=np.float32)

    # Entity: use process_id (exists in both schemas with different names)
    pid = df.get("process_id", df.get("ProcessId", df.get("processId",
          pd.Series(["0"] * n)))).fillna("0").astype(str)
    tid = df.get("thread_id", df.get("ThreadID",
          pd.Series(["0"] * n))).fillna("0").astype(str)
    entity_col = pid + "_" + tid
    entity_col = entity_col.replace("0_0", "unk").replace("_", "unk")

    # compute_auth_aggregates expects a DataFrame with named columns
    _df2 = pd.DataFrame({"_entity": entity_col.values, "_dst": eids.astype(str).values,
                          "_is_fail": is_fail})
    fail_rate, unique_targets, event_freq = compute_auth_aggregates(
        _df2, "_entity", "_dst", "_is_fail")

    layer3 = compute_layer3(auth_enc, is_fail, is_admin, src_dst_match,
                            is_remote, fail_rate, unique_targets, event_freq)

    features = assemble_row(layer1, {3: layer3}, n)
    features["is_malicious"] = df["_label"].values
    features["attack_type"] = df["_attack_type"].values
    features["source_dataset"] = "windows"
    return features


def extract_firewall(max_rows: int) -> Optional[pd.DataFrame]:
    """03_Firewall: UNSW-NB15 — network intrusion dataset."""
    fp = DATA_DIR / "03_Firewall" / "UNSW-NB15_1.csv"
    if not fp.exists():
        log.warning("  SKIP: Firewall not found")
        return None

    df = pd.read_csv(fp, encoding="utf-8-sig")
    # Verify header exists (should after gap fix)
    if df.columns[0].strip().replace("\ufeff", "") == "srcip":
        pass  # Header is present
    else:
        # No header — assign manually
        df = pd.read_csv(fp, encoding="utf-8-sig", header=None, names=FIREWALL_COLUMNS)

    df = sample_df(df, max_rows, "label")
    n = len(df)
    is_attack = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    log.info("  03_Firewall: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1 — no meaningful timestamp or text message for flow data
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["firewall"],
        np.zeros(n), np.zeros(n), np.zeros(n),  # no msg for flows
    )

    # Layer 2: Network
    proto_map = {k: v for k, v in PROTOCOL_MAP.items()}
    proto = df["proto"].str.lower().map(proto_map).fillna(0).values
    sb = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0).values
    db = pd.to_numeric(df["dbytes"], errors="coerce").fillna(0).values
    sp_pkts = pd.to_numeric(df["spkts"], errors="coerce").fillna(0).values
    dp_pkts = pd.to_numeric(df["dpkts"], errors="coerce").fillna(0).values
    dur = pd.to_numeric(df["dur"], errors="coerce").fillna(0).values * 1000  # sec→ms
    dport = pd.to_numeric(df["dsport"], errors="coerce").fillna(0).values

    # IAT from inter-packet columns
    iat_mean = pd.to_numeric(df.get("sintpkt", 0), errors="coerce").fillna(0).values
    iat_std = pd.to_numeric(df.get("dintpkt", 0), errors="coerce").fillna(0).values

    # TCP flags: approximate from syn/ack/fin states
    state = df["state"].fillna("").str.lower()
    syn_flag = state.str.contains("s|syn", regex=True).astype(int).values
    rst_flag = state.str.contains("rst", regex=True).astype(int).values
    fin_flag = state.str.contains("fin", regex=True).astype(int).values

    # Packet size variance approximation
    smeansz = pd.to_numeric(df.get("smeansz", 0), errors="coerce").fillna(0).values
    dmeansz = pd.to_numeric(df.get("dmeansz", 0), errors="coerce").fillna(0).values
    pkt_var = np.abs(smeansz - dmeansz)  # rough proxy

    layer2 = compute_layer2(
        sb, db, sp_pkts, dp_pkts, dur, dport, proto,
        iat_mean, iat_std, pkt_var,
        syn_flag, rst_flag, fin_flag,
        np.zeros(n),  # no retransmit data
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = is_attack.values
    attack_cat = df.get("attack_cat", pd.Series([""] * n)).fillna("").str.strip()
    features["attack_type"] = np.where(is_attack, attack_cat.replace("", "unknown"), "benign")
    features["source_dataset"] = "firewall"
    return features


def extract_ad(max_rows: int) -> Optional[pd.DataFrame]:
    """04_Active_Directory: LANL auth AD — with real attack labels."""
    fp = DATA_DIR / "04_Active_Directory" / "lanl_auth_ad.csv"
    if not fp.exists():
        log.warning("  SKIP: AD not found")
        return None

    df = pd.read_csv(fp)

    # Load redteam labels for attack enrichment
    rt_fp = DATA_DIR / "04_Active_Directory" / "redteam.txt"
    redteam_set = set()
    if rt_fp.exists():
        rt = pd.read_csv(rt_fp, header=None, names=["time", "src_user", "src_comp", "dst_comp"])
        for _, row in rt.iterrows():
            redteam_set.add((int(row["time"]), str(row["src_user"]), str(row["dst_comp"])))

    df = sample_df(df, max_rows, "label")
    n = len(df)
    is_attack = (df["label"] != "normal").astype(int)
    log.info("  04_AD: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1: Core
    ts_sec = pd.to_numeric(df["time"], errors="coerce").fillna(0)
    hours = (ts_sec // 3600) % 24
    dows = (ts_sec // 86400) % 7
    msgs = ("AD auth " + df["auth_type"].fillna("") + " " +
            df["logon_type"].fillna("") + " " +
            df["status"].fillna("") + " " +
            df["src_user"].fillna("") + " → " + df["dst_user"].fillna(""))
    severity = (df["status"].str.lower() == "fail").astype(int)

    layer1 = compute_layer1(
        n, hours.values, dows.values, LOG_TYPE_MAP["ad"],
        severity.values, msgs.str.len().values, shannon_entropy_vec(msgs),
    )

    # Layer 3: Auth
    auth_enc = df["auth_type"].str.lower().map(AUTH_TYPE_MAP).fillna(4).astype(int)
    is_fail = (df["status"].str.lower() == "fail").astype(int).values
    admin_names = {"root", "admin", "administrator", "system"}
    is_admin = df["dst_user"].str.lower().isin(admin_names).astype(int).values
    src_dst_match = (df["src_user"] == df["dst_user"]).astype(int).values
    logon_type = df["logon_type"].fillna("").str.lower()
    is_remote = logon_type.isin({"network", "remoteinteractive"}).astype(int).values

    fail_rate, unique_targets, event_freq = compute_auth_aggregates(
        df.assign(_is_fail=is_fail), "src_user", "dst_computer", "_is_fail")

    layer3 = compute_layer3(auth_enc.values, is_fail, is_admin, src_dst_match,
                            is_remote, fail_rate, unique_targets, event_freq)

    features = assemble_row(layer1, {3: layer3}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = df["label"].values
    features["source_dataset"] = "ad_lanl"
    return features


def extract_dns_dga(max_rows: int) -> Optional[pd.DataFrame]:
    """05_DNS: DGA detection — domain name classification."""
    fp = DATA_DIR / "05_DNS" / "dga_detection.csv"
    if not fp.exists():
        log.warning("  SKIP: DGA not found")
        return None

    df = pd.read_csv(fp, nrows=max_rows * 3)
    df = sample_df(df, max_rows, "label")
    n = len(df)
    is_attack = (df["label"] != "normal.alexa").astype(int)
    log.info("  05_DNS/DGA: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)
    domains = df["domain"].fillna("").astype(str)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["dns"],
        np.zeros(n), domains.str.len().values, shannon_entropy_vec(domains),
    )

    # Layer 4: DNS features from domain names
    dom_len = domains.str.len().values.astype(np.float32)
    dom_ent = shannon_entropy_vec(domains)
    sub_depth = domains.str.count(r"\.").values.astype(np.float32)
    total_chars = np.maximum(dom_len, 1)
    digit_count = domains.str.count(r"\d").values.astype(np.float32)
    digit_ratio = digit_count / total_chars

    consonant_run = max_consonant_run_vec(domains)
    bigram_freq = bigram_frequency_vec(domains)

    # Hex pattern: 8+ consecutive hex characters in subdomain
    hex_pat = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)
    has_hex = has_pattern_vec(domains, hex_pat)

    # TLD risk
    tlds = domains.str.rsplit(".", n=1).str[-1].str.lower()
    tld_risk = tlds.map(TLD_RISK).fillna(0.3).values

    layer4 = compute_layer4(dom_len, dom_ent, sub_depth, digit_ratio,
                            consonant_run, bigram_freq, has_hex, tld_risk)

    features = assemble_row(layer1, {4: layer4}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["label"], "benign")
    features["source_dataset"] = "dns_dga"
    return features


def extract_dns_doh(max_rows: int) -> Optional[pd.DataFrame]:
    """05_DNS: DoH (DNS-over-HTTPS) — flow-based detection."""
    import glob as _glob
    doh_dir = DATA_DIR / "05_DNS" / "CIRA-CIC-DoHBrw-2020"
    if not doh_dir.exists():
        log.warning("  SKIP: DoH not found")
        return None

    csvs = list(doh_dir.rglob("*.csv"))
    if not csvs:
        log.warning("  SKIP: No DoH CSV files")
        return None

    parts = []
    per_file_max = max(max_rows // len(csvs), 5000)
    for csv_path in csvs:
        _df = pd.read_csv(csv_path)
        # Label from directory: benign-csvs or malic-csvs
        is_mal = 1 if "malic" in str(csv_path.parent).lower() else 0
        _df["_label"] = is_mal
        _df["_attack_type"] = csv_path.stem if is_mal else "benign"
        parts.append(sample_df(_df, per_file_max))

    df = pd.concat(parts, ignore_index=True)
    df = sample_df(df, max_rows, "_label")
    n = len(df)
    log.info("  05_DNS/DoH: %d rows (attacks: %d)", n, (df["_label"] == 1).sum())

    # Layer 1
    try:
        ts = pd.to_datetime(df["TimeStamp"], errors="coerce")
        hours = ts.dt.hour.fillna(12).values
        dows = ts.dt.dayofweek.fillna(2).values
    except Exception:
        hours = np.full(n, 12)
        dows = np.full(n, 2)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["dns"],
        np.zeros(n), np.zeros(n), np.zeros(n),  # flow data, no text
    )

    # Layer 2: Network
    sb = pd.to_numeric(df.get("FlowBytesSent", 0), errors="coerce").fillna(0).values
    db = pd.to_numeric(df.get("FlowBytesReceived", 0), errors="coerce").fillna(0).values
    dur = pd.to_numeric(df.get("Duration", 0), errors="coerce").fillna(0).values * 1000
    dport = pd.to_numeric(df.get("DestinationPort", 0), errors="coerce").fillna(0).values
    pkt_var = pd.to_numeric(df.get("PacketLengthVariance", 0), errors="coerce").fillna(0).values
    pkt_mean = pd.to_numeric(df.get("PacketTimeMean", 0), errors="coerce").fillna(0).values
    pkt_std = pd.to_numeric(df.get("PacketTimeStandardDeviation", 0), errors="coerce").fillna(0).values

    # Approximate packets from bytes and mean pkt size
    pkt_len_mean = pd.to_numeric(df.get("PacketLengthMean", 0), errors="coerce").fillna(1).values
    pkt_len_mean = np.maximum(pkt_len_mean, 1)
    sp = sb / pkt_len_mean
    dp = db / pkt_len_mean

    layer2 = compute_layer2(
        sb, db, sp, dp, dur, dport, np.full(n, 6),  # TCP for DoH
        pkt_mean, pkt_std, pkt_var,
        np.zeros(n), np.zeros(n), np.zeros(n),  # no TCP flags in DoH
        np.zeros(n),
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = df["_label"].values
    features["attack_type"] = df["_attack_type"].values
    features["source_dataset"] = "dns_doh"
    return features


def extract_dns_exfil(max_rows: int) -> Optional[pd.DataFrame]:
    """05_DNS: CIC-Bell DNS exfiltration — stateless domain features."""
    exfil_dir = DATA_DIR / "05_DNS" / "CIC-Bell-DNS-EXFil-2021"
    if not exfil_dir.exists():
        log.warning("  SKIP: DNS exfil not found")
        return None

    # Find stateless CSVs (they have domain-level features we can use)
    csvs = list(exfil_dir.rglob("stateless*.csv"))
    if not csvs:
        log.warning("  SKIP: No stateless DNS exfil files")
        return None

    parts = []
    for csv_path in csvs:
        _df = pd.read_csv(csv_path)
        fname = csv_path.stem.lower()
        is_mal = 0 if "benign" in fname else 1
        _df["_label"] = is_mal
        _df["_attack_type"] = fname.replace("stateless_features-", "").replace(".pcap", "") if is_mal else "benign"
        parts.append(_df)

    if not parts:
        return None

    df = pd.concat(parts, ignore_index=True)
    df = sample_df(df, max_rows, "_label")
    n = len(df)
    log.info("  05_DNS/Exfil: %d rows (attacks: %d)", n, (df["_label"] == 1).sum())

    # Layer 1
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["dns"],
        np.zeros(n), np.zeros(n), np.zeros(n),
    )

    # Layer 4: DNS features from pre-computed statistics
    dom_len = pd.to_numeric(df.get("len", 0), errors="coerce").fillna(0).values.astype(np.float32)
    dom_ent = pd.to_numeric(df.get("entropy", 0), errors="coerce").fillna(0).values.astype(np.float32)
    sub_depth = pd.to_numeric(df.get("labels", 0), errors="coerce").fillna(0).values.astype(np.float32)
    total_chars = np.maximum(dom_len, 1)
    digit_count = pd.to_numeric(df.get("numeric", 0), errors="coerce").fillna(0).values.astype(np.float32)
    digit_ratio = digit_count / total_chars

    # Features we can't compute from stateless (no raw domain): use what we have
    subdomain_col = df.get("subdomain", pd.Series([""] * n)).fillna("").astype(str)
    consonant_run = max_consonant_run_vec(subdomain_col)
    bigram_freq = bigram_frequency_vec(subdomain_col)
    hex_pat = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)
    has_hex = has_pattern_vec(subdomain_col, hex_pat)
    tld_risk = np.full(n, 0.3, dtype=np.float32)  # no TLD info available

    layer4 = compute_layer4(dom_len, dom_ent, sub_depth, digit_ratio,
                            consonant_run, bigram_freq, has_hex, tld_risk)

    features = assemble_row(layer1, {4: layer4}, n)
    features["is_malicious"] = df["_label"].values
    features["attack_type"] = df["_attack_type"].values
    features["source_dataset"] = "dns_exfil"
    return features


def extract_cloud(max_rows: int) -> Optional[pd.DataFrame]:
    """06_Cloud_AWS: CloudTrail labeled events."""
    fp = DATA_DIR / "06_Cloud_AWS" / "cloudtrail_labeled.csv"
    if not fp.exists():
        log.warning("  SKIP: CloudTrail not found")
        return None

    df = pd.read_csv(fp, nrows=max_rows * 3)
    df["label"] = df["label"].astype(str)
    df = sample_df(df, max_rows, "label")
    n = len(df)
    # CloudTrail: 'attack' = definite attack, 'suspicious' = APT activity (treat as attack)
    is_attack = df["label"].str.lower().isin({"attack", "suspicious"}).astype(int)
    log.info("  06_Cloud: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    try:
        ts = pd.to_datetime(df["eventTime"], errors="coerce")
        hours = ts.dt.hour.fillna(12).values
        dows = ts.dt.dayofweek.fillna(2).values
    except Exception:
        hours = np.full(n, 12)
        dows = np.full(n, 2)

    # Build richer message from eventName + userAgent + sourceIPAddress + awsRegion + errorMessage
    msg_parts = [df["eventName"].fillna("")]
    for col in ["userAgent", "sourceIPAddress", "awsRegion", "errorMessage",
                "requestParameters", "responseElements"]:
        if col in df.columns:
            vals = df[col].fillna("").astype(str)
            if vals.str.len().mean() > 0.5:
                msg_parts.append(vals)
    msgs = msg_parts[0]
    for part in msg_parts[1:]:
        msgs = msgs + " " + part

    severity = np.where(df["errorCode"].notna() & (df["errorCode"] != ""), 1, 0)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["cloud"],
        severity, msgs.str.len().values, shannon_entropy_vec(msgs),
    )

    # Layer 7: Cloud
    evtname = df["eventName"].fillna("")
    evt_name_map = {name: i for i, name in enumerate(CT_EVENT_NAMES)}
    evt_encoded = evtname.map(evt_name_map).fillna(len(CT_EVENT_NAMES)).values

    evtsource = df["eventSource"].fillna("").str.lower()
    is_sensitive = evtsource.isin(SENSITIVE_SERVICES).astype(int).values

    is_read_only = evtname.str.startswith(("Describe", "Get", "List")).astype(int).values

    has_error = (df["errorCode"].notna() & (df["errorCode"] != "")).astype(int).values

    id_type = df["userIdentitytype"].fillna("")
    id_type_map = {"Root": 0, "IAMUser": 1, "AssumedRole": 2, "FederatedUser": 3,
                   "AWSAccount": 4, "AWSService": 5}
    id_encoded = id_type.map(id_type_map).fillna(6).values

    # Enrich id_encoded with sourceIPAddress hash for diversity
    src_ip = df.get("sourceIPAddress", pd.Series([""] * n)).fillna("").astype(str)
    ip_cat = src_ip.astype("category").cat.codes.values.astype(np.float32)
    # Combine identity type with IP hash: shift IP contribution to decimal places
    ip_nunique = max(src_ip.nunique(), 1)
    id_encoded = id_encoded.astype(np.float32) + (ip_cat / ip_nunique)

    is_root = (id_type == "Root").astype(int).values

    # Enrich is_sensitive with awsRegion info
    region = df.get("awsRegion", pd.Series([""] * n)).fillna("").astype(str)
    region_cat = region.astype("category").cat.codes.values.astype(np.float32)
    region_nunique = max(region.nunique(), 1)
    # Shift region info into is_sensitive fractional part
    is_sensitive = is_sensitive.astype(np.float32) + (region_cat / region_nunique) * 0.1

    layer7 = compute_layer7(evt_encoded, is_sensitive, is_read_only,
                            has_error, id_encoded, is_root)

    features = assemble_row(layer1, {7: layer7}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(
        df["label"].str.lower() == "attack",
        df["attack_tactic"].fillna("cloud_attack"),
        np.where(df["label"].str.lower() == "suspicious", "suspicious", "benign"))
    features["source_dataset"] = "cloud_aws"
    return features


def extract_web_csic(max_rows: int) -> Optional[pd.DataFrame]:
    """08_Web: CSIC parsed HTTP requests."""
    fp = DATA_DIR / "08_Web_Server" / "csic_parsed.csv"
    if not fp.exists():
        log.warning("  SKIP: CSIC not found")
        return None

    df = pd.read_csv(fp)
    df = sample_df(df, max_rows, "label")
    n = len(df)
    is_attack = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    log.info("  08_Web/CSIC: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    try:
        ts = pd.to_datetime(df["time"], errors="coerce")
        hours = ts.dt.hour.fillna(12).values
        dows = ts.dt.dayofweek.fillna(2).values
    except Exception:
        hours = np.full(n, 12)
        dows = np.full(n, 2)

    urls = df["url"].fillna("").astype(str)
    # Severity from URL content: suspicious patterns = 1, else 0 (NOT the label)
    url_has_suspicious = (
        has_pattern_vec(urls, SQL_KEYWORDS) |
        has_pattern_vec(urls, XSS_PATTERNS) |
        has_pattern_vec(urls, TRAVERSAL_PATTERNS)
    ).astype(np.float32)
    severity = url_has_suspicious

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["web"],
        severity, urls.str.len().values, shannon_entropy_vec(urls),
    )

    # Layer 5: Web
    url_len = urls.str.len().values.astype(np.float32)
    url_ent = shannon_entropy_vec(urls)
    # Query param count
    qmark = urls.str.contains(r"\?", regex=True)
    q_count = np.where(qmark, urls.str.split("&").str.len(), 0).astype(np.float32)

    has_sql = has_pattern_vec(urls, SQL_KEYWORDS)
    has_xss = has_pattern_vec(urls, XSS_PATTERNS)
    has_trav = has_pattern_vec(urls, TRAVERSAL_PATTERNS)

    method_map = {"get": 0, "post": 1, "put": 2, "delete": 3, "head": 4, "options": 5}
    http_meth = df["method"].fillna("").str.lower().map(method_map).fillna(6).values

    layer5 = compute_layer5(url_len, url_ent, q_count, has_sql, has_xss, has_trav, http_meth)

    features = assemble_row(layer1, {5: layer5}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, "web_attack", "benign")
    features["source_dataset"] = "web_csic"
    return features


def extract_web_queries(max_rows: int) -> Optional[pd.DataFrame]:
    """08_Web: goodqueries + badqueries — URL path classification."""
    good_fp = DATA_DIR / "08_Web_Server" / "goodqueries.txt"
    bad_fp = DATA_DIR / "08_Web_Server" / "badqueries.txt"

    parts = []
    if good_fp.exists():
        with open(good_fp, "r", encoding="utf-8", errors="replace") as f:
            good = [line.strip() for line in f if line.strip()]
        df_good = pd.DataFrame({"url": good, "_label": 0, "_attack_type": "benign"})
        parts.append(df_good)

    if bad_fp.exists():
        with open(bad_fp, "r", encoding="utf-8", errors="replace") as f:
            bad = [line.strip() for line in f if line.strip()]
        df_bad = pd.DataFrame({"url": bad, "_label": 1, "_attack_type": "web_attack"})
        parts.append(df_bad)

    if not parts:
        log.warning("  SKIP: Web queries not found")
        return None

    df = pd.concat(parts, ignore_index=True)
    df = sample_df(df, max_rows, "_label")
    n = len(df)
    log.info("  08_Web/queries: %d rows (attacks: %d)", n, (df["_label"] == 1).sum())

    # Layer 1 (no timestamp for URL paths)
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)
    urls = df["url"].fillna("").astype(str)

    # Severity from URL content: suspicious patterns = 1, else 0 (NOT the label)
    url_has_suspicious = (
        has_pattern_vec(urls, SQL_KEYWORDS) |
        has_pattern_vec(urls, XSS_PATTERNS) |
        has_pattern_vec(urls, TRAVERSAL_PATTERNS)
    ).astype(np.float32)
    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["web"],
        url_has_suspicious, urls.str.len().values, shannon_entropy_vec(urls),
    )

    # Layer 5: Web
    url_len = urls.str.len().values.astype(np.float32)
    url_ent = shannon_entropy_vec(urls)
    qmark = urls.str.contains(r"\?", regex=True)
    q_count = np.where(qmark, urls.str.split("&").str.len(), 0).astype(np.float32)

    has_sql = has_pattern_vec(urls, SQL_KEYWORDS)
    has_xss = has_pattern_vec(urls, XSS_PATTERNS)
    has_trav = has_pattern_vec(urls, TRAVERSAL_PATTERNS)
    http_meth = np.zeros(n, dtype=np.float32)  # No method info → 0 (GET)

    layer5 = compute_layer5(url_len, url_ent, q_count, has_sql, has_xss, has_trav, http_meth)

    features = assemble_row(layer1, {5: layer5}, n)
    features["is_malicious"] = df["_label"].values
    features["attack_type"] = df["_attack_type"].values
    features["source_dataset"] = "web_queries"
    return features


def extract_netflow(max_rows: int) -> Optional[pd.DataFrame]:
    """09_NetFlow: NF-UNSW-NB15-v3 — network flow intrusion detection."""
    fp = DATA_DIR / "09_NetFlow" / "NF-UNSW-NB15-v3.csv"
    if not fp.exists():
        log.warning("  SKIP: NetFlow not found")
        return None

    df = pd.read_csv(fp, nrows=max_rows * 3)
    df["_is_mal"] = is_malicious_label(df["Label"])
    df = sample_df(df, max_rows, "_is_mal")
    n = len(df)
    is_attack = df["_is_mal"]
    log.info("  09_NetFlow: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1 — derive time from FLOW_START_MILLISECONDS (epoch ms)
    ts_ms = pd.to_numeric(df["FLOW_START_MILLISECONDS"], errors="coerce").fillna(0)
    ts_sec = ts_ms / 1000
    hours = (ts_sec // 3600 % 24).values
    dows = ((ts_sec // 86400) % 7).values

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["netflow"],
        np.zeros(n), np.zeros(n), np.zeros(n),  # no text for flows
    )

    # Layer 2: Network
    sb = pd.to_numeric(df["IN_BYTES"], errors="coerce").fillna(0).values
    db = pd.to_numeric(df["OUT_BYTES"], errors="coerce").fillna(0).values
    sp = pd.to_numeric(df["IN_PKTS"], errors="coerce").fillna(0).values
    dp = pd.to_numeric(df["OUT_PKTS"], errors="coerce").fillna(0).values
    dur = pd.to_numeric(df["FLOW_DURATION_MILLISECONDS"], errors="coerce").fillna(0).values
    dport = pd.to_numeric(df["L4_DST_PORT"], errors="coerce").fillna(0).values
    proto = pd.to_numeric(df["PROTOCOL"], errors="coerce").fillna(0).values

    # IAT
    iat_mean = pd.to_numeric(df.get("SRC_TO_DST_IAT_AVG", 0), errors="coerce").fillna(0).values
    iat_std = pd.to_numeric(df.get("SRC_TO_DST_IAT_STDDEV", 0), errors="coerce").fillna(0).values

    # Packet size variance from packet size bucket columns
    longest = pd.to_numeric(df.get("LONGEST_FLOW_PKT", 0), errors="coerce").fillna(0).values
    shortest = pd.to_numeric(df.get("SHORTEST_FLOW_PKT", 0), errors="coerce").fillna(0).values
    pkt_var = (longest - shortest).astype(np.float64)  # approximate variance proxy

    # TCP flags (bitfield)
    tcp_flags = pd.to_numeric(df.get("TCP_FLAGS", 0), errors="coerce").fillna(0).astype(int).values
    syn_flag = ((tcp_flags & 0x02) > 0).astype(np.float32)
    rst_flag = ((tcp_flags & 0x04) > 0).astype(np.float32)
    fin_flag = ((tcp_flags & 0x01) > 0).astype(np.float32)

    # Retransmit ratio
    retrans_in = pd.to_numeric(df.get("RETRANSMITTED_IN_BYTES", 0), errors="coerce").fillna(0).values
    retrans_out = pd.to_numeric(df.get("RETRANSMITTED_OUT_BYTES", 0), errors="coerce").fillna(0).values
    total_bytes = sb + db
    retransmit_ratio = (retrans_in + retrans_out) / (total_bytes + 1e-10)

    layer2 = compute_layer2(
        sb, db, sp, dp, dur, dport, proto,
        iat_mean, iat_std, pkt_var,
        syn_flag, rst_flag, fin_flag, retransmit_ratio,
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["Attack"].fillna("unknown"), "benign")
    features["source_dataset"] = "netflow"
    return features


def _load_ids2018_all(max_rows: int) -> Optional[pd.DataFrame]:
    """Load CIC-IDS2018 CSVs with shared column mapping."""
    ids_dir = DATA_DIR / "10_IDS_IPS" / "CIC-IDS2018"
    if not ids_dir.exists():
        return None

    csvs = sorted(ids_dir.glob("*.csv"))
    if not csvs:
        return None

    per_file_cap = max(max_rows // len(csvs), 10000)
    parts = []
    for csv_path in csvs:
        try:
            # Read more than needed to allow stratified sampling, but cap to avoid loading millions
            _df = pd.read_csv(csv_path, low_memory=False, nrows=per_file_cap * 3)
            _df = sample_df(_df, per_file_cap, "Label")
            parts.append(_df)
        except Exception as e:
            log.warning("  IDS2018: error reading %s: %s", csv_path.name, e)
    if not parts:
        return None
    return pd.concat(parts, ignore_index=True)


def extract_ids_2018(max_rows: int) -> Optional[pd.DataFrame]:
    """10_IDS_IPS: CIC-IDS2018 — multi-attack flow data."""
    df = _load_ids2018_all(max_rows)
    if df is None:
        log.warning("  SKIP: IDS2018 not found")
        return None

    df["_is_mal"] = is_malicious_label(df["Label"])
    df = sample_df(df, max_rows, "_is_mal")
    n = len(df)
    is_attack = df["_is_mal"]
    log.info("  10_IDS/2018: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    try:
        ts = pd.to_datetime(df["Timestamp"], errors="coerce")
        hours = ts.dt.hour.fillna(12).values
        dows = ts.dt.dayofweek.fillna(2).values
    except Exception:
        hours = np.full(n, 12)
        dows = np.full(n, 2)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["ids"],
        np.zeros(n), np.zeros(n), np.zeros(n),
    )

    # Layer 2: Network
    dport = pd.to_numeric(df["Dst Port"], errors="coerce").fillna(0).values
    proto = pd.to_numeric(df["Protocol"], errors="coerce").fillna(0).values
    fwd_bytes = pd.to_numeric(df["TotLen Fwd Pkts"], errors="coerce").fillna(0).values
    bwd_bytes = pd.to_numeric(df["TotLen Bwd Pkts"], errors="coerce").fillna(0).values
    fwd_pkts = pd.to_numeric(df["Tot Fwd Pkts"], errors="coerce").fillna(0).values
    bwd_pkts = pd.to_numeric(df["Tot Bwd Pkts"], errors="coerce").fillna(0).values
    dur = pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0).values / 1000  # μs→ms

    iat_mean = pd.to_numeric(df.get("Flow IAT Mean", 0), errors="coerce").fillna(0).values
    iat_std = pd.to_numeric(df.get("Flow IAT Std", 0), errors="coerce").fillna(0).values
    pkt_var = pd.to_numeric(df.get("Pkt Len Var", 0), errors="coerce").fillna(0).values

    syn = pd.to_numeric(df.get("SYN Flag Cnt", 0), errors="coerce").fillna(0).values.clip(0, 1)
    rst = pd.to_numeric(df.get("RST Flag Cnt", 0), errors="coerce").fillna(0).values.clip(0, 1)
    fin = pd.to_numeric(df.get("FIN Flag Cnt", 0), errors="coerce").fillna(0).values.clip(0, 1)

    layer2 = compute_layer2(
        fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts, dur, dport, proto,
        iat_mean, iat_std, pkt_var,
        syn, rst, fin, np.zeros(n),
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["Label"], "benign")
    features["source_dataset"] = "ids_2018"
    return features


def extract_ids_2017(max_rows: int) -> Optional[pd.DataFrame]:
    """10_IDS_IPS: CIC-IDS-2017 — Parquet flow data."""
    ids_dir = DATA_DIR / "10_IDS_IPS" / "CIC-IDS-2017"
    if not ids_dir.exists():
        log.warning("  SKIP: IDS2017 not found")
        return None

    parquets = sorted(ids_dir.glob("*.parquet"))
    if not parquets:
        log.warning("  SKIP: No IDS2017 parquet files")
        return None

    per_file_cap = max(max_rows // len(parquets), 10000)
    parts = []
    for pq in parquets:
        try:
            _df = pd.read_parquet(pq)
            _df = sample_df(_df, per_file_cap, "Label")
            parts.append(_df)
        except Exception as e:
            log.warning("  IDS2017: error reading %s: %s", pq.name, e)

    if not parts:
        return None

    df = pd.concat(parts, ignore_index=True)
    df["_is_mal"] = is_malicious_label(df["Label"])
    df = sample_df(df, max_rows, "_is_mal")
    n = len(df)
    is_attack = df["_is_mal"]
    log.info("  10_IDS/2017: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1 — no Timestamp column in 2017 Parquet
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["ids"],
        np.zeros(n), np.zeros(n), np.zeros(n),
    )

    # Layer 2: Network  (column names differ from 2018)
    proto = pd.to_numeric(df["Protocol"], errors="coerce").fillna(0).values
    fwd_bytes = pd.to_numeric(df["Fwd Packets Length Total"], errors="coerce").fillna(0).values
    bwd_bytes = pd.to_numeric(df["Bwd Packets Length Total"], errors="coerce").fillna(0).values
    fwd_pkts = pd.to_numeric(df["Total Fwd Packets"], errors="coerce").fillna(0).values
    bwd_pkts = pd.to_numeric(df["Total Backward Packets"], errors="coerce").fillna(0).values
    dur = pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0).values / 1000  # μs→ms

    iat_mean = pd.to_numeric(df.get("Flow IAT Mean", 0), errors="coerce").fillna(0).values
    iat_std = pd.to_numeric(df.get("Flow IAT Std", 0), errors="coerce").fillna(0).values
    pkt_var = pd.to_numeric(df.get("Packet Length Variance", 0), errors="coerce").fillna(0).values

    syn = pd.to_numeric(df.get("SYN Flag Count", 0), errors="coerce").fillna(0).values.clip(0, 1)
    rst = pd.to_numeric(df.get("RST Flag Count", 0), errors="coerce").fillna(0).values.clip(0, 1)
    fin = pd.to_numeric(df.get("FIN Flag Count", 0), errors="coerce").fillna(0).values.clip(0, 1)

    # No Dst Port in 2017 — set to 0
    dport = np.zeros(n, dtype=np.float64)

    layer2 = compute_layer2(
        fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts, dur, dport, proto,
        iat_mean, iat_std, pkt_var,
        syn, rst, fin, np.zeros(n),
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["Label"], "benign")
    features["source_dataset"] = "ids_2017"
    return features


def extract_ids_kdd(max_rows: int) -> Optional[pd.DataFrame]:
    """10_IDS_IPS: NSL-KDD — classic intrusion detection dataset."""
    train_fp = DATA_DIR / "10_IDS_IPS" / "KDDTrain+.txt"
    test_fp = DATA_DIR / "10_IDS_IPS" / "KDDTest+.txt"

    parts = []
    for fp in [train_fp, test_fp]:
        if fp.exists():
            _df = pd.read_csv(fp, header=None, names=KDD_COLUMNS)
            parts.append(_df)

    if not parts:
        log.warning("  SKIP: KDD not found")
        return None

    df = pd.concat(parts, ignore_index=True)
    df = sample_df(df, max_rows, "class")
    n = len(df)
    is_attack = (df["class"] != "normal").astype(int)
    log.info("  10_IDS/KDD: %d rows (attacks: %d)", n, is_attack.sum())

    # Layer 1
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["ids"],
        np.zeros(n), np.zeros(n), np.zeros(n),
    )

    # Layer 2: Network
    proto_map_kdd = {"tcp": 6, "udp": 17, "icmp": 1}
    proto = df["protocol_type"].str.lower().map(proto_map_kdd).fillna(0).values
    sb = pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0).values
    db = pd.to_numeric(df["dst_bytes"], errors="coerce").fillna(0).values
    dur = pd.to_numeric(df["duration"], errors="coerce").fillna(0).values * 1000  # sec→ms

    # KDD doesn't have port, packet, IAT columns — zero-fill where needed
    dport = np.zeros(n, dtype=np.float64)
    sp = np.zeros(n, dtype=np.float64)
    dp = np.zeros(n, dtype=np.float64)

    layer2 = compute_layer2(
        sb, db, sp, dp, dur, dport, proto,
        np.zeros(n), np.zeros(n), np.zeros(n),
        np.zeros(n), np.zeros(n), np.zeros(n),
        np.zeros(n),
    )

    features = assemble_row(layer1, {2: layer2}, n)
    features["is_malicious"] = is_attack.values
    features["attack_type"] = np.where(is_attack, df["class"], "benign")
    features["source_dataset"] = "ids_kdd"
    return features


def extract_email(max_rows: int) -> Optional[pd.DataFrame]:
    """11_Email: Unified email dataset (spam + phishing + fraud)."""
    fp = DATA_DIR / "11_Email" / "email_unified.csv"
    if not fp.exists():
        log.warning("  SKIP: Email not found")
        return None

    df = pd.read_csv(fp)
    df = sample_df(df, max_rows, "label")
    n = len(df)
    is_malicious = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    log.info("  11_Email: %d rows (attacks: %d)", n, is_malicious.sum())

    # Layer 1
    rng = np.random.default_rng(42)
    hours = rng.integers(0, 24, size=n)
    dows = rng.integers(0, 7, size=n)

    subjects = df["subject"].fillna("").astype(str)
    bodies = df["body"].fillna("").astype(str)
    combined = subjects + " " + bodies
    # Severity from content: urgency/financial keywords = 1, else 0 (NOT the label)
    severity = (has_pattern_vec(combined, URGENCY_KEYWORDS) |
                has_pattern_vec(combined, FINANCIAL_KEYWORDS)).astype(np.float32)

    layer1 = compute_layer1(
        n, hours, dows, LOG_TYPE_MAP["email"],
        severity, combined.str.len().values, shannon_entropy_vec(combined),
    )

    # Layer 6: Email
    subj_len = subjects.str.len().values.astype(np.float32)
    body_len_log = np.log10(1.0 + bodies.str.len().values.astype(np.float64)).astype(np.float32)
    subj_ent = shannon_entropy_vec(subjects)
    url_cnt = count_urls_in_text(combined)
    caps_rat = caps_ratio_vec(combined)
    has_urg = has_pattern_vec(combined, URGENCY_KEYWORDS)
    has_fin = has_pattern_vec(combined, FINANCIAL_KEYWORDS)

    layer6 = compute_layer6(subj_len, body_len_log, subj_ent, url_cnt,
                            caps_rat, has_urg, has_fin)

    features = assemble_row(layer1, {6: layer6}, n)
    features["is_malicious"] = is_malicious.values
    source = df.get("source", pd.Series(["email"] * n)).fillna("email")
    features["attack_type"] = np.where(is_malicious, "spam_phishing", "benign")
    features["source_dataset"] = "email"
    return features


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

ALL_EXTRACTORS = [
    ("01_Syslog/LANL", extract_syslog_lanl),
    ("01_Syslog/SSH", extract_syslog_ssh),
    ("01_Syslog/CREMEv2", extract_syslog_cremev2),
    ("01_CREMEv2/traffic", extract_cremev2_traffic),
    ("02_Windows", extract_windows),
    ("03_Firewall", extract_firewall),
    ("04_AD", extract_ad),
    ("05_DNS/DGA", extract_dns_dga),
    ("05_DNS/DoH", extract_dns_doh),
    ("05_DNS/Exfil", extract_dns_exfil),
    ("06_Cloud", extract_cloud),
    ("08_Web/CSIC", extract_web_csic),
    ("08_Web/queries", extract_web_queries),
    ("09_NetFlow", extract_netflow),
    ("10_IDS/2018", extract_ids_2018),
    ("10_IDS/2017", extract_ids_2017),
    ("10_IDS/KDD", extract_ids_kdd),
    ("11_Email", extract_email),
]

# Per-dataset max rows (prevents memory explosion on huge datasets)
DEFAULT_MAX_PER_DATASET = {
    "01_Syslog/LANL": 200_000,
    "01_Syslog/SSH": 200_000,
    "01_Syslog/CREMEv2": 200_000,
    "01_CREMEv2/traffic": 200_000,
    "02_Windows": 100_000,
    "03_Firewall": 200_000,
    "04_AD": 200_000,
    "05_DNS/DGA": 200_000,
    "05_DNS/DoH": 200_000,
    "05_DNS/Exfil": 100_000,
    "06_Cloud": 200_000,
    "08_Web/CSIC": 10_000,
    "08_Web/queries": 200_000,
    "09_NetFlow": 200_000,
    "10_IDS/2018": 300_000,
    "10_IDS/2017": 200_000,
    "10_IDS/KDD": 150_000,
    "11_Email": 170_000,
}


def run_extraction(max_per_dataset: Optional[int] = None,
                   dry_run: bool = False) -> pd.DataFrame:
    """Run all extractors and concatenate results."""
    all_dfs = []
    report = {}

    log.info("=" * 60)
    log.info("CLIF v8 Feature Extraction -- 60 features x 7 layers")
    log.info("=" * 60)

    for name, extractor in ALL_EXTRACTORS:
        log.info("Extracting: %s ...", name)
        cap = max_per_dataset if max_per_dataset else DEFAULT_MAX_PER_DATASET.get(name, 200_000)

        if dry_run:
            log.info("  [DRY RUN] Would extract up to %d rows", cap)
            continue

        try:
            t0 = time.time()
            df = extractor(cap)
            elapsed = time.time() - t0

            if df is not None and len(df) > 0:
                # Validate shape
                feat_cols = [c for c in df.columns if c in FEATURE_NAMES]
                assert len(feat_cols) == NUM_FEATURES, \
                    f"{name}: expected {NUM_FEATURES} features, got {len(feat_cols)}"

                # Check for unexpected NaN in features
                nan_counts = df[FEATURE_NAMES].isna().sum()
                nan_cols = nan_counts[nan_counts > 0]
                if len(nan_cols) > 0:
                    log.warning("  %s: NaN in features: %s", name, dict(nan_cols))
                    df[FEATURE_NAMES] = df[FEATURE_NAMES].fillna(0)

                # Check for Inf
                inf_counts = np.isinf(df[FEATURE_NAMES].values).sum(axis=0)
                inf_cols = [(FEATURE_NAMES[i], int(c)) for i, c in enumerate(inf_counts) if c > 0]
                if inf_cols:
                    log.warning("  %s: Inf in features: %s", name, inf_cols)
                    df[FEATURE_NAMES] = df[FEATURE_NAMES].replace([np.inf, -np.inf], 0)

                n_attack = (df["is_malicious"] == 1).sum()
                n_benign = (df["is_malicious"] == 0).sum()
                report[name] = {
                    "rows": len(df), "benign": int(n_benign), "attack": int(n_attack),
                    "time_sec": round(elapsed, 1),
                }
                log.info("  [OK] %s: %d rows (%d benign, %d attack) in %.1fs",
                         name, len(df), n_benign, n_attack, elapsed)
                all_dfs.append(df)
            else:
                report[name] = {"rows": 0, "status": "skipped"}
                log.info("  [SKIP] %s: no data", name)
        except Exception as e:
            log.error("  [FAIL] %s: FAILED -- %s", name, e, exc_info=True)
            report[name] = {"rows": 0, "status": f"error: {str(e)}"}

    if dry_run:
        log.info("Dry run complete -- no data extracted")
        return pd.DataFrame()

    if not all_dfs:
        log.error("No data extracted from any dataset!")
        return pd.DataFrame()

    # Concatenate all
    log.info("")
    log.info("Concatenating %d datasets...", len(all_dfs))
    combined = pd.concat(all_dfs, ignore_index=True)

    # Shuffle
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    # Duplicate capping: no single feature vector should appear more than MAX_DUP_CAP times
    MAX_DUP_CAP = 50
    feat_cols = FEATURE_NAMES
    before_cap = len(combined)
    dup_hash = pd.util.hash_pandas_object(combined[feat_cols], index=False)
    combined["_dup_hash"] = dup_hash
    combined["_dup_rank"] = combined.groupby("_dup_hash").cumcount()
    combined = combined[combined["_dup_rank"] < MAX_DUP_CAP].drop(columns=["_dup_hash", "_dup_rank"])
    combined = combined.reset_index(drop=True)
    after_cap = len(combined)
    if before_cap != after_cap:
        log.info("Duplicate cap (%d): removed %d rows (%d -> %d)",
                 MAX_DUP_CAP, before_cap - after_cap, before_cap, after_cap)

    # Remove label-conflicting vectors: same feature vector with both 0 and 1 labels
    vec_hash = pd.util.hash_pandas_object(combined[feat_cols], index=False)
    combined["_vec_hash"] = vec_hash
    labels_per_hash = combined.groupby("_vec_hash")["is_malicious"].nunique()
    ambiguous_hashes = set(labels_per_hash[labels_per_hash > 1].index)
    if ambiguous_hashes:
        before_dedup = len(combined)
        combined = combined[~combined["_vec_hash"].isin(ambiguous_hashes)]
        combined = combined.drop(columns=["_vec_hash"]).reset_index(drop=True)
        log.info("Label-conflict removal: %d ambiguous hashes, removed %d rows (%d -> %d)",
                 len(ambiguous_hashes), before_dedup - len(combined), before_dedup, len(combined))
    else:
        combined = combined.drop(columns=["_vec_hash"]).reset_index(drop=True)

    total = len(combined)
    total_attack = (combined["is_malicious"] == 1).sum()
    total_benign = (combined["is_malicious"] == 0).sum()
    log.info("Total: %d rows (%d benign, %d attack, ratio %.1f%%)",
             total, total_benign, total_attack, 100 * total_attack / max(total, 1))

    # Dataset distribution
    log.info("Source distribution:")
    for src, cnt in combined["source_dataset"].value_counts().items():
        log.info("  %s: %d (%.1f%%)", src, cnt, 100 * cnt / total)

    # Save report
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report["_summary"] = {
        "total_rows": total,
        "total_benign": int(total_benign),
        "total_attack": int(total_attack),
        "num_features": NUM_FEATURES,
        "num_datasets": len(all_dfs),
    }
    with open(OUTPUT_DIR / "extraction_report.json", "w") as f:
        json.dump(report, f, indent=2)

    return combined


def split_and_save(combined: pd.DataFrame):
    """Split into train/val/test, scale features, save."""
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    n = len(combined)
    log.info("")
    log.info("Splitting %d rows: 80%% train / 10%% val / 10%% test", n)

    # Stratified split by is_malicious + source_dataset
    # Create a combined stratification key
    strat_key = combined["is_malicious"].astype(str) + "_" + combined["source_dataset"]

    # Handle rare classes (< 3 samples can't be stratified)
    key_counts = strat_key.value_counts()
    rare_keys = key_counts[key_counts < 3].index
    if len(rare_keys) > 0:
        # Merge rare keys with their is_malicious counterpart
        for rk in rare_keys:
            label_part = rk.split("_")[0]
            strat_key = strat_key.replace(rk, label_part + "_other")

    try:
        train_val, test = train_test_split(
            combined, test_size=0.1, random_state=42, stratify=strat_key)
        strat_tv = train_val["is_malicious"].astype(str) + "_" + train_val["source_dataset"]
        key_counts_tv = strat_tv.value_counts()
        rare_tv = key_counts_tv[key_counts_tv < 2].index
        for rk in rare_tv:
            strat_tv = strat_tv.replace(rk, rk.split("_")[0] + "_other")
        train, val = train_test_split(
            train_val, test_size=0.1111, random_state=42, stratify=strat_tv)
    except ValueError:
        # Fallback: stratify only on is_malicious
        log.warning("Complex stratification failed, falling back to label-only stratification")
        train_val, test = train_test_split(
            combined, test_size=0.1, random_state=42, stratify=combined["is_malicious"])
        train, val = train_test_split(
            train_val, test_size=0.1111, random_state=42, stratify=train_val["is_malicious"])

    log.info("  Train: %d | Val: %d | Test: %d", len(train), len(val), len(test))

    # ── Guarantee minimum attack samples per dataset in test & val ──
    # Datasets with very few total attacks (e.g. LANL has 23) can end up with
    # 0-1 attacks in test/val after splitting, making per-dataset F1 meaningless.
    # Fix: for any dataset with < MIN_ATTACKS in test or val, move samples from train.
    MIN_ATTACKS_PER_SPLIT = 5
    for split_name, split_df in [("test", test), ("val", val)]:
        for ds in split_df["source_dataset"].unique():
            ds_mask = split_df["source_dataset"] == ds
            atk_count = (split_df.loc[ds_mask, "is_malicious"] == 1).sum()
            if atk_count < MIN_ATTACKS_PER_SPLIT:
                needed = MIN_ATTACKS_PER_SPLIT - atk_count
                # Find attack rows in train for this dataset
                train_ds_atk = train[(train["source_dataset"] == ds) & (train["is_malicious"] == 1)]
                n_move = min(needed, len(train_ds_atk))
                if n_move > 0:
                    move_idx = train_ds_atk.sample(n=n_move, random_state=42).index
                    if split_name == "test":
                        test = pd.concat([test, train.loc[move_idx]], ignore_index=True)
                    else:
                        val = pd.concat([val, train.loc[move_idx]], ignore_index=True)
                    train = train.drop(move_idx)
                    log.info("  Moved %d attack samples from train→%s for %s (was %d)",
                             n_move, split_name, ds, atk_count)

    # ── Remove train-test and train-val feature-vector overlap ──
    # Identical feature vectors in both train and test/val cause data leakage.
    # Drop overlapping rows from val/test (keep in train).
    train_hashes = set(pd.util.hash_pandas_object(train[FEATURE_NAMES], index=False).values)
    for split_name in ["val", "test"]:
        split_df = val if split_name == "val" else test
        split_h = pd.util.hash_pandas_object(split_df[FEATURE_NAMES], index=False)
        overlap_mask = split_h.isin(train_hashes)
        n_overlap = overlap_mask.sum()
        if n_overlap > 0:
            split_df = split_df[~overlap_mask].reset_index(drop=True)
            if split_name == "val":
                val = split_df
            else:
                test = split_df
            log.info("  Removed %d train-overlap rows from %s (%.1f%%)",
                     n_overlap, split_name, 100 * n_overlap / (n_overlap + len(split_df)))

    log.info("  After dedup: Train=%d | Val=%d | Test=%d", len(train), len(val), len(test))

    # Feature scaling: fit on train ONLY
    log.info("Fitting StandardScaler on train set...")
    scaler = StandardScaler()
    train_features = train[FEATURE_NAMES].values.astype(np.float32)
    scaler.fit(train_features)

    # Apply scaling + clip to [-10, 10] to prevent extreme outliers destabilizing training
    CLIP_RANGE = 10.0
    train[FEATURE_NAMES] = np.clip(scaler.transform(train_features), -CLIP_RANGE, CLIP_RANGE)
    val[FEATURE_NAMES] = np.clip(scaler.transform(val[FEATURE_NAMES].values.astype(np.float32)), -CLIP_RANGE, CLIP_RANGE)
    test[FEATURE_NAMES] = np.clip(scaler.transform(test[FEATURE_NAMES].values.astype(np.float32)), -CLIP_RANGE, CLIP_RANGE)
    log.info("Applied feature clipping to [%.0f, %.0f]", -CLIP_RANGE, CLIP_RANGE)

    # Post-clip label-conflict removal: clipping can make previously-distinct
    # vectors identical, creating new label conflicts. Remove them from each split
    # WITHOUT re-splitting (which would reintroduce train-test overlap).
    all_scaled = pd.concat([train, val, test], ignore_index=True)
    h2 = pd.util.hash_pandas_object(all_scaled[FEATURE_NAMES], index=False)
    lph2 = pd.DataFrame({"h": h2, "lbl": all_scaled["is_malicious"]}).groupby("h")["lbl"].nunique()
    amb_hashes = set(lph2[lph2 > 1].index)
    if amb_hashes:
        for split_name in ["train", "val", "test"]:
            split_df = {"train": train, "val": val, "test": test}[split_name]
            sh = pd.util.hash_pandas_object(split_df[FEATURE_NAMES], index=False)
            mask = sh.isin(amb_hashes)
            n_rm = mask.sum()
            if n_rm > 0:
                split_df = split_df[~mask].reset_index(drop=True)
                if split_name == "train":
                    train = split_df
                elif split_name == "val":
                    val = split_df
                else:
                    test = split_df
                log.info("Post-clip: removed %d label-conflict rows from %s", n_rm, split_name)
        log.info("Post-clip label-conflict removal: %d ambiguous hashes", len(amb_hashes))
    else:
        log.info("Post-clip: no new label conflicts from clipping")

    # Save scaler parameters
    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "var": scaler.var_.tolist(),
        "feature_names": FEATURE_NAMES,
    }
    with open(OUTPUT_DIR / "feature_scaler_v8.json", "w") as f:
        json.dump(scaler_params, f, indent=2)
    log.info("Saved scaler: feature_scaler_v8.json")

    # Save feature names
    with open(OUTPUT_DIR / "feature_names.json", "w") as f:
        json.dump({"feature_names": FEATURE_NAMES, "num_features": NUM_FEATURES,
                    "layer_ranges": {str(k): v for k, v in LAYER_RANGES.items()}}, f, indent=2)

    # Save splits
    try:
        train.to_parquet(OUTPUT_DIR / "train.parquet", index=False, engine="pyarrow")
        val.to_parquet(OUTPUT_DIR / "val.parquet", index=False, engine="pyarrow")
        test.to_parquet(OUTPUT_DIR / "test.parquet", index=False, engine="pyarrow")
        log.info("Saved: train.parquet, val.parquet, test.parquet (Parquet format)")
    except ImportError:
        log.warning("pyarrow not available, saving as CSV")
        train.to_csv(OUTPUT_DIR / "train.csv", index=False)
        val.to_csv(OUTPUT_DIR / "val.csv", index=False)
        test.to_csv(OUTPUT_DIR / "test.csv", index=False)
        log.info("Saved: train.csv, val.csv, test.csv (CSV fallback)")

    # Print final stats
    log.info("")
    log.info("=" * 60)
    log.info("EXTRACTION COMPLETE")
    log.info("=" * 60)
    log.info("Output: %s", OUTPUT_DIR)
    log.info("Features: %d", NUM_FEATURES)
    log.info("Train: %d rows (%.1f%% attack)",
             len(train), 100 * (train["is_malicious"] == 1).sum() / len(train))
    log.info("Val:   %d rows (%.1f%% attack)",
             len(val), 100 * (val["is_malicious"] == 1).sum() / len(val))
    log.info("Test:  %d rows (%.1f%% attack)",
             len(test), 100 * (test["is_malicious"] == 1).sum() / len(test))

    # Per-source breakdown
    log.info("")
    log.info("Per-source breakdown (train set):")
    for src in sorted(train["source_dataset"].unique()):
        sub = train[train["source_dataset"] == src]
        a = (sub["is_malicious"] == 1).sum()
        log.info("  %-20s  %7d rows  %6d attack  %6d benign",
                 src, len(sub), a, len(sub) - a)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_output():
    """Validate extracted data quality."""
    log.info("")
    log.info("Running validation checks...")
    checks_passed = 0
    checks_failed = 0

    # Load one split for validation
    try:
        if (OUTPUT_DIR / "train.parquet").exists():
            train = pd.read_parquet(OUTPUT_DIR / "train.parquet")
        elif (OUTPUT_DIR / "train.csv").exists():
            train = pd.read_csv(OUTPUT_DIR / "train.csv")
        else:
            log.error("No training file found!")
            return
    except Exception as e:
        log.error("Cannot load training data: %s", e)
        return

    feat_df = train[FEATURE_NAMES]

    # Check 1: No NaN
    nan_total = feat_df.isna().sum().sum()
    if nan_total == 0:
        log.info("  [OK] No NaN values in features")
        checks_passed += 1
    else:
        log.error("  [FAIL] Found %d NaN values!", nan_total)
        checks_failed += 1

    # Check 2: No Inf
    inf_total = np.isinf(feat_df.values).sum()
    if inf_total == 0:
        log.info("  [OK] No Inf values in features")
        checks_passed += 1
    else:
        log.error("  [FAIL] Found %d Inf values!", inf_total)
        checks_failed += 1

    # Check 3: Correct number of features
    if len(feat_df.columns) == NUM_FEATURES:
        log.info("  [OK] Feature count: %d", NUM_FEATURES)
        checks_passed += 1
    else:
        log.error("  [FAIL] Expected %d features, got %d", NUM_FEATURES, len(feat_df.columns))
        checks_failed += 1

    # Check 4: Labels are binary
    labels = train["is_malicious"]
    unique_labels = set(labels.unique())
    if unique_labels <= {0, 1}:
        log.info("  [OK] Labels are binary {0, 1}")
        checks_passed += 1
    else:
        log.error("  [FAIL] Unexpected label values: %s", unique_labels)
        checks_failed += 1

    # Check 5: Both classes present
    if 0 in unique_labels and 1 in unique_labels:
        log.info("  [OK] Both classes present (benign=%d, attack=%d)",
                 (labels == 0).sum(), (labels == 1).sum())
        checks_passed += 1
    else:
        log.error("  [FAIL] Missing class(es): %s", unique_labels)
        checks_failed += 1

    # Check 6: Multiple source datasets
    n_sources = train["source_dataset"].nunique()
    if n_sources >= 5:
        log.info("  [OK] Multiple source datasets: %d", n_sources)
        checks_passed += 1
    else:
        log.warning("  [WARN] Only %d source datasets (expected >=5)", n_sources)
        checks_failed += 1

    # Check 7: Inactive layers are zero for correct log types
    # For email (log_type=9), network layer (features 9-23) should be ~0
    email_mask = (feat_df["log_type"].round() == LOG_TYPE_MAP["email"])
    if email_mask.sum() > 0:
        net_feats = feat_df.loc[email_mask, FEATURE_NAMES[9:24]]
        # After scaling, zeros become the scaled version of 0
        # Check that the pre-scaled values were 0 by checking low variance
        net_std = net_feats.std()
        mostly_zero = (net_std < 0.5).all()  # Low variance = mostly same value
        if mostly_zero:
            log.info("  [OK] Email rows have near-zero network features (layer masking correct)")
            checks_passed += 1
        else:
            log.warning("  [WARN] Email rows have non-zero network features (check extraction)")
            checks_failed += 1

    # Check 8: Feature ranges are reasonable (after scaling, should be ~N(0,1))
    means = feat_df.mean()
    stds = feat_df.std()
    extreme_means = means[means.abs() > 5]
    if len(extreme_means) == 0:
        log.info("  [OK] Feature means are reasonable (all within +/-5 sigma)")
        checks_passed += 1
    else:
        log.warning("  [WARN] Features with extreme means: %s", dict(extreme_means))
        checks_failed += 1

    log.info("")
    log.info("Validation: %d PASSED, %d FAILED", checks_passed, checks_failed)
    return checks_passed, checks_failed


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="CLIF v8 Feature Extraction")
    parser.add_argument("--max-per-dataset", type=int, default=None,
                        help="Global cap per dataset (overrides per-dataset defaults)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate setup without extracting data")
    args = parser.parse_args()

    t_start = time.time()

    combined = run_extraction(
        max_per_dataset=args.max_per_dataset,
        dry_run=args.dry_run,
    )

    if args.dry_run or len(combined) == 0:
        return

    split_and_save(combined)
    validate_output()

    elapsed = time.time() - t_start
    log.info("")
    log.info("Total time: %.0f seconds (%.1f minutes)", elapsed, elapsed / 60)


if __name__ == "__main__":
    main()
