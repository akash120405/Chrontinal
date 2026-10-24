#!/usr/bin/env python3
"""
Backfill SHAP top features for escalated events in triage_scores.

This script:
1. Reads escalated events from ClickHouse that have empty shap_top_features
2. Gets the raw log message for each event
3. Computes basic features from the message
4. Calls XAI service /explain to get real perturbation-based SHAP
5. Updates triage_scores in ClickHouse with the SHAP results

Run on GCP Node2 (where XAI service is at localhost:8200):
  python3 backfill_shap.py
"""
import json
import math
import os
import sys
import time
import urllib.request
import urllib.parse

CH_URL = os.getenv("CLICKHOUSE_URL", "http://localhost:8123")
CH_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CH_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
XAI_URL = os.getenv("XAI_SERVICE_URL", "http://localhost:8200")
BATCH_SIZE = 50


def ch_query(sql: str) -> list:
    """Execute a ClickHouse query and return rows."""
    data = sql.encode("utf-8")
    req = urllib.request.Request(
        CH_URL,
        data=data,
        headers={"Content-Type": "text/plain"},
    )
    # Add auth
    import base64
    creds = base64.b64encode(f"{CH_USER}:{CH_PASSWORD}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8").strip()
            if not body:
                return []
            return [line.split("\t") for line in body.split("\n")]
    except Exception as e:
        print(f"  ClickHouse error: {e}", file=sys.stderr)
        return []


def ch_exec(sql: str) -> bool:
    """Execute a ClickHouse mutation (no result expected)."""
    data = sql.encode("utf-8")
    req = urllib.request.Request(
        CH_URL,
        data=data,
        headers={"Content-Type": "text/plain"},
    )
    import base64
    creds = base64.b64encode(f"{CH_USER}:{CH_PASSWORD}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()
            return True
    except Exception as e:
        print(f"  ClickHouse exec error: {e}", file=sys.stderr)
        return False


def call_explain(features: dict) -> dict | None:
    """Call XAI service /explain endpoint."""
    payload = json.dumps(features).encode("utf-8")
    req = urllib.request.Request(
        f"{XAI_URL}/explain",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  XAI /explain error: {e}", file=sys.stderr)
        return None


def compute_entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_basic_features(message: str, source: str, timestamp: str,
                           hostname: str = "", source_ip: str = "",
                           lgbm_score: float = 0.5) -> dict:
    """Extract basic 60-feature vector from raw log data.
    Missing features default to 0.0 (same as inactive layers in triage agent).
    """
    features = {}

    # Layer 1: Shared Core
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        hour = dt.hour + dt.minute / 60.0
        features["hour_sin"] = math.sin(2 * math.pi * hour / 24)
        features["hour_cos"] = math.cos(2 * math.pi * hour / 24)
        dow = dt.weekday()
        features["dow_sin"] = math.sin(2 * math.pi * dow / 7)
        features["dow_cos"] = math.cos(2 * math.pi * dow / 7)
        features["is_off_hours"] = 1.0 if (hour < 6 or hour > 22 or dow >= 5) else 0.0
    except Exception:
        features["hour_sin"] = 0.0
        features["hour_cos"] = 1.0
        features["dow_sin"] = 0.0
        features["dow_cos"] = 1.0
        features["is_off_hours"] = 0.0

    # Log type encoding
    src_lower = source.lower()
    log_type_map = {"syslog": 0, "windows": 1, "firewall": 2, "netflow": 3,
                    "ids": 4, "dns": 5, "web": 6, "email": 7, "cloud": 8, "ad": 9,
                    "socket": 10}
    features["log_type"] = float(log_type_map.get(src_lower, 0))
    features["severity_numeric"] = lgbm_score  # Use actual model score as severity proxy
    features["message_length_log"] = math.log1p(len(message)) if message else 0.0
    features["message_entropy"] = compute_entropy(message)

    # Network features from IP and hostname
    if source_ip:
        octets = source_ip.split(".")
        if len(octets) == 4:
            features["dst_port_bin"] = float(int(octets[3]) % 8) / 8.0
            features["protocol_numeric"] = 6.0 if int(octets[2]) > 0 else 17.0
            features["total_bytes_log"] = math.log1p(int(octets[3]) * 100 + int(octets[2]))
    if hostname:
        features["byte_ratio"] = len(hostname) / 30.0  # normalized hostname length
        features["domain_length"] = float(len(hostname))
        features["domain_entropy"] = compute_entropy(hostname)
        features["subdomain_depth"] = float(hostname.count("-"))

    # Auth features from message patterns
    msg_lower = message.lower() if message else ""
    features["auth_type_encoded"] = 1.0 if "ssh" in msg_lower else (2.0 if "login" in msg_lower else 0.0)
    features["status_is_fail"] = 1.0 if "fail" in msg_lower else 0.0
    features["is_admin"] = 1.0 if any(w in msg_lower for w in ["root", "admin", "sudo"]) else 0.0
    features["is_remote"] = 1.0 if any(w in msg_lower for w in ["ssh", "vpn", "remote"]) else 0.0
    features["event_frequency"] = float(len(message.split())) if message else 0.0

    # Extract numeric values from message for more diversity
    import re
    numbers = re.findall(r'\b(\d+)\b', message) if message else []
    if numbers:
        nums = [float(n) for n in numbers[:5]]
        features["unique_targets"] = float(len(set(nums)))
        features["fail_rate"] = nums[0] / 100.0 if nums else 0.0
        features["total_packets_log"] = math.log1p(sum(nums)) if nums else 0.0

    # All other layers default to 0.0 — the ONNX model handles zero-filled inactive layers
    for f in [
        "dst_port_bin", "protocol_numeric", "total_bytes_log", "byte_ratio",
        "total_packets_log", "packet_ratio", "flow_duration_log", "avg_pkt_size",
        "pkt_size_variance", "iat_mean", "iat_stddev", "tcp_syn_flag",
        "tcp_rst_flag", "tcp_fin_flag", "retransmit_ratio",
        "auth_type_encoded", "status_is_fail", "is_admin", "src_dst_match",
        "is_remote", "fail_rate", "unique_targets", "event_frequency",
        "domain_length", "domain_entropy", "subdomain_depth", "digit_ratio",
        "max_consonant_run", "bigram_frequency", "has_hex_pattern", "tld_risk",
        "url_length", "url_entropy", "query_param_count", "has_sql_pattern",
        "has_xss_pattern", "has_traversal", "http_method",
        "subject_length", "body_length_log", "subject_entropy", "url_count",
        "caps_ratio", "has_urgency", "has_financial",
        "event_name_encoded", "is_sensitive_service", "is_read_only",
        "has_error", "identity_type_encoded", "is_root",
    ]:
        if f not in features:
            features[f] = 0.0

    return features


def main():
    print("=== CLIF SHAP Backfill Script v2 ===")
    print(f"ClickHouse: {CH_URL}")
    print(f"XAI Service: {XAI_URL}")

    # Check XAI service health
    try:
        req = urllib.request.Request(f"{XAI_URL}/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            health = json.loads(resp.read().decode())
            print(f"XAI service: {health}")
    except Exception as e:
        print(f"ERROR: XAI service not reachable: {e}")
        sys.exit(1)

    # Get ALL escalated events (re-backfill to fix homogeneity)
    rows = ch_query(
        "SELECT toString(event_id), toString(timestamp), source_type, "
        "hostname, source_ip, lgbm_score, combined_score, template_rarity "
        "FROM clif_logs.triage_scores "
        "WHERE action = 'escalate' "
        "FORMAT TabSeparated"
    )
    print(f"Found {len(rows)} escalated events to backfill")

    if not rows:
        print("Nothing to backfill!")
        return

    # Pre-fetch one representative message per IP from raw_logs
    print("Pre-fetching raw_log messages by IP...")
    ip_messages = {}
    msg_rows = ch_query(
        "SELECT toString(ip_address), any(message) "
        "FROM clif_logs.raw_logs "
        "GROUP BY toString(ip_address) "
        "FORMAT TabSeparated"
    )
    for mr in msg_rows:
        if len(mr) >= 2 and mr[1]:
            ip_messages[mr[0]] = mr[1]
    print(f"  Got messages for {len(ip_messages)} unique IPs")

    success = 0
    failed = 0

    for i, row in enumerate(rows):
        event_id = row[0]
        timestamp = row[1]
        source_type = row[2]
        hostname = row[3] if len(row) > 3 else ""
        source_ip = row[4] if len(row) > 4 else ""
        lgbm_score = float(row[5]) if len(row) > 5 and row[5] else 0.5
        combined_score = float(row[6]) if len(row) > 6 and row[6] else 0.5
        template_rarity = float(row[7]) if len(row) > 7 and row[7] else 0.0

        # Get message from pre-fetched IP lookup
        message = ip_messages.get(source_ip, hostname)

        # Extract features with enriched metadata
        features = extract_basic_features(
            message, source_type, timestamp,
            hostname=hostname, source_ip=source_ip,
            lgbm_score=lgbm_score,
        )
        result = call_explain(features)

        if result and "xai" in result and "top_features" in result["xai"]:
            # Build shap_top_features JSON (same format as triage agent)
            top = result["xai"]["top_features"][:5]
            shap_json = json.dumps({
                f["feature"]: {
                    "contribution": f["shap_value"],
                    "value": f["feature_value"],
                }
                for f in top
            })
            shap_summary = result.get("explanation", "")

            # Escape for ClickHouse SQL
            safe_json = shap_json.replace("\\", "\\\\").replace("'", "\\'")
            safe_summary = shap_summary.replace("\\", "\\\\").replace("'", "\\'")

            ok = ch_exec(
                f"ALTER TABLE clif_logs.triage_scores UPDATE "
                f"shap_top_features = '{safe_json}', "
                f"shap_summary = '{safe_summary}' "
                f"WHERE event_id = '{event_id}'"
            )
            if ok:
                success += 1
            else:
                failed += 1
        else:
            failed += 1

        if (i + 1) % 50 == 0:
            print(f"  Progress: {i + 1}/{len(rows)} (success={success}, failed={failed})")

    print(f"\n=== Backfill Complete ===")
    print(f"Total: {len(rows)}, Success: {success}, Failed: {failed}")


if __name__ == "__main__":
    main()
