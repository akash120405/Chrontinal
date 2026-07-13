"""Compare raw feature values from inference FE vs training parquet for the same log types."""
import json, sys, math, numpy as np, pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents" / "triage"))
from feature_extractor import FeatureExtractor, FEATURE_NAMES

MODEL_DIR = ROOT / "agents" / "triage" / "models"
with open(MODEL_DIR / "feature_scaler_v8.json") as f:
    sc = json.load(f)
mean = np.array(sc["mean"], dtype=np.float32)
std = np.array(sc["std"], dtype=np.float32)
std[std < 1e-8] = 1.0

fe = FeatureExtractor()

# Sample SSH attack log
ssh_log = {
    "timestamp": "2025-06-14T00:15:22.000Z",
    "hostname": "sshgw01",
    "source_type": "syslog",
    "message": "Jun 14 00:15:22 sshgw01 sshd[3011]: Failed password for root from 185.220.101.42 port 52344 ssh2",
    "auth_type": "password",
    "status": "fail",
    "user": "root",
    "username": "root",
    "src_ip": "185.220.101.42",
}

feats = fe.extract(ssh_log, "raw-logs")
vec_raw = np.array([feats.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32)
vec_scaled = (vec_raw - mean) / std

# Training stats for syslog_ssh
df = pd.read_parquet("agents/Data/training_v8/test.parquet")
ssh_df = df[df["source_dataset"] == "syslog_ssh"]
ssh_atk = ssh_df[ssh_df["is_malicious"] == 1]

# Auth feature indices
auth_feats = ["log_type", "severity_numeric", "message_length_log", "message_entropy",
              "auth_type_encoded", "status_is_fail", "is_admin", "src_dst_match",
              "is_remote", "fail_rate", "unique_targets", "event_frequency"]

print("=== SSH ATTACK: Inference FE vs Training Data ===")
print(f"{'Feature':<25} {'FE_raw':>10} {'FE_scaled':>10} {'Train_mean':>12} {'Train_std':>10} {'Delta_σ':>8}")
for fn in auth_feats:
    idx = FEATURE_NAMES.index(fn) if fn in FEATURE_NAMES else -1
    raw = vec_raw[idx] if idx >= 0 else 0
    scaled = vec_scaled[idx] if idx >= 0 else 0
    if fn in ssh_atk.columns:
        tmean = ssh_atk[fn].mean()
        tstd = ssh_atk[fn].std()
        delta = abs(scaled - tmean) / max(tstd, 0.01)
        print(f"{fn:<25} {raw:>10.4f} {scaled:>10.4f} {tmean:>12.4f} {tstd:>10.4f} {delta:>8.2f}")
    else:
        print(f"{fn:<25} {raw:>10.4f} {scaled:>10.4f} {'N/A':>12} {'N/A':>10} {'N/A':>8}")

# Sample Windows attack log
win_log = {
    "timestamp": "2025-06-14T00:27:00.000Z",
    "hostname": "SRV-APP-02",
    "source_type": "windows_event",
    "message": "Jun 14 00:27:00 SRV-APP-02 Microsoft-Windows-Security-Auditing[4688]: A new process has been created",
    "EventID": 4688,
    "windows_event_id": 4688,
}

feats_w = fe.extract(win_log, "security-events")
vec_raw_w = np.array([feats_w.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32)
vec_scaled_w = (vec_raw_w - mean) / std

win_df = df[df["source_dataset"] == "windows"]
win_atk = win_df[win_df["is_malicious"] == 1]

print("\n=== WINDOWS ATTACK: Inference FE vs Training Data ===")
win_feats = ["log_type", "severity_numeric", "message_length_log", "message_entropy",
             "auth_type_encoded", "status_is_fail", "is_admin", "src_dst_match",
             "is_remote", "fail_rate", "unique_targets", "event_frequency"]
for fn in win_feats:
    idx = FEATURE_NAMES.index(fn) if fn in FEATURE_NAMES else -1
    raw = vec_raw_w[idx] if idx >= 0 else 0
    scaled = vec_scaled_w[idx] if idx >= 0 else 0
    if fn in win_atk.columns and len(win_atk) > 0:
        tmean = win_atk[fn].mean()
        tstd = win_atk[fn].std() if len(win_atk) > 1 else 0.01
        delta = abs(scaled - tmean) / max(tstd, 0.01)
        print(f"{fn:<25} {raw:>10.4f} {scaled:>10.4f} {tmean:>12.4f} {tstd:>10.4f} {delta:>8.2f}")
    else:
        print(f"{fn:<25} {raw:>10.4f} {scaled:>10.4f} {'N/A':>12} {'N/A':>10} {'N/A':>8}")

# Now show what the model sees (feature subset for auth model)
with open(MODEL_DIR / "manifest_per_type.json") as f:
    manifest = json.load(f)

auth_info = manifest["models"]["auth"]
feat_idx = auth_info["feature_indices"]
print(f"\n=== AUTH MODEL INPUT (SSH log, {len(feat_idx)} features) ===")
print(f"{'Idx':>4} {'Feature':<25} {'Scaled_Value':>12}")
for i, fi in enumerate(feat_idx):
    fn = FEATURE_NAMES[fi]
    print(f"{fi:>4} {fn:<25} {vec_scaled[fi]:>12.4f}")

win_info = manifest["models"]["windows"]
win_idx = win_info["feature_indices"]
print(f"\n=== WINDOWS MODEL INPUT (Windows log, {len(win_idx)} features) ===")
print(f"{'Idx':>4} {'Feature':<25} {'Scaled_Value':>12}")
for i, fi in enumerate(win_idx):
    fn = FEATURE_NAMES[fi]
    print(f"{fi:>4} {fn:<25} {vec_scaled_w[fi]:>12.4f}")
