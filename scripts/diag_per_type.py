#!/usr/bin/env python3
"""Diagnose per-type model failures for windows and syslog events."""
import json, sys, numpy as np
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents" / "triage"))
from feature_extractor import FeatureExtractor, FEATURE_NAMES
import onnxruntime as ort
import pandas as pd

MODEL_DIR = ROOT / "agents" / "triage" / "models"
DATA_DIR  = ROOT / "agents" / "Data" / "training_v8"

# Load scaler
sc = json.loads((MODEL_DIR / "feature_scaler_v8.json").read_text())
sc_mean = np.array(sc["mean"], dtype=np.float32)
sc_std  = np.array(sc["std"], dtype=np.float32)
sc_std[sc_std < 1e-8] = 1.0

# Load manifest
manifest = json.loads((MODEL_DIR / "manifest_per_type.json").read_text())

# Load training datais_malicious","attack_type","source_dataset"
train_df = pd.read_parquet(DATA_DIR / "test.parquet")
print(f"Test parquet: {len(train_df)} rows")

# Feature names
feat_names = [c for c in train_df.columns if c not in ("label",)]

# --- Windows model analysis ---
print("\n" + "="*60)
print("WINDOWS PER-TYPE MODEL ANALYSIS")
print("="*60)

win_info = manifest["models"]["windows"]
win_feat_idx = win_info["feature_indices"]
print(f"Feature indices: {win_feat_idx}")
print(f"Feature names: {[FEATURE_NAMES[i] for i in win_feat_idx]}")

# Training data for windows (log_type encoded)
# In z-scored space, need to find windows rows
# log_type raw=7 for windows -> z-score = (7 - mean) / std
log_type_raw_windows = 7.0
log_type_zscored = (log_type_raw_windows - sc_mean[5]) / sc_std[5]
print(f"\nWindows log_type z-scored value: {log_type_zscored:.4f}")

# Find training rows close to this z-score for feature index 5 (log_type)
train_windows = train_df[np.abs(train_dis_malicious"] == 1]
    ben = train_windows[train_windows["is_maliciousarquet: {len(train_windows)}")

# Show attack vs benign
if len(train_windows) > 0:
    atk = train_windows[train_windows["label"] == 1]
    ben = train_windows[train_windows["label"] == 0]
    print(f"  Attack: {len(atk)}, Benign: {len(ben)}")
    
    # Show feature statistics for windows attack rows
    print(f"\nWindows ATTACK feature stats (z-scored, from training):")
    for idx in win_feat_idx:
        fn = FEATURE_NAMES[idx]
        vals = atk[feat_names[idx]].values if len(atk) > 0 else np.array([0])
        print(f"  [{idx:2d}] {fn:<22} mean={np.mean(vals):>8.4f}  std={np.std(vals):>8.4f}  "
              f"min={np.min(vals):>8.4f}  max={np.max(vals):>8.4f}")

# Now extract features for a sample windows event
fe = FeatureExtractor()
win_event = {
    "timestamp": "2025-06-14T00:11:03.000Z",
    "hostname": "DC01",
    "source_type": "windows_event",
    "message": "Jun 14 00:11:03 DC01 Microsoft-Windows-Security-Auditing[4768]: A Kerberos authentication ticket (TGT) was requested. Account Name: svc_backup",
    "level": "INFO",
    "EventID": 4768,
    "windows_event_id": 4768,
    "Channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "TargetUserName": "svc_backup",
    "username": "svc_backup",
}

feats = fe.extract(win_event, "security-events")
vec = np.array([feats.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
vec_scaled = (vec - sc_mean) / sc_std

print(f"\nSample Windows event feature values (raw → z-scored):")
for idx in win_feat_idx:
    fn = FEATURE_NAMES[idx]
    raw = vec[0, idx]
    zsc = vec_scaled[0, idx]
    print(f"  [{idx:2d}] {fn:<22} raw={raw:>10.4f}  z-scored={zsc:>10.4f}")

# Run through windows model
win_sess = ort.InferenceSession(str(MODEL_DIR / win_info["onnx_file"]), providers=["CPUExecutionProvider"])
win_input = win_sess.get_inputs()[0].name
X_sub = vec_scaled[:, win_feat_idx].astype(np.float32)
res = win_sess.run(None, {win_input: X_sub})
if len(res) >= 2:
    score = [d.get(1, d.get("1", 0.0)) for d in res[1]][0]
else:
    score = float(res[0][0])
print(f"\nWindows per-type model score: {score:.6f}")

# Also run through global model
gl_sess = ort.InferenceSession(str(MODEL_DIR / "lgbm_v8.onnx"), providers=["CPUExecutionProvider"])
gl_input = gl_sess.get_inputs()[0].name
gl_res = gl_sess.run(None, {gl_input: vec_scaled.astype(np.float32)})
if len(gl_res) >= 2:
    gl_score = [d.get(1, d.get("1", 0.0)) for d in gl_res[1]][0]
else:
    gl_score = float(gl_res[0][0])
print(f"Global model score: {gl_score:.6f}")

# --- Syslog/Auth model analysis ---
print("\n" + "="*60)
print("SYSLOG/AUTH PER-TYPE MODEL ANALYSIS")
print("="*60)

auth_info = manifest["models"]["auth"]
auth_feat_idx = auth_info["feature_indices"]
print(f"Feature indices: {auth_feat_idx}")
print(f"Feature names: {[FEATURE_NAMES[i] for i in auth_feat_idx]}")

# Syslog log_type raw=0
log_type_raw_syslog = 0.0
log_type_zscored_sys = (log_type_raw_syslog - sc_mean[5]) / sc_std[5]
print(f"\nSyslog log_type z-scored vais_malicious"] == 1]
    ben = train_syslog[train_syslog["is_malicious
train_syslog = train_df[np.abs(train_df[feat_names[5]] - log_type_zscored_sys) < 0.01]
print(f"Training syslog-type rows in test.parquet: {len(train_syslog)}")
if len(train_syslog) > 0:
    atk = train_syslog[train_syslog["label"] == 1]
    ben = train_syslog[train_syslog["label"] == 0]
    print(f"  Attack: {len(atk)}, Benign: {len(ben)}")
    
    print(f"\nSyslog ATTACK feature stats (z-scored, from training):")
    for idx in auth_feat_idx:
        fn = FEATURE_NAMES[idx]
        vals = atk[feat_names[idx]].values if len(atk) > 0 else np.array([0])
        print(f"  [{idx:2d}] {fn:<22} mean={np.mean(vals):>8.4f}  std={np.std(vals):>8.4f}  "
              f"min={np.min(vals):>8.4f}  max={np.max(vals):>8.4f}")

# SSH brute force event
ssh_event = {
    "timestamp": "2025-06-14T00:15:22.000Z",
    "hostname": "sshgw01",
    "source_type": "syslog",
    "message": "Jun 14 00:15:22 sshgw01 sshd[3011]: Failed password for root from 10.30.144.88 port 55401 ssh2",
    "level": "WARNING",
    "auth_type": "password",
    "status": "fail",
    "user": "root",
    "username": "root",
    "event_type": "ssh_login",
    "src_ip": "10.30.144.88",
}

feats2 = fe.extract(ssh_event, "raw-logs")
vec2 = np.array([feats2.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
vec2_scaled = (vec2 - sc_mean) / sc_std

print(f"\nSSH brute force event feature values (raw → z-scored):")
for idx in auth_feat_idx:
    fn = FEATURE_NAMES[idx]
    raw = vec2[0, idx]
    zsc = vec2_scaled[0, idx]
    print(f"  [{idx:2d}] {fn:<22} raw={raw:>10.4f}  z-scored={zsc:>10.4f}")

# Auth model score  
auth_sess = ort.InferenceSession(str(MODEL_DIR / auth_info["onnx_file"]), providers=["CPUExecutionProvider"])
auth_input = auth_sess.get_inputs()[0].name
X_sub2 = vec2_scaled[:, auth_feat_idx].astype(np.float32)
res2 = auth_sess.run(None, {auth_input: X_sub2})
if len(res2) >= 2:
    score2 = [d.get(1, d.get("1", 0.0)) for d in res2[1]][0]
else:
    score2 = float(res2[0][0])
print(f"\nAuth per-type model score: {score2:.6f}")

# Global model score
gl_res2 = gl_sess.run(None, {gl_input: vec2_scaled.astype(np.float32)})
if len(gl_res2) >= 2:
    gl_score2 = [d.get(1, d.get("1", 0.0)) for d in gl_res2[1]][0]
else:
    gl_score2 = float(gl_res2[0][0])
print(f"Global model score: {gl_scoreis_malicious}")

# Compare specific features with training data
print(f"\nDelta analysis (inference z-scored vs training attack mean):")
if len(train_syslog) > 0:
    atk = train_syslog[train_syslog["label"] == 1]
    for idx in auth_feat_idx:
        fn = FEATURE_NAMES[idx]
        inf_val = vec2_scaled[0, idx]
        train_mean = atk[feat_names[idx]].mean() if len(atk) > 0 else 0
        train_std = atk[feat_names[idx]].std() if len(atk) > 0 else 1
        delta_sigma = abs(inf_val - train_mean) / max(train_std, 1e-8)
        flag = "  ✗" if delta_sigma > 2 else "  ✓"
        print(f"  [{idx:2d}] {fn:<22} inf={inf_val:>8.4f}  train_mean={train_mean:>8.4f}  "
              f"Δσ={delta_sigma:>6.2f}{flag}")
