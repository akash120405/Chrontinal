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

sc = json.loads((MODEL_DIR / "feature_scaler_v8.json").read_text())
sc_mean = np.array(sc["mean"], dtype=np.float32)
sc_std  = np.array(sc["std"], dtype=np.float32)
sc_std[sc_std < 1e-8] = 1.0

manifest = json.loads((MODEL_DIR / "manifest_per_type.json").read_text())
train_df = pd.read_parquet(DATA_DIR / "test.parquet")
feat_names = [c for c in train_df.columns if c not in ("is_malicious","attack_type","source_dataset")]
print(f"Test parquet: {len(train_df)} rows, features: {len(feat_names)}")

fe = FeatureExtractor()
gl_sess = ort.InferenceSession(str(MODEL_DIR / "lgbm_v8.onnx"), providers=["CPUExecutionProvider"])
gl_input = gl_sess.get_inputs()[0].name

# ============ WINDOWS ============
print("\n" + "="*60)
print("WINDOWS PER-TYPE MODEL ANALYSIS")
print("="*60)

win_info = manifest["models"]["windows"]
win_feat_idx = win_info["feature_indices"]
print(f"Feature names: {[FEATURE_NAMES[i] for i in win_feat_idx]}")

log_type_zscored_win = (7.0 - sc_mean[5]) / sc_std[5]
train_win = train_df[np.abs(train_df[feat_names[5]] - log_type_zscored_win) < 0.01]
win_atk = train_win[train_win["is_malicious"] == 1]
win_ben = train_win[train_win["is_malicious"] == 0]
print(f"Windows training rows: {len(train_win)} (atk={len(win_atk)}, ben={len(win_ben)})")

print(f"\nWindows ATTACK feature stats (z-scored):")
for idx in win_feat_idx:
    fn = FEATURE_NAMES[idx]
    vals = win_atk[feat_names[idx]].values if len(win_atk) > 0 else np.array([0])
    print(f"  [{idx:2d}] {fn:<22} mean={np.mean(vals):>8.4f}  std={np.std(vals):>8.4f}  min={np.min(vals):>8.4f}  max={np.max(vals):>8.4f}")

# Sample inference windows event
win_event = {
    "timestamp": "2025-06-14T00:11:03.000Z", "hostname": "DC01", "source_type": "windows_event",
    "message": "Jun 14 00:11:03 DC01 Microsoft-Windows-Security-Auditing[4768]: A Kerberos authentication ticket (TGT) was requested. Account Name: svc_backup",
    "level": "INFO", "EventID": 4768, "windows_event_id": 4768, "Channel": "Security",
    "TargetUserName": "svc_backup", "username": "svc_backup",
}
feats = fe.extract(win_event, "security-events")
vec = np.array([feats.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
vec_scaled = (vec - sc_mean) / sc_std

print(f"\nSample Windows event features (raw -> z-scored) vs training attack mean:")
for idx in win_feat_idx:
    fn = FEATURE_NAMES[idx]
    raw = vec[0, idx]; zsc = vec_scaled[0, idx]
    tm = win_atk[feat_names[idx]].mean() if len(win_atk) > 0 else 0
    ts = win_atk[feat_names[idx]].std() if len(win_atk) > 0 else 1
    ds = abs(zsc - tm) / max(ts, 1e-8) if ts > 0.001 else abs(zsc - tm)
    flag = " MISMATCH" if (ds > 2 or (ts < 0.001 and abs(zsc - tm) > 0.01)) else " ok"
    print(f"  [{idx:2d}] {fn:<22} raw={raw:>10.4f} zsc={zsc:>10.4f} train_mean={tm:>8.4f} train_std={ts:>8.4f}{flag}")

# Run through windows model
win_sess = ort.InferenceSession(str(MODEL_DIR / win_info["onnx_file"]), providers=["CPUExecutionProvider"])
win_input_name = win_sess.get_inputs()[0].name
X_sub = vec_scaled[:, win_feat_idx].astype(np.float32)
res = win_sess.run(None, {win_input_name: X_sub})
score_pt = [d.get(1, d.get("1", 0.0)) for d in res[1]][0] if len(res) >= 2 else float(res[0][0])
gl_res = gl_sess.run(None, {gl_input: vec_scaled.astype(np.float32)})
score_gl = [d.get(1, d.get("1", 0.0)) for d in gl_res[1]][0] if len(gl_res) >= 2 else float(gl_res[0][0])
print(f"\nWindows PT model score: {score_pt:.6f}  |  Global model score: {score_gl:.6f}")

# ============ SYSLOG ============
print("\n" + "="*60)
print("SYSLOG/AUTH PER-TYPE MODEL ANALYSIS")
print("="*60)

auth_info = manifest["models"]["auth"]
auth_feat_idx = auth_info["feature_indices"]
print(f"Feature names: {[FEATURE_NAMES[i] for i in auth_feat_idx]}")

log_type_zscored_sys = (0.0 - sc_mean[5]) / sc_std[5]
train_sys = train_df[np.abs(train_df[feat_names[5]] - log_type_zscored_sys) < 0.01]
sys_atk = train_sys[train_sys["is_malicious"] == 1]
sys_ben = train_sys[train_sys["is_malicious"] == 0]
print(f"Syslog training rows: {len(train_sys)} (atk={len(sys_atk)}, ben={len(sys_ben)})")

print(f"\nSyslog ATTACK feature stats (z-scored):")
for idx in auth_feat_idx:
    fn = FEATURE_NAMES[idx]
    vals = sys_atk[feat_names[idx]].values if len(sys_atk) > 0 else np.array([0])
    print(f"  [{idx:2d}] {fn:<22} mean={np.mean(vals):>8.4f}  std={np.std(vals):>8.4f}  min={np.min(vals):>8.4f}  max={np.max(vals):>8.4f}")

ssh_event = {
    "timestamp": "2025-06-14T00:15:22.000Z", "hostname": "sshgw01", "source_type": "syslog",
    "message": "Jun 14 00:15:22 sshgw01 sshd[3011]: Failed password for root from 10.30.144.88 port 55401 ssh2",
    "level": "WARNING", "auth_type": "password", "status": "fail",
    "user": "root", "username": "root", "event_type": "ssh_login", "src_ip": "10.30.144.88",
}
feats2 = fe.extract(ssh_event, "raw-logs")
vec2 = np.array([feats2.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
vec2_scaled = (vec2 - sc_mean) / sc_std

print(f"\nSSH brute force features (raw -> z-scored) vs training attack mean:")
for idx in auth_feat_idx:
    fn = FEATURE_NAMES[idx]
    raw = vec2[0, idx]; zsc = vec2_scaled[0, idx]
    tm = sys_atk[feat_names[idx]].mean() if len(sys_atk) > 0 else 0
    ts = sys_atk[feat_names[idx]].std() if len(sys_atk) > 0 else 1
    ds = abs(zsc - tm) / max(ts, 1e-8) if ts > 0.001 else abs(zsc - tm)
    flag = " MISMATCH" if (ds > 2 or (ts < 0.001 and abs(zsc - tm) > 0.01)) else " ok"
    print(f"  [{idx:2d}] {fn:<22} raw={raw:>10.4f} zsc={zsc:>10.4f} train_mean={tm:>8.4f} train_std={ts:>8.4f}{flag}")

auth_sess = ort.InferenceSession(str(MODEL_DIR / auth_info["onnx_file"]), providers=["CPUExecutionProvider"])
auth_input_name = auth_sess.get_inputs()[0].name
X_sub2 = vec2_scaled[:, auth_feat_idx].astype(np.float32)
res2 = auth_sess.run(None, {auth_input_name: X_sub2})
score_pt2 = [d.get(1, d.get("1", 0.0)) for d in res2[1]][0] if len(res2) >= 2 else float(res2[0][0])
gl_res2 = gl_sess.run(None, {gl_input: vec2_scaled.astype(np.float32)})
score_gl2 = [d.get(1, d.get("1", 0.0)) for d in gl_res2[1]][0] if len(gl_res2) >= 2 else float(gl_res2[0][0])
print(f"\nAuth PT model score: {score_pt2:.6f}  |  Global model score: {score_gl2:.6f}")
