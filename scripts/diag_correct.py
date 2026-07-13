#!/usr/bin/env python3
"""Correct diagnostic for windows and syslog per-type models."""
import json, sys, numpy as np, pandas as pd
from pathlib import Path
import onnxruntime as ort

if sys.stdout.encoding != "utf-8": sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8": sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents" / "triage"))
from feature_extractor import FeatureExtractor, FEATURE_NAMES

MODEL_DIR = ROOT / "agents" / "triage" / "models"
sc = json.loads((MODEL_DIR / "feature_scaler_v8.json").read_text())
sc_mean = np.array(sc["mean"], dtype=np.float32)
sc_std  = np.array(sc["std"], dtype=np.float32)
sc_std[sc_std < 1e-8] = 1.0

manifest = json.loads((MODEL_DIR / "manifest_per_type.json").read_text())
df = pd.read_parquet(ROOT / "agents" / "Data" / "training_v8" / "test.parquet")
feat_names = [c for c in df.columns if c not in ("is_malicious","attack_type","source_dataset")]

fe = FeatureExtractor()
gl_sess = ort.InferenceSession(str(MODEL_DIR / "lgbm_v8.onnx"), providers=["CPUExecutionProvider"])
gl_input = gl_sess.get_inputs()[0].name

# =========== WINDOWS ===========
print("=" * 60)
print("WINDOWS PER-TYPE MODEL (CORRECT log_type=1)")
print("=" * 60)

win_z = (1.0 - sc_mean[5]) / sc_std[5]
win_df = df[np.abs(df[feat_names[5]] - win_z) < 0.01]
win_atk = win_df[win_df["is_malicious"] == 1]
win_ben = win_df[win_df["is_malicious"] == 0]
print(f"Windows rows: {len(win_df)} (atk={len(win_atk)}, ben={len(win_ben)})")
print(f"Source datasets: {dict(win_df['source_dataset'].value_counts())}")
if len(win_atk) > 0:
    print(f"Attack types: {dict(win_atk['attack_type'].value_counts())}")

win_feat_idx = manifest["models"]["windows"]["feature_indices"]
print(f"\nWindows ATTACK feature stats (z-scored):")
for idx in win_feat_idx:
    fn = FEATURE_NAMES[idx]
    vals = win_atk[feat_names[idx]].values if len(win_atk) > 0 else np.array([0])
    print(f"  [{idx:2d}] {fn:<22} mean={np.mean(vals):>8.4f}  std={np.std(vals):>8.4f}  min={np.min(vals):>8.4f}  max={np.max(vals):>8.4f}")

# Sample windows event
win_event = {
    "timestamp": "2025-06-14T00:11:03.000Z", "hostname": "DC01", "source_type": "windows_event",
    "message": "Jun 14 00:11:03 DC01 Microsoft-Windows-Security-Auditing[4768]: A Kerberos authentication ticket (TGT) was requested. Account Name: svc_backup",
    "level": "INFO", "EventID": 4768, "windows_event_id": 4768, "Channel": "Security",
    "TargetUserName": "svc_backup", "username": "svc_backup",
}
feats = fe.extract(win_event, "security-events")
vec = np.array([feats.get(fn, 0.0) for fn in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
vec_scaled = (vec - sc_mean) / sc_std

print(f"\nSample Windows event vs training ATTACK mean:")
for idx in win_feat_idx:
    fn = FEATURE_NAMES[idx]
    zsc = vec_scaled[0, idx]
    tm = win_atk[feat_names[idx]].mean() if len(win_atk) > 0 else 0
    ts = win_atk[feat_names[idx]].std() if len(win_atk) > 0 else 1
    ds = abs(zsc - tm) / max(ts, 0.01)
    flag = " <-- MISMATCH" if ds > 3 else ""
    print(f"  [{idx:2d}] {fn:<22} inf={zsc:>8.4f}  train_mean={tm:>8.4f}  train_std={ts:>8.4f}  d_sigma={ds:>6.2f}{flag}")

win_info = manifest["models"]["windows"]
win_sess = ort.InferenceSession(str(MODEL_DIR / win_info["onnx_file"]), providers=["CPUExecutionProvider"])
win_input = win_sess.get_inputs()[0].name
X_sub = vec_scaled[:, win_feat_idx].astype(np.float32)
res = win_sess.run(None, {win_input: X_sub})
score_pt = [d.get(1, d.get("1", 0.0)) for d in res[1]][0] if len(res) >= 2 else float(res[0][0])
gl_res = gl_sess.run(None, {gl_input: vec_scaled.astype(np.float32)})
score_gl = [d.get(1, d.get("1", 0.0)) for d in gl_res[1]][0] if len(gl_res) >= 2 else float(gl_res[0][0])
print(f"\nWindows PT: {score_pt:.6f}  |  Global: {score_gl:.6f}")

# Feed actual training attack row to verify model works
if len(win_atk) > 0:
    sample_row = win_atk[feat_names].iloc[0:1].values.astype(np.float32)
    sample_sub = sample_row[:, win_feat_idx]
    res_train = win_sess.run(None, {win_input: sample_sub})
    sc_train = [d.get(1, d.get("1", 0.0)) for d in res_train[1]][0] if len(res_train) >= 2 else float(res_train[0][0])
    gl_train = gl_sess.run(None, {gl_input: sample_row})
    gl_sc = [d.get(1, d.get("1", 0.0)) for d in gl_train[1]][0] if len(gl_train) >= 2 else float(gl_train[0][0])
    print(f"Training attack row → PT: {sc_train:.6f}  |  Global: {gl_sc:.6f}")

# =========== SYSLOG ===========
print("\n" + "=" * 60)
print("SYSLOG/AUTH PER-TYPE MODEL (log_type=0)")
print("=" * 60)

sys_z = (0.0 - sc_mean[5]) / sc_std[5]
sys_df = df[np.abs(df[feat_names[5]] - sys_z) < 0.01]
sys_atk = sys_df[sys_df["is_malicious"] == 1]
sys_ben = sys_df[sys_df["is_malicious"] == 0]
print(f"Syslog rows: {len(sys_df)} (atk={len(sys_atk)}, ben={len(sys_ben)})")
print(f"Source datasets: {dict(sys_df['source_dataset'].value_counts())}")

auth_feat_idx = manifest["models"]["auth"]["feature_indices"]
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

print(f"\nSSH brute force vs training ATTACK mean:")
for idx in auth_feat_idx:
    fn = FEATURE_NAMES[idx]
    zsc = vec2_scaled[0, idx]
    tm = sys_atk[feat_names[idx]].mean() if len(sys_atk) > 0 else 0
    ts = sys_atk[feat_names[idx]].std() if len(sys_atk) > 0 else 1
    ds = abs(zsc - tm) / max(ts, 0.01)
    flag = " <-- MISMATCH" if ds > 3 else ""
    print(f"  [{idx:2d}] {fn:<22} inf={zsc:>8.4f}  train_mean={tm:>8.4f}  train_std={ts:>8.4f}  d_sigma={ds:>6.2f}{flag}")

auth_info = manifest["models"]["auth"]
auth_sess = ort.InferenceSession(str(MODEL_DIR / auth_info["onnx_file"]), providers=["CPUExecutionProvider"])
auth_input = auth_sess.get_inputs()[0].name
X_sub2 = vec2_scaled[:, auth_feat_idx].astype(np.float32)
res2 = auth_sess.run(None, {auth_input: X_sub2})
score_pt2 = [d.get(1, d.get("1", 0.0)) for d in res2[1]][0] if len(res2) >= 2 else float(res2[0][0])
gl_res2 = gl_sess.run(None, {gl_input: vec2_scaled.astype(np.float32)})
score_gl2 = [d.get(1, d.get("1", 0.0)) for d in gl_res2[1]][0] if len(gl_res2) >= 2 else float(gl_res2[0][0])
print(f"\nAuth PT: {score_pt2:.6f}  |  Global: {score_gl2:.6f}")

# Feed actual training attack row to verify
if len(sys_atk) > 0:
    sample_row = sys_atk[feat_names].iloc[0:1].values.astype(np.float32)
    sample_sub = sample_row[:, auth_feat_idx]
    res_train = auth_sess.run(None, {auth_input: sample_sub})
    sc_train = [d.get(1, d.get("1", 0.0)) for d in res_train[1]][0] if len(res_train) >= 2 else float(res_train[0][0])
    gl_train = gl_sess.run(None, {gl_input: sample_row})
    gl_sc = [d.get(1, d.get("1", 0.0)) for d in gl_train[1]][0] if len(gl_train) >= 2 else float(gl_train[0][0])
    print(f"Training attack row -> Auth PT: {sc_train:.6f}  |  Global: {gl_sc:.6f}")
