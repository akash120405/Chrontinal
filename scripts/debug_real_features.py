"""
Debug: Run REAL logs through local feature extraction + ONNX inference.
Compare feature vectors for real SSH attacks vs what training expects.
"""
import sys, os, json, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents", "triage"))

import numpy as np
import pandas as pd
import onnxruntime as ort

from feature_extractor import FeatureExtractor, FEATURE_NAMES

DATA_DIR = "agents/Data/Latest_Dataset"
MODEL_DIR = "agents/triage/models"

# Load scaler
with open(f"{MODEL_DIR}/feature_scaler_v8.json") as f:
    scaler = json.load(f)
means = np.array(scaler["mean"], dtype=np.float32)
stds = np.array(scaler["std"], dtype=np.float32)
stds = np.where(stds < 1e-9, 1.0, stds)

# Load models
lgbm = ort.InferenceSession(f"{MODEL_DIR}/lgbm_v8.onnx")
ae = ort.InferenceSession(f"{MODEL_DIR}/autoencoder_v8.onnx")

extractor = FeatureExtractor()


def score_event(event, topic="raw-logs"):
    feats = extractor.extract(event, topic)
    vec = np.array([feats[n] for n in FEATURE_NAMES], dtype=np.float32)
    scaled = (vec - means) / stds
    scaled = np.nan_to_num(scaled, nan=0.0, posinf=0.0, neginf=0.0)
    
    # LightGBM - discover input name
    lgbm_input = lgbm.get_inputs()[0].name
    lgbm_output = lgbm.get_outputs()[0].name
    lgbm_out = lgbm.run(None, {lgbm_input: scaled.reshape(1, -1)})[0]
    # Might be probabilities (shape [1,2]) or labels
    if lgbm_out.ndim == 2 and lgbm_out.shape[1] == 2:
        lgbm_score = float(lgbm_out[0, 1])
    else:
        # Try second output for probabilities
        all_out = lgbm.run(None, {lgbm_input: scaled.reshape(1, -1)})
        for o in all_out:
            if hasattr(o, 'shape') and len(o.shape) == 2 and o.shape[1] == 2:
                lgbm_score = float(o[0, 1])
                break
        else:
            lgbm_score = float(lgbm_out[0])
    
    # Autoencoder
    ae_input = ae.get_inputs()[0].name
    ae_out = ae.run(None, {ae_input: scaled.reshape(1, -1)})[0]
    mse = float(np.mean((scaled - ae_out[0]) ** 2))
    ae_cap = 5.0
    ae_score = min(mse / ae_cap, 1.0)
    
    combined = lgbm_score * 0.85 + ae_score * 0.15
    return lgbm_score, ae_score, combined, feats, vec, scaled


def print_features(feats, vec, scaled, label=""):
    print(f"\n  --- Feature dump ({label}) ---")
    for i, name in enumerate(FEATURE_NAMES):
        raw = vec[i]
        sc = scaled[i]
        if abs(raw) > 0.001 or abs(sc) > 0.5:  # Only non-trivial
            print(f"    [{i:2d}] {name:<25s}  raw={raw:10.4f}  scaled={sc:10.4f}")


# ===== TEST 1: Real SSH Brute Force =====
print("=" * 70)
print("  TEST 1: Real SSH Events (ssh_parsed.csv)")
print("=" * 70)

df = pd.read_csv(f"{DATA_DIR}/01_Syslog/ssh_parsed.csv", nrows=1000)

# Separate attack vs benign
attack_types = {"failed_root", "auth_failure", "failed_invalid_user",
                "invalid_user", "break_in_attempt", "failed_password",
                "pam_auth_failure", "failed_login", "failed_login_invalid_user"}
fail_types = {"failed_root", "auth_failure", "failed_invalid_user",
              "failed_password", "pam_auth_failure", "failed_login",
              "failed_login_invalid_user"}

attacks = df[df["event_type"].isin(attack_types)]
benign = df[~df["event_type"].isin(attack_types)]

print(f"\n  SSH attacks: {len(attacks)}, benign: {len(benign)}")

# Score first 20 attacks
scores = []
for i, (_, row) in enumerate(attacks.head(20).iterrows()):
    et = str(row.get("event_type", "")).lower()
    event = {
        "timestamp": str(row.get("timestamp", "")),
        "hostname": str(row.get("hostname", "unknown")),
        "message": str(row.get("message", "")),
        "source_type": "syslog",
        "auth_type": "password",
        "status": "fail" if et in fail_types else "success",
        "user": str(row.get("username", "")) if pd.notna(row.get("username")) else "",
        "src_ip": str(row.get("source_ip", "")) if pd.notna(row.get("source_ip")) else "",
        "level": "warning",
    }
    lgbm_s, ae_s, comb, feats, vec, scaled = score_event(event)
    scores.append(comb)
    if i < 3:
        print(f"\n  Event #{i}: event_type={et}, user={event['user']}, src_ip={event['src_ip']}")
        print(f"    LightGBM={lgbm_s:.4f}  AE={ae_s:.4f}  Combined={comb:.4f}")
        print_features(feats, vec, scaled, f"SSH attack #{i}")

atk_scores = scores
print(f"\n  SSH Attack scores (first 20): min={min(atk_scores):.4f} max={max(atk_scores):.4f} avg={np.mean(atk_scores):.4f}")

# Score 10 benign
ben_scores = []
for i, (_, row) in enumerate(benign.head(10).iterrows()):
    event = {
        "timestamp": str(row.get("timestamp", "")),
        "hostname": str(row.get("hostname", "unknown")),
        "message": str(row.get("message", "")),
        "source_type": "syslog",
        "auth_type": "password",
        "status": "success",
        "user": str(row.get("username", "")) if pd.notna(row.get("username")) else "",
        "src_ip": str(row.get("source_ip", "")) if pd.notna(row.get("source_ip")) else "",
        "level": "info",
    }
    lgbm_s, ae_s, comb, feats, vec, scaled = score_event(event)
    ben_scores.append(comb)

print(f"  SSH Benign scores (first 10): min={min(ben_scores):.4f} max={max(ben_scores):.4f} avg={np.mean(ben_scores):.4f}")


# ===== TEST 2: Real CloudTrail =====
print("\n" + "=" * 70)
print("  TEST 2: Real CloudTrail Events (cloudtrail_labeled.csv)")
print("=" * 70)

df2 = pd.read_csv(f"{DATA_DIR}/06_Cloud_AWS/cloudtrail_labeled.csv", nrows=200000)
ct_attacks = df2[df2["label"] == "attack"]
ct_suspicious = df2[df2["label"] == "suspicious"]
ct_normal = df2[df2["label"] == "normal"]

print(f"\n  CloudTrail attacks: {len(ct_attacks)}, suspicious: {len(ct_suspicious)}, normal: {len(ct_normal)}")

for label_name, subset in [("attack", ct_attacks.head(10)), ("suspicious", ct_suspicious.head(10))]:
    scores = []
    for i, (_, row) in enumerate(subset.iterrows()):
        identity_type = str(row.get("userIdentitytype", "")) if pd.notna(row.get("userIdentitytype")) else ""
        error_code = str(row.get("errorCode", "")) if pd.notna(row.get("errorCode")) else ""
        event = {
            "timestamp": str(row.get("eventTime", "")),
            "hostname": "aws-account",
            "eventName": str(row.get("eventName", "")),
            "eventSource": str(row.get("eventSource", "")),
            "awsRegion": str(row.get("awsRegion", "")),
            "userIdentity": {"type": identity_type},
            "errorCode": error_code,
            "source_type": "cloudtrail",
            "message": f"CloudTrail: {row.get('eventName', '')}",
            "level": "warning",
        }
        lgbm_s, ae_s, comb, feats, vec, scaled = score_event(event)
        scores.append(comb)
        if i < 2:
            print(f"\n  CT {label_name} #{i}: eventName={event['eventName']}, eventSource={event['eventSource'][:30]}, identity={identity_type}")
            print(f"    LightGBM={lgbm_s:.4f}  AE={ae_s:.4f}  Combined={comb:.4f}")
            print_features(feats, vec, scaled, f"CT {label_name} #{i}")
    
    if scores:
        print(f"\n  CT {label_name} scores: min={min(scores):.4f} max={max(scores):.4f} avg={np.mean(scores):.4f}")


# ===== TEST 3: Now compare with TRAINING features =====
print("\n" + "=" * 70)
print("  TEST 3: Compare Training Features vs Inference Features")
print("=" * 70)

try:
    train_test = pd.read_parquet("agents/Data/training_v8/test.parquet")
    # SSH attacks from training
    ssh_train = train_test[(train_test["log_type"] == 0) & (train_test["label"] == 1)]
    print(f"\n  Training SSH attacks: {len(ssh_train)}")
    if len(ssh_train) > 0:
        for i, (_, row) in enumerate(ssh_train.head(3).iterrows()):
            vec_train = np.array([row[n] for n in FEATURE_NAMES], dtype=np.float32)
            scaled_train = (vec_train - means) / stds
            lgbm_out = lgbm.run(None, {lgbm.get_inputs()[0].name: scaled_train.reshape(1, -1)})
            # Find probabilities output
            lgbm_score = None
            for o in lgbm_out:
                if hasattr(o, 'shape') and len(o.shape) == 2 and o.shape[1] == 2:
                    lgbm_score = float(o[0, 1])
                    break
            if lgbm_score is None:
                lgbm_score = float(lgbm_out[0][0]) if lgbm_out else 0.0
            print(f"\n  Training SSH attack #{i}: lgbm_score={lgbm_score:.4f}")
            for j, name in enumerate(FEATURE_NAMES):
                if abs(vec_train[j]) > 0.001:
                    print(f"    [{j:2d}] {name:<25s}  train={vec_train[j]:10.4f}")
    
    # Cloud attacks from training
    cloud_train = train_test[(train_test["log_type"] == 5) & (train_test["label"] == 1)]
    print(f"\n  Training cloud attacks: {len(cloud_train)}")
    if len(cloud_train) > 0:
        for i, (_, row) in enumerate(cloud_train.head(3).iterrows()):
            vec_train = np.array([row[n] for n in FEATURE_NAMES], dtype=np.float32)
            scaled_train = (vec_train - means) / stds
            lgbm_out = lgbm.run(None, {lgbm.get_inputs()[0].name: scaled_train.reshape(1, -1)})
            lgbm_score = None
            for o in lgbm_out:
                if hasattr(o, 'shape') and len(o.shape) == 2 and o.shape[1] == 2:
                    lgbm_score = float(o[0, 1])
                    break
            if lgbm_score is None:
                lgbm_score = float(lgbm_out[0][0]) if lgbm_out else 0.0
            print(f"\n  Training cloud attack #{i}: lgbm_score={lgbm_score:.4f}")
            for j, name in enumerate(FEATURE_NAMES):
                if abs(vec_train[j]) > 0.001:
                    print(f"    [{j:2d}] {name:<25s}  train={vec_train[j]:10.4f}")
except Exception as e:
    print(f"  Could not load training data: {e}")


# ===== SUMMARY =====
print("\n" + "=" * 70)
print("  SUMMARY")
print("=" * 70)
