"""Compare training SSH attack features vs inference features to find mismatches."""
import pandas as pd
import numpy as np
import json
import sys

sys.path.insert(0, 'agents/triage')
from feature_extractor import FeatureExtractor, FEATURE_NAMES

# Training attack means (already z-scored)
df = pd.read_parquet(r'agents\Data\training_v8\test.parquet')
ssh_atk = df[(df['source_dataset'] == 'syslog_ssh') & (df['is_malicious'] == 1)]
feat_cols = [c for c in df.columns if c not in ('is_malicious', 'attack_type', 'source_dataset')]
train_means = ssh_atk[feat_cols].mean()

# Load scaler
scaler = json.load(open('agents/triage/models/feature_scaler_v8.json'))

# Build inference event (like Vector security output with all fixes)
ext = FeatureExtractor()
event = {
    'clif_event_type': 'security',
    'description': 'Failed password for root from 183.62.140.253 port 38556 ssh2',
    'hostname': 'LabSZ',
    'ip_address': '183.62.140.253',
    'message_body': 'Failed password for root from 183.62.140.253 port 38556 ssh2',
    'source_type': 'syslog',
    'username': 'root',
    'source_ip': '183.62.140.253',
    'status': 'fail',
    'auth_type': 'password',
    'host': 'LabSZ',
    'category': 'auth',
    'original_log_level': 2,
}

# Warm up tracker with ~100 events to get realistic entity features
for _ in range(100):
    ext.extract(event, 'security-events')

feat = ext.extract(event, 'security-events')

# Z-score the inference features
vec = np.array([feat[f] for f in FEATURE_NAMES], dtype=np.float32)
means = np.array(scaler['mean'], dtype=np.float32)
stds = np.array(scaler['std'], dtype=np.float32)
scaled = (vec - means) / stds

print(f"{'feature':30s} {'train_atk':>12s} {'inference':>12s} {'diff':>10s}")
print("-" * 70)
for i, f in enumerate(FEATURE_NAMES):
    t = train_means.get(f, 0.0)
    inf_val = scaled[i]
    diff = inf_val - t
    flag = " ***" if abs(diff) > 2.0 else ""
    print(f"{f:30s} {t:>12.4f} {inf_val:>12.4f} {diff:>+10.4f}{flag}")

# Also show raw (pre-scaled) inference values
print("\n\nRaw inference features (pre-scaling):")
for i, f in enumerate(FEATURE_NAMES):
    if vec[i] != 0.0:
        print(f"  {f:30s} = {vec[i]:.4f}")
