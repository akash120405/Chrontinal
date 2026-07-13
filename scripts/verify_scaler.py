"""Verify scaler transforms raw encoding to match training parquet values."""
import json, numpy as np

with open("agents/triage/models/feature_scaler_v8.json") as f:
    scaler = json.load(f)
mean = np.array(scaler["mean"])
std = np.array(scaler["std"])

# Feature index 5 = log_type
print("=== log_type (index 5) ===")
print(f"  mean={mean[5]:.4f}, std={std[5]:.4f}")
for name, raw_val in [("syslog",0), ("windows",1), ("ids",8), ("email",9), ("dns",4), ("netflow",7)]:
    scaled = (raw_val - mean[5]) / std[5]
    print(f"  {name}: raw={raw_val} -> scaled={scaled:.4f}")

# Feature index 6 = severity_numeric
print("\n=== severity_numeric (index 6) ===")
print(f"  mean={mean[6]:.4f}, std={std[6]:.4f}")
for raw_val in [0.0, 1.0, 2.0]:
    scaled = (raw_val - mean[6]) / std[6]
    print(f"  raw={raw_val} -> scaled={scaled:.4f}")

# Feature index 7 = message_length_log
print("\n=== message_length_log (index 7) ===")
print(f"  mean={mean[7]:.4f}, std={std[7]:.4f}")

# Feature index 8 = message_entropy
print("\n=== message_entropy (index 8) ===")
print(f"  mean={mean[8]:.4f}, std={std[8]:.4f}")

# Feature index 24 = auth_type_encoded
print("\n=== auth_type_encoded (index 24) ===")
print(f"  mean={mean[24]:.4f}, std={std[24]:.4f}")
for name, raw_val in [("password",3), ("?",4)]:
    scaled = (raw_val - mean[24]) / std[24]
    print(f"  {name}: raw={raw_val} -> scaled={scaled:.4f}")

# Feature index 25 = status_is_fail
print("\n=== status_is_fail (index 25) ===")
print(f"  mean={mean[25]:.4f}, std={std[25]:.4f}")
for raw_val in [0.0, 1.0]:
    scaled = (raw_val - mean[25]) / std[25]
    print(f"  raw={raw_val} -> scaled={scaled:.4f}")

print("\n=== CONCLUSION ===")
# Check: syslog raw log_type=0, scaler says -1.4644?
syslog_scaled = (0 - mean[5]) / std[5]
print(f"syslog log_type: raw=0 -> scaled={syslog_scaled:.4f} (training parquet has -1.4644)")
ids_scaled = (8 - mean[5]) / std[5]
print(f"ids log_type: raw=8 -> scaled={ids_scaled:.4f} (training parquet has 1.1544)")
