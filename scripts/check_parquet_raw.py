"""Quick check: are training parquet features raw or pre-z-scored?"""
import pandas as pd

df = pd.read_parquet("agents/Data/training_v8/test.parquet")

datasets = ["syslog_ssh", "ids_2017", "dns_dga", "netflow", "windows", "email"]
cols = ["log_type", "severity_numeric", "message_length_log", "message_entropy",
        "auth_type_encoded", "status_is_fail", "is_remote", "fail_rate"]

for ds in datasets:
    sub = df[df["source_dataset"] == ds]
    if len(sub) == 0:
        print(f"{ds}: NOT FOUND")
        continue
    row = sub.iloc[0]
    vals = ", ".join(f"{c}={row[c]:.4f}" for c in cols if c in row.index)
    print(f"{ds} (n={len(sub)}): {vals}")

print("\nUnique log_type values:", sorted(df["log_type"].unique()))
