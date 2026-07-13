"""
CLIF v8 — Unbiased Escalation Test (80% Normal / 20% Attack)
=============================================================
Randomly samples from test.parquet to create an 80/20 normal/attack mix,
runs the full LightGBM + Autoencoder ensemble, then reports how many
events fall into each triage bucket:

  DISCARD   (score < 0.40)  — benign, dropped
  MONITOR   (0.40 ≤ score < 0.90) — suspicious, logged to dashboard
  ESCALATE  (score ≥ 0.90) — forwarded to Hunter agent

Unbiased design:
  - Random seed for reproducibility (but truly random sampling)
  - Stratified random sample: 80% from normal, 20% from attack
  - No cherry-picking, no ordering effects
  - Uses the exact same ensemble weights/thresholds as production
"""

import os, sys, time
import numpy as np
import pandas as pd

os.environ["ONNXRUNTIME_LOG_SEVERITY_LEVEL"] = "3"
import onnxruntime as ort
ort.set_default_logger_severity(3)

import json

# ── Paths ───────────────────────────────────────────────────────────────────

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)

TEST_PARQUET   = os.path.join(ROOT, "agents", "Data", "training_v8", "test.parquet")
LGBM_PATH      = os.path.join(ROOT, "agents", "triage", "models", "lgbm_v8.onnx")
AE_PATH        = os.path.join(ROOT, "agents", "triage", "models", "autoencoder_v8.onnx")
SCALER_PATH    = os.path.join(ROOT, "agents", "triage", "models", "feature_scaler_v8.json")
CALIB_PATH     = os.path.join(ROOT, "agents", "triage", "models", "ae_calibration_v8.json")
MANIFEST_PATH  = os.path.join(ROOT, "agents", "triage", "models", "manifest_v8.json")

# ── Production thresholds ───────────────────────────────────────────────────

SUSPICIOUS_THRESHOLD = 0.40
ANOMALOUS_THRESHOLD  = 0.90    # ← Hunter escalation boundary
LGBM_WEIGHT          = 0.85
AE_WEIGHT            = 0.15
AE_SCORE_CAP         = 0.50

# ── Sampling config ─────────────────────────────────────────────────────────

TARGET_TOTAL   = 10_000        # total test events
NORMAL_RATIO   = 0.80          # 80% normal
ATTACK_RATIO   = 0.20          # 20% attack
RANDOM_SEED    = 42            # reproducibility

# ═════════════════════════════════════════════════════════════════════════════

def load_models():
    """Load LightGBM, Autoencoder, Scaler, Calibration."""
    opts = ort.SessionOptions()
    opts.inter_op_num_threads = 1
    opts.intra_op_num_threads = 1
    opts.log_severity_level = 3
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

    lgbm_sess = ort.InferenceSession(LGBM_PATH, providers=["CPUExecutionProvider"], sess_options=opts)
    ae_sess   = ort.InferenceSession(AE_PATH, providers=["CPUExecutionProvider"], sess_options=opts)

    with open(SCALER_PATH) as f:
        scaler_data = json.load(f)
    mean = np.array(scaler_data["mean"], dtype=np.float32)
    std  = np.array(scaler_data["std"], dtype=np.float32)
    std[std < 1e-8] = 1.0

    with open(CALIB_PATH) as f:
        calibration = json.load(f)

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
    features = manifest["features"]

    return lgbm_sess, ae_sess, mean, std, calibration, features


def ensemble_predict(lgbm_sess, ae_sess, X_raw, mean, std, calibration, source_types):
    """
    Full ensemble prediction matching production model_ensemble.py logic.
    
    LightGBM: raw features → probability
    Autoencoder: z-scaled features → reconstruction error → calibrated score
    Combined: 0.85 × LGB + 0.15 × min(AE, 0.50)
    """
    X = X_raw.astype(np.float32)
    n = X.shape[0]

    # ── LightGBM ────────────────────────────────────────────────────────
    lgbm_input = lgbm_sess.get_inputs()[0].name
    lgbm_results = lgbm_sess.run(None, {lgbm_input: X})
    if len(lgbm_results) >= 2:
        prob_list = lgbm_results[1]
        lgbm_scores = np.array(
            [d.get(1, d.get("1", 0.0)) for d in prob_list], dtype=np.float64
        )
    else:
        lgbm_scores = np.array(lgbm_results[0], dtype=np.float64).flatten()
    lgbm_scores = np.clip(lgbm_scores, 0.0, 1.0)

    # ── Autoencoder (z-scaled input) ────────────────────────────────────
    X_scaled = ((X - mean) / std).astype(np.float32)
    ae_input = ae_sess.get_inputs()[0].name
    ae_results = ae_sess.run(None, {ae_input: X_scaled})
    reconstructed = ae_results[0]

    # MSE per sample
    mse = ((X_scaled - reconstructed) ** 2).mean(axis=1)

    # Per-source-type calibration
    default_cal = calibration.get("_default", {"p99_error": 0.05})
    ae_scores = np.zeros(n, dtype=np.float64)
    for i in range(n):
        src = source_types[i] if source_types else "_default"
        cal = calibration.get(src, default_cal)
        p99 = cal.get("p99_error", default_cal["p99_error"])
        if p99 < 1e-10:
            p99 = default_cal["p99_error"]
        ae_scores[i] = mse[i] / p99
    ae_scores = np.clip(ae_scores, 0.0, 1.0)

    # ── Combine ─────────────────────────────────────────────────────────
    ae_capped = np.clip(ae_scores, 0.0, AE_SCORE_CAP)
    combined = lgbm_scores * LGBM_WEIGHT + ae_capped * AE_WEIGHT
    combined = np.clip(combined, 0.0, 1.0)

    return lgbm_scores, ae_scores, combined


def classify(scores):
    """Assign triage labels based on production thresholds."""
    labels = np.where(
        scores >= ANOMALOUS_THRESHOLD, "ESCALATE",
        np.where(scores >= SUSPICIOUS_THRESHOLD, "MONITOR", "DISCARD")
    )
    return labels


def main():
    print("=" * 70)
    print("CLIF v8 — Unbiased Escalation Test (80% Normal / 20% Attack)")
    print("=" * 70)

    # ── Load data ───────────────────────────────────────────────────────
    print("\n[1] Loading test data...")
    df = pd.read_parquet(TEST_PARQUET)
    print(f"    Full dataset: {len(df):,} rows")

    normal_df = df[df["is_malicious"] == 0]
    attack_df = df[df["is_malicious"] == 1]
    print(f"    Normal: {len(normal_df):,}  |  Attack: {len(attack_df):,}")

    # ── Stratified random sample ────────────────────────────────────────
    print(f"\n[2] Stratified random sampling (seed={RANDOM_SEED})...")
    n_normal = int(TARGET_TOTAL * NORMAL_RATIO)
    n_attack = int(TARGET_TOTAL * ATTACK_RATIO)

    # Cap if insufficient data
    n_normal = min(n_normal, len(normal_df))
    n_attack = min(n_attack, len(attack_df))

    rng = np.random.RandomState(RANDOM_SEED)
    normal_sample = normal_df.sample(n=n_normal, random_state=rng)
    attack_sample = attack_df.sample(n=n_attack, random_state=rng)

    sample = pd.concat([normal_sample, attack_sample])
    # Shuffle to remove any ordering bias
    sample = sample.sample(frac=1.0, random_state=rng).reset_index(drop=True)

    actual_normal = int((sample["is_malicious"] == 0).sum())
    actual_attack = int((sample["is_malicious"] == 1).sum())
    total = len(sample)
    print(f"    Sampled: {total:,} events")
    print(f"    Normal:  {actual_normal:,} ({actual_normal/total*100:.1f}%)")
    print(f"    Attack:  {actual_attack:,} ({actual_attack/total*100:.1f}%)")

    # ── Load models ─────────────────────────────────────────────────────
    print("\n[3] Loading ensemble models...")
    lgbm_sess, ae_sess, mean, std, calibration, features = load_models()
    print(f"    Features: {len(features)}")
    print(f"    Calibration sources: {len(calibration)}")

    # ── Extract feature matrix ──────────────────────────────────────────
    X = sample[features].values.astype(np.float32)
    is_malicious = sample["is_malicious"].values
    source_datasets = sample["source_dataset"].values.tolist() if "source_dataset" in sample.columns else None

    # ── Run ensemble ────────────────────────────────────────────────────
    print("\n[4] Running ensemble inference...")
    t0 = time.monotonic()
    lgbm_scores, ae_scores, combined = ensemble_predict(
        lgbm_sess, ae_sess, X, mean, std, calibration, source_datasets
    )
    elapsed = time.monotonic() - t0
    print(f"    Inference time: {elapsed*1000:.1f} ms ({elapsed/total*1e6:.1f} µs/event)")

    # ── Classify ────────────────────────────────────────────────────────
    labels = classify(combined)

    # ── Overall results ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS — Triage Buckets (Production Thresholds)")
    print("=" * 70)
    print(f"\n  Thresholds:  DISCARD < {SUSPICIOUS_THRESHOLD}  |  "
          f"MONITOR [{SUSPICIOUS_THRESHOLD}, {ANOMALOUS_THRESHOLD})  |  "
          f"ESCALATE ≥ {ANOMALOUS_THRESHOLD}")
    print(f"  Ensemble:    {LGBM_WEIGHT}×LightGBM + {AE_WEIGHT}×min(AE, {AE_SCORE_CAP})")

    n_discard  = int((labels == "DISCARD").sum())
    n_monitor  = int((labels == "MONITOR").sum())
    n_escalate = int((labels == "ESCALATE").sum())

    print(f"\n  {'Bucket':<12} {'Count':>7} {'%':>8}")
    print(f"  {'-'*12} {'-'*7} {'-'*8}")
    print(f"  {'DISCARD':<12} {n_discard:>7,} {n_discard/total*100:>7.1f}%")
    print(f"  {'MONITOR':<12} {n_monitor:>7,} {n_monitor/total*100:>7.1f}%")
    print(f"  {'ESCALATE':<12} {n_escalate:>7,} {n_escalate/total*100:>7.1f}%  ← sent to Hunter")
    print(f"  {'TOTAL':<12} {total:>7,} {100.0:>7.1f}%")

    # ── Breakdown by ground truth ───────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("BREAKDOWN — By Ground Truth")
    print(f"{'─' * 70}")

    for truth_label, truth_val in [("NORMAL (benign)", 0), ("ATTACK (malicious)", 1)]:
        mask = is_malicious == truth_val
        n_group = int(mask.sum())
        group_labels = labels[mask]
        g_disc = int((group_labels == "DISCARD").sum())
        g_mon  = int((group_labels == "MONITOR").sum())
        g_esc  = int((group_labels == "ESCALATE").sum())

        print(f"\n  {truth_label} ({n_group:,} events):")
        print(f"    {'DISCARD':<12} {g_disc:>7,} ({g_disc/n_group*100:>6.2f}%)")
        print(f"    {'MONITOR':<12} {g_mon:>7,} ({g_mon/n_group*100:>6.2f}%)")
        print(f"    {'ESCALATE':<12} {g_esc:>7,} ({g_esc/n_group*100:>6.2f}%)  ← Hunter")

    # ── Confusion matrix (binary: escalated vs not) ─────────────────────
    print(f"\n{'─' * 70}")
    print("CONFUSION MATRIX — Escalation (score ≥ 0.90 → Hunter)")
    print(f"{'─' * 70}")

    escalated = labels == "ESCALATE"
    tp = int((escalated & (is_malicious == 1)).sum())
    fp = int((escalated & (is_malicious == 0)).sum())
    fn = int((~escalated & (is_malicious == 1)).sum())
    tn = int((~escalated & (is_malicious == 0)).sum())

    print(f"\n                     Predicted")
    print(f"                  Not-Esc   Escalate")
    print(f"  Actual Normal   {tn:>7,}   {fp:>7,}")
    print(f"  Actual Attack   {fn:>7,}   {tp:>7,}")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"\n  Precision (of escalated, how many are real attacks): {precision:.4f}")
    print(f"  Recall    (of attacks, how many got escalated):      {recall:.4f}")
    print(f"  F1 Score:                                            {f1:.4f}")
    print(f"  False Positive Rate (normal → Hunter):               {fpr:.4f} ({fp} events)")

    # ── Score distribution ──────────────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("SCORE DISTRIBUTION — Combined Ensemble Score")
    print(f"{'─' * 70}")

    for truth_label, truth_val in [("Normal", 0), ("Attack", 1)]:
        mask = is_malicious == truth_val
        scores = combined[mask]
        print(f"\n  {truth_label} (n={int(mask.sum()):,}):")
        print(f"    Mean:   {scores.mean():.4f}")
        print(f"    Median: {np.median(scores):.4f}")
        print(f"    Std:    {scores.std():.4f}")
        print(f"    Min:    {scores.min():.4f}   Max: {scores.max():.4f}")
        print(f"    P5:     {np.percentile(scores, 5):.4f}   P95: {np.percentile(scores, 95):.4f}")

    # ── Per-source breakdown (top escalators) ───────────────────────────
    if source_datasets:
        print(f"\n{'─' * 70}")
        print("PER-SOURCE ESCALATION RATES")
        print(f"{'─' * 70}")

        sample_with_results = sample.copy()
        sample_with_results["combined_score"] = combined
        sample_with_results["escalated"] = escalated
        sample_with_results["label"] = labels

        src_stats = sample_with_results.groupby("source_dataset").agg(
            total=("is_malicious", "count"),
            attacks=("is_malicious", "sum"),
            escalated=("escalated", "sum"),
            mean_score=("combined_score", "mean"),
        ).sort_values("escalated", ascending=False)

        print(f"\n  {'Source':<25} {'Total':>6} {'Attacks':>8} {'Escalated':>10} {'Esc%':>7} {'AvgScore':>9}")
        print(f"  {'-'*25} {'-'*6} {'-'*8} {'-'*10} {'-'*7} {'-'*9}")
        for src, row in src_stats.iterrows():
            esc_pct = row["escalated"] / row["total"] * 100 if row["total"] > 0 else 0
            print(f"  {src:<25} {int(row['total']):>6} {int(row['attacks']):>8} "
                  f"{int(row['escalated']):>10} {esc_pct:>6.1f}% {row['mean_score']:>8.4f}")

    # ── Hunter workload projection ──────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("HUNTER WORKLOAD PROJECTION")
    print(f"{'─' * 70}")
    esc_rate = n_escalate / total
    print(f"\n  Escalation rate: {esc_rate*100:.2f}% of all events")
    print(f"  At 1,000 events/sec: ~{esc_rate*1000:.0f} Hunter tasks/sec")
    print(f"  At 10,000 events/sec: ~{esc_rate*10000:.0f} Hunter tasks/sec")
    print(f"  At 100,000 events/sec: ~{esc_rate*100000:.0f} Hunter tasks/sec")
    if fp > 0:
        print(f"\n  False alarm rate: {fpr*100:.3f}% of normal traffic → Hunter")
        print(f"  At 10,000 normal events/sec: ~{fpr*10000:.1f} false Hunter tasks/sec")

    print(f"\n{'=' * 70}")
    print("TEST COMPLETE")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
