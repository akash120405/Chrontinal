#!/usr/bin/env python3
"""
CLIF Mass Model Test — Per-Type vs Global LightGBM Comparison
==============================================================
Tests both per-type and global models on:
  1. test.parquet (176,686 rows) — the canonical held-out test set
  2. val.parquet (176,734 rows) — validation set
  3. Full breakdown by source_dataset (18 datasets)

Reports: per-model F1/precision/recall/AUC, per-dataset breakdown, 
         and head-to-head comparison.

Usage:
  python scripts/mass_test_models.py [--datasets all|ids,netflow,auth,dns,email,windows]
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, confusion_matrix
)

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "agents" / "Data" / "training_v8"
MODEL_DIR = ROOT / "agents" / "triage" / "models"

import onnxruntime as ort

# ── Feature architecture (same as training) ─────────────────────────────────

ALL_FEATURE_NAMES = [
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "is_off_hours",
    "log_type", "severity_numeric", "message_length_log", "message_entropy",
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
]

LAYER_RANGES = {
    1: (0, 9), 2: (9, 24), 3: (24, 32), 4: (32, 40),
    5: (40, 47), 6: (47, 54), 7: (54, 60),
}

TYPE_CONFIG = {
    "ids": {"datasets": ["ids_2017", "ids_2018", "ids_kdd"], "layers": [1, 2]},
    "netflow": {"datasets": ["netflow", "firewall", "cremev2_traffic", "dns_doh"], "layers": [1, 2]},
    "auth": {"datasets": ["syslog_lanl", "syslog_ssh", "syslog_cremev2", "ad_lanl"], "layers": [1, 3]},
    "dns": {"datasets": ["dns_dga", "dns_exfil"], "layers": [1, 4]},
    "email": {"datasets": ["email"], "layers": [1, 6]},
    "windows": {"datasets": ["windows"], "layers": [1, 3]},
}

DATASET_TO_TYPE = {}
for tn, cfg in TYPE_CONFIG.items():
    for ds in cfg["datasets"]:
        DATASET_TO_TYPE[ds] = tn

# Datasets that fall back to global model
GLOBAL_DATASETS = {"web_csic", "web_queries", "cloud_aws"}


def get_feature_indices(layers):
    indices = []
    for layer in sorted(layers):
        s, e = LAYER_RANGES[layer]
        indices.extend(range(s, e))
    return indices


# ── Load Models ─────────────────────────────────────────────────────────────

def load_global_model():
    path = MODEL_DIR / "lgbm_v8.onnx"
    sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    return sess, sess.get_inputs()[0].name


def load_per_type_models():
    manifest_path = MODEL_DIR / "manifest_per_type.json"
    manifest = json.loads(manifest_path.read_text())
    models = {}
    for name, info in manifest["models"].items():
        onnx_path = MODEL_DIR / info["onnx_file"]
        if onnx_path.exists():
            sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
            models[name] = {
                "session": sess,
                "input_name": sess.get_inputs()[0].name,
                "feature_indices": info["feature_indices"],
                "n_features": info["n_features"],
            }
    return models


def predict_batch(sess, input_name, X):
    if X.dtype != np.float32:
        X = X.astype(np.float32)
    results = sess.run(None, {input_name: X})
    if len(results) >= 2:
        return np.array([d.get(1, d.get("1", 0.0)) for d in results[1]], dtype=np.float64)
    return np.clip(np.array(results[0], dtype=np.float64).flatten(), 0, 1)


# ── Evaluation ──────────────────────────────────────────────────────────────

def eval_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    n = len(y_true)
    n_mal = int(y_true.sum())

    if n_mal == 0 or n_mal == n:
        return {"n": n, "n_mal": n_mal, "f1": 0, "prec": 0, "rec": 0, "auc": 0, "thr": threshold}

    f1 = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_prob)
    except ValueError:
        auc = 0.0

    return {"n": n, "n_mal": n_mal, "f1": round(f1, 4), "prec": round(prec, 4),
            "rec": round(rec, 4), "auc": round(auc, 4), "thr": threshold}


def find_best_threshold(y_true, y_prob, start=0.1, stop=0.9, step=0.02):
    best_f1, best_thr = 0, 0.5
    for thr in np.arange(start, stop, step):
        f = f1_score(y_true, (y_prob >= thr).astype(int), zero_division=0)
        if f > best_f1:
            best_f1, best_thr = f, thr
    return round(best_thr, 3)


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("  CLIF MASS MODEL TEST — Per-Type vs Global LightGBM")
    print("=" * 80)

    # Load data
    print("\n  Loading test data...")
    t0 = time.time()
    test_df = pd.read_parquet(DATA_DIR / "test.parquet")
    val_df = pd.read_parquet(DATA_DIR / "val.parquet")
    print(f"  Test: {len(test_df):,} rows | Val: {len(val_df):,} rows  ({time.time()-t0:.1f}s)")

    # Show data distribution
    print(f"\n  Test set distribution:")
    for ds in sorted(test_df["source_dataset"].unique()):
        n = (test_df["source_dataset"] == ds).sum()
        n_mal = ((test_df["source_dataset"] == ds) & (test_df["is_malicious"] == 1)).sum()
        tname = DATASET_TO_TYPE.get(ds, "global")
        print(f"    {ds:<22} {n:>8,} rows  ({n_mal:>6,} mal)  → {tname}")

    # Load models
    print("\n  Loading models...")
    global_sess, global_input = load_global_model()
    print(f"    Global model: lgbm_v8.onnx (60 features)")
    per_type_models = load_per_type_models()
    for name, info in per_type_models.items():
        print(f"    Per-type model: {name} ({info['n_features']} features)")

    # ═══ TEST ON test.parquet ════════════════════════════════════════════════

    for split_name, df in [("TEST", test_df), ("VALIDATION", val_df)]:
        print(f"\n{'=' * 80}")
        print(f"  {split_name} SET ({len(df):,} rows)")
        print(f"{'=' * 80}")

        X_all = df[ALL_FEATURE_NAMES].values.astype(np.float32)
        y_all = df["is_malicious"].values.astype(int)
        datasets = df["source_dataset"].values

        # ── Global model on entire dataset ───────────────────────────────
        print(f"\n  ── GLOBAL MODEL (lgbm_v8.onnx, all 60 features) ──")
        t0 = time.time()
        global_scores = predict_batch(global_sess, global_input, X_all)
        g_time = time.time() - t0

        g_thr = find_best_threshold(y_all, global_scores)
        g_metrics = eval_metrics(y_all, global_scores, g_thr)
        print(f"  Overall: F1={g_metrics['f1']:.4f}  P={g_metrics['prec']:.4f}  "
              f"R={g_metrics['rec']:.4f}  AUC={g_metrics['auc']:.4f}  thr={g_thr}  "
              f"({g_time:.2f}s)")

        # Per dataset with global model
        print(f"\n  {'Dataset':<22} {'N':>8} {'Mal':>6} {'F1':>7} {'Prec':>7} {'Rec':>7} {'AUC':>7} {'Thr':>5}")
        print(f"  {'-'*75}")
        global_per_ds = {}
        for ds in sorted(df["source_dataset"].unique()):
            mask = datasets == ds
            y_ds = y_all[mask]
            s_ds = global_scores[mask]
            if y_ds.sum() > 0 and len(np.unique(y_ds)) > 1:
                ds_thr = find_best_threshold(y_ds, s_ds)
                m = eval_metrics(y_ds, s_ds, ds_thr)
            else:
                m = {"n": len(y_ds), "n_mal": int(y_ds.sum()), "f1": 0, "prec": 0, "rec": 0, "auc": 0, "thr": 0}
                ds_thr = 0
            global_per_ds[ds] = m
            print(f"  {ds:<22} {m['n']:>8,} {m['n_mal']:>6,} {m['f1']:>7.4f} {m['prec']:>7.4f} "
                  f"{m['rec']:>7.4f} {m['auc']:>7.4f} {ds_thr:>5.3f}")

        # ── Per-type models ──────────────────────────────────────────────
        print(f"\n  ── PER-TYPE MODELS (6 specialized LGBMs) ──")
        pertype_scores = np.full(len(df), -1.0, dtype=np.float64)
        model_used = np.array(["none"] * len(df), dtype=object)

        t0 = time.time()
        for type_name, type_cfg in TYPE_CONFIG.items():
            if type_name not in per_type_models:
                continue
            model_info = per_type_models[type_name]
            feat_idx = model_info["feature_indices"]

            mask = np.isin(datasets, type_cfg["datasets"])
            if mask.sum() == 0:
                continue

            idx = np.where(mask)[0]
            X_sub = X_all[idx][:, feat_idx]
            scores = predict_batch(model_info["session"], model_info["input_name"], X_sub)
            pertype_scores[idx] = scores
            model_used[idx] = type_name

        # Fallback to global for unmapped datasets
        unmapped = pertype_scores < 0
        if unmapped.sum() > 0:
            idx = np.where(unmapped)[0]
            scores = predict_batch(global_sess, global_input, X_all[idx])
            pertype_scores[idx] = scores
            model_used[idx] = "global_fallback"

        pt_time = time.time() - t0
        pt_thr = find_best_threshold(y_all, pertype_scores)
        pt_metrics = eval_metrics(y_all, pertype_scores, pt_thr)
        print(f"  Overall: F1={pt_metrics['f1']:.4f}  P={pt_metrics['prec']:.4f}  "
              f"R={pt_metrics['rec']:.4f}  AUC={pt_metrics['auc']:.4f}  thr={pt_thr}  "
              f"({pt_time:.2f}s)")

        # Per dataset with per-type model
        print(f"\n  {'Dataset':<22} {'Model':<10} {'N':>8} {'Mal':>6} {'F1':>7} {'Prec':>7} {'Rec':>7} {'AUC':>7} {'Thr':>5}")
        print(f"  {'-'*85}")
        pertype_per_ds = {}
        for ds in sorted(df["source_dataset"].unique()):
            mask = datasets == ds
            y_ds = y_all[mask]
            s_ds = pertype_scores[mask]
            mn = model_used[mask][0] if mask.sum() > 0 else "?"
            if y_ds.sum() > 0 and len(np.unique(y_ds)) > 1:
                ds_thr = find_best_threshold(y_ds, s_ds)
                m = eval_metrics(y_ds, s_ds, ds_thr)
            else:
                m = {"n": len(y_ds), "n_mal": int(y_ds.sum()), "f1": 0, "prec": 0, "rec": 0, "auc": 0, "thr": 0}
                ds_thr = 0
            pertype_per_ds[ds] = m
            print(f"  {ds:<22} {mn:<10} {m['n']:>8,} {m['n_mal']:>6,} {m['f1']:>7.4f} {m['prec']:>7.4f} "
                  f"{m['rec']:>7.4f} {m['auc']:>7.4f} {ds_thr:>5.3f}")

        # ── HEAD-TO-HEAD COMPARISON ──────────────────────────────────────
        print(f"\n  ── HEAD-TO-HEAD: Per-Type vs Global ({split_name}) ──")
        print(f"  {'Dataset':<22} {'Global F1':>10} {'PerType F1':>11} {'Delta':>8} {'Winner':>8}")
        print(f"  {'-'*65}")
        wins_g, wins_p, ties = 0, 0, 0
        for ds in sorted(df["source_dataset"].unique()):
            g_f1 = global_per_ds[ds]["f1"]
            p_f1 = pertype_per_ds[ds]["f1"]
            delta = p_f1 - g_f1
            if abs(delta) < 0.001:
                winner = "TIE"
                ties += 1
            elif delta > 0:
                winner = "PerType"
                wins_p += 1
            else:
                winner = "Global"
                wins_g += 1
            print(f"  {ds:<22} {g_f1:>10.4f} {p_f1:>11.4f} {delta:>+8.4f} {winner:>8}")

        print(f"\n  Wins: Global={wins_g}  PerType={wins_p}  Ties={ties}")
        print(f"  Overall Global:  F1={g_metrics['f1']:.4f}  AUC={g_metrics['auc']:.4f}")
        print(f"  Overall PerType: F1={pt_metrics['f1']:.4f}  AUC={pt_metrics['auc']:.4f}")
        gf1 = g_metrics['f1']
        pf1 = pt_metrics['f1']
        delta_overall = pf1 - gf1
        print(f"  Delta F1: {delta_overall:+.4f} {'✓ PerType WINS' if delta_overall > 0 else '✗ Global WINS'}")

    print(f"\n{'=' * 80}")
    print("  MASS TEST COMPLETE")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
