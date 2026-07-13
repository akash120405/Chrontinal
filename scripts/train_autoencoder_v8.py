"""
CLIF v8 -- Autoencoder Training Pipeline
==========================================
Production-grade anomaly detector for SIEM triage scoring.
Trained from scratch on v8 feature space (60 features).

How it works:
  - Trains ONLY on normal (benign) data — the AE learns to reconstruct
    normal traffic patterns
  - Attack traffic produces higher reconstruction error
  - Per-source-type calibration normalizes errors across heterogeneous log types
  - Combined with LightGBM in a weighted ensemble (0.85 LGBM + 0.15 AE)

Pipeline:
  1. Load pre-extracted v8 features (60-dim, z-scored, clipped [-10,10])
  2. Filter to normal-only samples for training
  3. Optuna hyperparameter search (architecture, lr, dropout, bottleneck)
  4. Train final model with best params (early stopping on val loss)
  5. Compute per-source-type calibration (p99/p50 reconstruction errors)
  6. Evaluate anomaly detection quality (AUC, separation)
  7. Export: autoencoder_v8.onnx, ae_calibration_v8.json
  8. ONNX round-trip validation
  9. Update manifest_v8.json with AE entry

Usage:
  python scripts/train_autoencoder_v8.py                  # full pipeline
  python scripts/train_autoencoder_v8.py --skip-tuning    # use default architecture
  python scripts/train_autoencoder_v8.py --n-trials 50    # fewer Optuna trials
  python scripts/train_autoencoder_v8.py --epochs 200     # more epochs
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning)

# ── Logging ─────────────────────────────────────────────────────────────────

log = logging.getLogger("clif.train_autoencoder_v8")
log.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_handler)

# ── Paths ───────────────────────────────────────────────────────────────────

DATA_DIR = Path(r"C:\CLIF\agents\Data\training_v8")
MODEL_DIR = Path(r"C:\CLIF\agents\triage\models")
SCALER_PATH = MODEL_DIR / "feature_scaler_v8.json"
MANIFEST_PATH = MODEL_DIR / "manifest_v8.json"

# v8 has 60 event-intrinsic features. Unlike v7 (which had 8 stateful EWMA/
# connection-tracker features that needed masking), all v8 features are
# per-event derived. No masking needed.
#
# v7 masked: entity_event_rate, entity_error_rate, entity_unique_actions,
#            source_novelty, conn_rate_fast, conn_rate_slow,
#            rate_acceleration, port_entropy
# v8: these were removed during the v7→v8 feature redesign.
AE_MASKED_INDICES_V8: Tuple[int, ...] = ()  # none needed for v8


# ═════════════════════════════════════════════════════════════════════════════
#  1. DATA LOADING
# ═════════════════════════════════════════════════════════════════════════════


def load_data() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, List[str]]:
    """Load train/val/test parquets and feature names."""
    log.info("Loading data from %s ...", DATA_DIR)

    with open(DATA_DIR / "feature_names.json") as f:
        meta = json.load(f)
    feat_names: List[str] = meta["feature_names"]
    n_feat = meta["num_features"]
    assert len(feat_names) == n_feat, f"Expected {n_feat} features, got {len(feat_names)}"

    train = pd.read_parquet(DATA_DIR / "train.parquet")
    val = pd.read_parquet(DATA_DIR / "val.parquet")
    test = pd.read_parquet(DATA_DIR / "test.parquet")

    for name, df in [("train", train), ("val", val), ("test", test)]:
        assert set(feat_names).issubset(df.columns), f"{name} missing features"
        assert "is_malicious" in df.columns, f"{name} missing is_malicious"
        assert "source_dataset" in df.columns, f"{name} missing source_dataset"

    log.info("  Train: %d rows (%d normal, %d attack)", len(train),
             (train["is_malicious"] == 0).sum(), (train["is_malicious"] == 1).sum())
    log.info("  Val:   %d rows (%d normal, %d attack)", len(val),
             (val["is_malicious"] == 0).sum(), (val["is_malicious"] == 1).sum())
    log.info("  Test:  %d rows (%d normal, %d attack)", len(test),
             (test["is_malicious"] == 0).sum(), (test["is_malicious"] == 1).sum())
    log.info("  Features: %d", len(feat_names))

    return train, val, test, feat_names


# ═════════════════════════════════════════════════════════════════════════════
#  2. AUTOENCODER ARCHITECTURE
# ═════════════════════════════════════════════════════════════════════════════


def build_autoencoder(
    input_dim: int,
    bottleneck_dim: int = 12,
    hidden_dims: Tuple[int, ...] = (128, 64, 32),
    dropout: float = 0.0,
    use_batchnorm: bool = True,
):
    """
    Build a symmetric autoencoder with configurable architecture.

    Architecture example (default):
      Encoder: 60 → 128 → 64 → 32 → 12
      Decoder: 12 → 32 → 64 → 128 → 60

    Why this sizing:
      - v7 used 32→8 (4:1 compression)
      - v8 uses 60→12 (5:1 compression) — slightly tighter to force
        better latent representation of the larger feature space
      - BatchNorm stabilizes training across heterogeneous log types
      - Dropout prevents memorization of frequent patterns
    """
    import torch.nn as nn

    # Build encoder layers
    encoder_layers = []
    prev_dim = input_dim
    for h_dim in hidden_dims:
        encoder_layers.append(nn.Linear(prev_dim, h_dim))
        if use_batchnorm:
            encoder_layers.append(nn.BatchNorm1d(h_dim))
        encoder_layers.append(nn.ReLU())
        if dropout > 0:
            encoder_layers.append(nn.Dropout(dropout))
        prev_dim = h_dim
    encoder_layers.append(nn.Linear(prev_dim, bottleneck_dim))
    encoder_layers.append(nn.ReLU())

    # Build decoder layers (mirror of encoder)
    decoder_layers = []
    prev_dim = bottleneck_dim
    for h_dim in reversed(hidden_dims):
        decoder_layers.append(nn.Linear(prev_dim, h_dim))
        if use_batchnorm:
            decoder_layers.append(nn.BatchNorm1d(h_dim))
        decoder_layers.append(nn.ReLU())
        if dropout > 0:
            decoder_layers.append(nn.Dropout(dropout))
        prev_dim = h_dim
    # Output layer — no activation (features are z-scored, can be negative)
    decoder_layers.append(nn.Linear(prev_dim, input_dim))

    encoder = nn.Sequential(*encoder_layers)
    decoder = nn.Sequential(*decoder_layers)

    return encoder, decoder


class AutoencoderV8:
    """Wrapper for PyTorch autoencoder with train/eval/export methods."""

    def __init__(
        self,
        input_dim: int,
        bottleneck_dim: int = 12,
        hidden_dims: Tuple[int, ...] = (128, 64, 32),
        dropout: float = 0.0,
        use_batchnorm: bool = True,
    ):
        import torch
        import torch.nn as nn

        self.input_dim = input_dim
        self.bottleneck_dim = bottleneck_dim
        self.hidden_dims = hidden_dims

        encoder, decoder = build_autoencoder(
            input_dim, bottleneck_dim, hidden_dims, dropout, use_batchnorm,
        )

        class _AEModule(nn.Module):
            def __init__(self, enc, dec):
                super().__init__()
                self.encoder = enc
                self.decoder = dec

            def forward(self, x):
                return self.decoder(self.encoder(x))

        self.model = _AEModule(encoder, decoder)
        self.device = torch.device("cpu")

    def to(self, device):
        import torch
        self.device = torch.device(device)
        self.model = self.model.to(self.device)
        return self

    def param_count(self) -> int:
        return sum(p.numel() for p in self.model.parameters())

    def summary(self) -> str:
        dims = [self.input_dim] + list(self.hidden_dims) + [self.bottleneck_dim]
        enc_str = " → ".join(str(d) for d in dims)
        dec_str = " → ".join(str(d) for d in reversed(dims))
        return f"Encoder: {enc_str}\nDecoder: {dec_str}\nParams: {self.param_count():,}"


# ═════════════════════════════════════════════════════════════════════════════
#  3. OPTUNA HYPERPARAMETER SEARCH
# ═════════════════════════════════════════════════════════════════════════════


def run_optuna_search(
    X_train: np.ndarray,
    X_val: np.ndarray,
    n_trials: int = 50,
) -> Dict[str, Any]:
    """
    Bayesian hyperparameter optimization for the autoencoder.

    Searches over:
      - Bottleneck dimension (8, 12, 16, 20)
      - Hidden layer sizes (2 or 3 hidden layers, various widths)
      - Learning rate (1e-4 to 1e-2)
      - Dropout (0.0 to 0.3)
      - Batch size (256, 512, 1024)
      - BatchNorm (on/off)
      - Weight decay (1e-6 to 1e-3)

    Objective: minimize validation MSE after 30 quick epochs.
    """
    import optuna
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info("Optuna search device: %s", device)

    # Subsample for speed during tuning
    max_samples = 200_000
    if len(X_train) > max_samples:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X_train), max_samples, replace=False)
        X_train_sub = X_train[idx]
    else:
        X_train_sub = X_train

    X_train_t = torch.from_numpy(X_train_sub).float().to(device)
    X_val_t = torch.from_numpy(X_val).float().to(device)

    input_dim = X_train.shape[1]

    def objective(trial: optuna.Trial) -> float:
        # Architecture
        bottleneck = trial.suggest_categorical("bottleneck_dim", [8, 12, 16, 20])
        n_layers = trial.suggest_int("n_hidden_layers", 2, 3)
        hidden_dims = []
        prev = input_dim
        for i in range(n_layers):
            max_dim = min(prev, 256)
            dim = trial.suggest_categorical(f"hidden_{i}", [32, 64, 96, 128, 192, 256])
            if dim > max_dim:
                dim = max_dim
            hidden_dims.append(dim)
            prev = dim

        # Training params
        lr = trial.suggest_float("lr", 1e-4, 1e-2, log=True)
        dropout = trial.suggest_float("dropout", 0.0, 0.3, step=0.05)
        batch_size = trial.suggest_categorical("batch_size", [256, 512, 1024])
        use_bn = trial.suggest_categorical("use_batchnorm", [True, False])
        weight_decay = trial.suggest_float("weight_decay", 1e-6, 1e-3, log=True)

        # Build model
        ae = AutoencoderV8(
            input_dim=input_dim,
            bottleneck_dim=bottleneck,
            hidden_dims=tuple(hidden_dims),
            dropout=dropout,
            use_batchnorm=use_bn,
        ).to(device)

        optimizer = torch.optim.Adam(
            ae.model.parameters(), lr=lr, weight_decay=weight_decay
        )
        criterion = nn.MSELoss()

        train_ds = TensorDataset(X_train_t)
        train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

        # Quick training: 30 epochs
        best_val = float("inf")
        no_improve = 0
        for epoch in range(30):
            ae.model.train()
            for (batch,) in train_dl:
                recon = ae.model(batch)
                loss = criterion(recon, batch)
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                optimizer.step()

            ae.model.eval()
            with torch.no_grad():
                val_recon = ae.model(X_val_t)
                val_loss = criterion(val_recon, X_val_t).item()

            if val_loss < best_val:
                best_val = val_loss
                no_improve = 0
            else:
                no_improve += 1
                if no_improve >= 5:
                    break

            trial.report(val_loss, epoch)
            if trial.should_prune():
                raise optuna.TrialPruned()

        del ae, optimizer
        torch.cuda.empty_cache() if torch.cuda.is_available() else None
        gc.collect()

        return best_val

    study = optuna.create_study(
        direction="minimize",
        pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=10),
    )
    study.optimize(objective, n_trials=n_trials, timeout=600, show_progress_bar=True)

    best = study.best_trial
    log.info("=" * 60)
    log.info("OPTUNA BEST TRIAL")
    log.info("=" * 60)
    log.info("  Val MSE:     %.6f", best.value)
    log.info("  Bottleneck:  %d", best.params["bottleneck_dim"])
    n_layers = best.params["n_hidden_layers"]
    hidden = tuple(best.params[f"hidden_{i}"] for i in range(n_layers))
    log.info("  Hidden dims: %s", hidden)
    log.info("  LR:          %.6f", best.params["lr"])
    log.info("  Dropout:     %.2f", best.params["dropout"])
    log.info("  Batch size:  %d", best.params["batch_size"])
    log.info("  BatchNorm:   %s", best.params["use_batchnorm"])
    log.info("  Weight decay:%.6f", best.params["weight_decay"])

    return {
        "bottleneck_dim": best.params["bottleneck_dim"],
        "hidden_dims": hidden,
        "lr": best.params["lr"],
        "dropout": best.params["dropout"],
        "batch_size": best.params["batch_size"],
        "use_batchnorm": best.params["use_batchnorm"],
        "weight_decay": best.params["weight_decay"],
        "optuna_val_mse": best.value,
    }


# Default architecture (if --skip-tuning)
DEFAULT_PARAMS = {
    "bottleneck_dim": 12,
    "hidden_dims": (128, 64, 32),
    "lr": 1e-3,
    "dropout": 0.1,
    "batch_size": 512,
    "use_batchnorm": True,
    "weight_decay": 1e-5,
}


# ═════════════════════════════════════════════════════════════════════════════
#  4. TRAINING
# ═════════════════════════════════════════════════════════════════════════════


def train_autoencoder(
    X_train_normal: np.ndarray,
    X_val_normal: np.ndarray,
    params: Dict[str, Any],
    max_epochs: int = 150,
    patience: int = 15,
) -> Tuple[AutoencoderV8, Dict[str, List[float]]]:
    """
    Train autoencoder on normal-only data with early stopping.

    Returns:
        (trained_ae, history)
    """
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info("=" * 60)
    log.info("AUTOENCODER TRAINING")
    log.info("=" * 60)

    input_dim = X_train_normal.shape[1]
    ae = AutoencoderV8(
        input_dim=input_dim,
        bottleneck_dim=params["bottleneck_dim"],
        hidden_dims=tuple(params["hidden_dims"]),
        dropout=params["dropout"],
        use_batchnorm=params["use_batchnorm"],
    ).to(device)

    log.info("  Architecture:")
    for line in ae.summary().split("\n"):
        log.info("    %s", line)
    log.info("  Device:       %s", device)
    log.info("  LR:           %.6f", params["lr"])
    log.info("  Weight decay: %.6f", params["weight_decay"])
    log.info("  Batch size:   %d", params["batch_size"])
    log.info("  Max epochs:   %d", max_epochs)
    log.info("  Patience:     %d", patience)
    log.info("  Train normal: %d samples", len(X_train_normal))
    log.info("  Val normal:   %d samples", len(X_val_normal))

    # DataLoaders
    use_cuda = device.type == "cuda"
    dl_kwargs = {}
    if use_cuda:
        dl_kwargs["pin_memory"] = True
        dl_kwargs["num_workers"] = 2
        dl_kwargs["persistent_workers"] = True

    X_train_t = torch.from_numpy(X_train_normal).float()
    X_val_t = torch.from_numpy(X_val_normal).float()

    train_ds = TensorDataset(X_train_t)
    val_ds = TensorDataset(X_val_t)
    train_dl = DataLoader(train_ds, batch_size=params["batch_size"], shuffle=True, **dl_kwargs)
    val_dl = DataLoader(val_ds, batch_size=2048, shuffle=False, **dl_kwargs)

    optimizer = torch.optim.Adam(
        ae.model.parameters(),
        lr=params["lr"],
        weight_decay=params["weight_decay"],
    )
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=7, min_lr=1e-6
    )
    criterion = nn.MSELoss()

    # Mixed precision for GPU
    use_amp = use_cuda and hasattr(torch.amp, "GradScaler")
    if use_amp:
        grad_scaler = torch.amp.GradScaler("cuda")
        log.info("  Mixed precision: enabled (fp16)")
    else:
        grad_scaler = None

    history = {"train_loss": [], "val_loss": [], "lr": []}
    best_val_loss = float("inf")
    patience_counter = 0
    best_state = None
    best_epoch = 0

    t0 = time.time()

    for epoch in range(max_epochs):
        # ── Train ──
        ae.model.train()
        train_loss_sum = 0.0
        n_train = 0
        for (batch,) in train_dl:
            batch = batch.to(device, non_blocking=use_cuda)
            if use_amp:
                with torch.amp.autocast("cuda"):
                    recon = ae.model(batch)
                    loss = criterion(recon, batch)
                optimizer.zero_grad(set_to_none=True)
                grad_scaler.scale(loss).backward()
                grad_scaler.step(optimizer)
                grad_scaler.update()
            else:
                recon = ae.model(batch)
                loss = criterion(recon, batch)
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                optimizer.step()
            train_loss_sum += loss.item() * len(batch)
            n_train += len(batch)

        train_loss = train_loss_sum / n_train

        # ── Validate ──
        ae.model.eval()
        val_loss_sum = 0.0
        n_val = 0
        with torch.no_grad():
            for (batch,) in val_dl:
                batch = batch.to(device, non_blocking=use_cuda)
                if use_amp:
                    with torch.amp.autocast("cuda"):
                        recon = ae.model(batch)
                        loss = criterion(recon, batch)
                else:
                    recon = ae.model(batch)
                    loss = criterion(recon, batch)
                val_loss_sum += loss.item() * len(batch)
                n_val += len(batch)

        val_loss = val_loss_sum / n_val
        current_lr = optimizer.param_groups[0]["lr"]

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["lr"].append(current_lr)

        scheduler.step(val_loss)

        # Logging
        if (epoch + 1) % 5 == 0 or epoch == 0 or epoch == max_epochs - 1:
            gap = train_loss - val_loss
            log.info(
                "  Epoch %3d/%d: train=%.6f  val=%.6f  gap=%+.6f  lr=%.2e",
                epoch + 1, max_epochs, train_loss, val_loss, gap, current_lr,
            )

        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            best_epoch = epoch + 1
            best_state = {k: v.cpu().clone() for k, v in ae.model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                log.info("  Early stopping at epoch %d (best epoch=%d, val=%.6f)",
                         epoch + 1, best_epoch, best_val_loss)
                break

    elapsed = time.time() - t0

    # Restore best weights
    if best_state:
        ae.model.load_state_dict(best_state)
    ae.model.eval()

    log.info("  Training complete in %.1f sec", elapsed)
    log.info("  Best epoch: %d  val_loss: %.6f", best_epoch, best_val_loss)
    log.info("  Final train/val gap: %.6f", history["train_loss"][best_epoch - 1] - best_val_loss)

    return ae, history


# ═════════════════════════════════════════════════════════════════════════════
#  5. CALIBRATION
# ═════════════════════════════════════════════════════════════════════════════


def compute_calibration(
    ae: AutoencoderV8,
    X_all: np.ndarray,
    y_all: np.ndarray,
    source_types: np.ndarray,
) -> Dict[str, Dict[str, float]]:
    """
    Compute per-source-type calibration from reconstruction errors on
    normal data. This normalizes the anomaly score across different
    log types (DNS vs firewall vs email all have different baselines).

    Returns:
        {source_type: {"p99_error": float, "p50_error": float}}
    """
    import torch

    log.info("=" * 60)
    log.info("PER-SOURCE-TYPE CALIBRATION")
    log.info("=" * 60)

    device = ae.device
    ae.model.eval()

    # Compute reconstruction errors in batches
    all_mse = []
    batch_size = 8192
    with torch.no_grad():
        for start in range(0, len(X_all), batch_size):
            end = min(start + batch_size, len(X_all))
            chunk = torch.from_numpy(X_all[start:end]).float().to(device)
            recon = ae.model(chunk)
            mse = ((chunk - recon) ** 2).mean(dim=1)
            all_mse.append(mse.cpu().numpy())

    all_mse = np.concatenate(all_mse)

    # Per-source-type calibration (normal data only)
    calibration = {}
    normal_mask = y_all == 0

    for st in np.unique(source_types):
        st_normal_mask = (source_types == st) & normal_mask
        if st_normal_mask.sum() > 10:
            errors = all_mse[st_normal_mask]
            calibration[st] = {
                "p99_error": float(np.percentile(errors, 99)),
                "p50_error": float(np.percentile(errors, 50)),
                "p95_error": float(np.percentile(errors, 95)),
                "mean_error": float(np.mean(errors)),
                "n_samples": int(st_normal_mask.sum()),
            }

    # Default from all normal data
    normal_errors = all_mse[normal_mask]
    calibration["_default"] = {
        "p99_error": float(np.percentile(normal_errors, 99)),
        "p50_error": float(np.percentile(normal_errors, 50)),
        "p95_error": float(np.percentile(normal_errors, 95)),
        "mean_error": float(np.mean(normal_errors)),
        "n_samples": int(normal_mask.sum()),
    }

    log.info("  %-22s %10s %10s %10s %10s %8s",
             "Source", "p50", "p95", "p99", "mean", "N")
    log.info("  " + "-" * 72)
    for st in sorted(calibration.keys()):
        cal = calibration[st]
        log.info("  %-22s %10.6f %10.6f %10.6f %10.6f %8d",
                 st, cal["p50_error"], cal["p95_error"],
                 cal["p99_error"], cal["mean_error"], cal["n_samples"])

    return calibration


# ═════════════════════════════════════════════════════════════════════════════
#  6. EVALUATION
# ═════════════════════════════════════════════════════════════════════════════


def evaluate_autoencoder(
    ae: AutoencoderV8,
    X_test: np.ndarray,
    y_test: np.ndarray,
    source_types_test: np.ndarray,
    calibration: Dict[str, Dict[str, float]],
) -> Dict[str, Any]:
    """
    Evaluate the autoencoder as an anomaly detector on the test set.

    Computes:
      - Reconstruction error distributions (normal vs attack)
      - AUC-ROC using calibrated scores
      - Per-source-type separation quality
      - Score distribution statistics
    """
    import torch
    from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

    log.info("=" * 60)
    log.info("AUTOENCODER EVALUATION (test set)")
    log.info("=" * 60)

    device = ae.device
    ae.model.eval()

    # Compute reconstruction errors
    all_mse = []
    batch_size = 8192
    with torch.no_grad():
        for start in range(0, len(X_test), batch_size):
            end = min(start + batch_size, len(X_test))
            chunk = torch.from_numpy(X_test[start:end]).float().to(device)
            recon = ae.model(chunk)
            mse = ((chunk - recon) ** 2).mean(dim=1)
            all_mse.append(mse.cpu().numpy())
    raw_mse = np.concatenate(all_mse)

    # Calibrated scores
    default_cal = calibration["_default"]
    calibrated_scores = np.zeros(len(raw_mse))
    for i in range(len(raw_mse)):
        st = source_types_test[i]
        cal = calibration.get(st, default_cal)
        p99 = cal.get("p99_error", default_cal["p99_error"])
        if p99 < 1e-10:
            p99 = default_cal["p99_error"]
        calibrated_scores[i] = raw_mse[i] / p99
    calibrated_scores = np.clip(calibrated_scores, 0.0, 1.0)

    normal_mask = y_test == 0
    attack_mask = y_test == 1

    # Raw MSE stats
    log.info("\n  Raw reconstruction error (MSE):")
    log.info("    Normal:  mean=%.6f  median=%.6f  p95=%.6f  p99=%.6f",
             np.mean(raw_mse[normal_mask]), np.median(raw_mse[normal_mask]),
             np.percentile(raw_mse[normal_mask], 95), np.percentile(raw_mse[normal_mask], 99))
    log.info("    Attack:  mean=%.6f  median=%.6f  p95=%.6f  p99=%.6f",
             np.mean(raw_mse[attack_mask]), np.median(raw_mse[attack_mask]),
             np.percentile(raw_mse[attack_mask], 95), np.percentile(raw_mse[attack_mask], 99))
    separation = np.mean(raw_mse[attack_mask]) / max(np.mean(raw_mse[normal_mask]), 1e-10)
    log.info("    Separation ratio (attack_mean / normal_mean): %.2fx", separation)

    # Calibrated score stats
    log.info("\n  Calibrated scores:")
    log.info("    Normal:  mean=%.4f  median=%.4f  p95=%.4f",
             np.mean(calibrated_scores[normal_mask]),
             np.median(calibrated_scores[normal_mask]),
             np.percentile(calibrated_scores[normal_mask], 95))
    log.info("    Attack:  mean=%.4f  median=%.4f  p95=%.4f",
             np.mean(calibrated_scores[attack_mask]),
             np.median(calibrated_scores[attack_mask]),
             np.percentile(calibrated_scores[attack_mask], 95))

    # AUC
    ae_auc = roc_auc_score(y_test, calibrated_scores)
    log.info("\n  AUC-ROC: %.4f", ae_auc)

    # Precision-Recall AUC
    precision, recall, _ = precision_recall_curve(y_test, calibrated_scores)
    pr_auc = auc(recall, precision)
    log.info("  PR-AUC:  %.4f", pr_auc)

    # Per-dataset evaluation
    log.info("\n  Per-source-type AUC:")
    log.info("  %-22s %8s %8s %8s %8s %8s",
             "Source", "AUC", "N", "N_atk", "Norm_err", "Atk_err")
    log.info("  " + "-" * 62)

    per_dataset = {}
    for st in sorted(np.unique(source_types_test)):
        mask = source_types_test == st
        y_st = y_test[mask]
        s_st = calibrated_scores[mask]

        n_atk = (y_st == 1).sum()
        n_norm = (y_st == 0).sum()

        if n_atk > 0 and n_norm > 0:
            st_auc = roc_auc_score(y_st, s_st)
        else:
            st_auc = 0.0

        norm_err = np.mean(raw_mse[mask & normal_mask]) if (mask & normal_mask).sum() > 0 else 0
        atk_err = np.mean(raw_mse[mask & attack_mask]) if (mask & attack_mask).sum() > 0 else 0

        per_dataset[st] = {
            "auc": float(st_auc),
            "n_total": int(mask.sum()),
            "n_attack": int(n_atk),
            "normal_mse": float(norm_err),
            "attack_mse": float(atk_err),
        }
        log.info("  %-22s %8.4f %8d %8d %8.6f %8.6f",
                 st, st_auc, mask.sum(), n_atk, norm_err, atk_err)

    metrics = {
        "ae_auc_roc": float(ae_auc),
        "ae_pr_auc": float(pr_auc),
        "separation_ratio": float(separation),
        "normal_mse_mean": float(np.mean(raw_mse[normal_mask])),
        "attack_mse_mean": float(np.mean(raw_mse[attack_mask])),
        "per_dataset": per_dataset,
    }

    return metrics


# ═════════════════════════════════════════════════════════════════════════════
#  7. ONNX EXPORT & VALIDATION
# ═════════════════════════════════════════════════════════════════════════════


def export_onnx(ae: AutoencoderV8, output_path: Path) -> None:
    """Export PyTorch autoencoder to ONNX format."""
    import torch

    log.info("Exporting autoencoder to ONNX: %s", output_path)

    model = ae.model.cpu()
    model.eval()

    dummy = torch.randn(1, ae.input_dim)
    torch.onnx.export(
        model,
        dummy,
        str(output_path),
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        opset_version=17,
    )

    size_mb = output_path.stat().st_size / (1024 * 1024)
    log.info("  ONNX saved: %.2f MB", size_mb)


def validate_onnx(ae: AutoencoderV8, onnx_path: Path, X_sample: np.ndarray) -> bool:
    """Validate ONNX predictions match PyTorch predictions."""
    import torch
    import onnxruntime as ort

    log.info("Validating ONNX round-trip...")

    # PyTorch predictions
    model = ae.model.cpu()
    model.eval()
    x_t = torch.from_numpy(X_sample[:100]).float()
    with torch.no_grad():
        pt_out = model(x_t).numpy()

    # ONNX predictions
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(None, {"input": X_sample[:100].astype(np.float32)})[0]

    # Compare
    max_diff = np.max(np.abs(pt_out - onnx_out))
    mean_diff = np.mean(np.abs(pt_out - onnx_out))

    log.info("  Max diff:  %.8f", max_diff)
    log.info("  Mean diff: %.8f", mean_diff)

    if max_diff > 0.01:
        log.error("  ONNX VALIDATION FAILED — max diff %.6f > 0.01 threshold", max_diff)
        return False

    log.info("  ONNX validation PASSED ✓")
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  8. MANIFEST UPDATE
# ═════════════════════════════════════════════════════════════════════════════


def update_manifest(
    manifest_path: Path,
    ae_metrics: Dict[str, Any],
    ae_params: Dict[str, Any],
    calibration_path: str,
) -> None:
    """Add autoencoder entry to existing manifest_v8.json."""
    log.info("Updating manifest: %s", manifest_path)

    with open(manifest_path) as f:
        manifest = json.load(f)

    manifest["models"]["autoencoder"] = {
        "file": "autoencoder_v8.onnx",
        "calibration_file": "ae_calibration_v8.json",
        "weight": 0.15,
        "type": "unsupervised",
        "architecture": {
            "input_dim": ae_params.get("input_dim", 60),
            "bottleneck_dim": ae_params["bottleneck_dim"],
            "hidden_dims": list(ae_params["hidden_dims"]),
            "dropout": ae_params.get("dropout", 0.0),
            "use_batchnorm": ae_params.get("use_batchnorm", True),
        },
        "training": {
            "trained_on": "normal_only",
            "loss": "MSE",
            "optimizer": "Adam",
        },
        "metrics": {
            "auc_roc": ae_metrics["ae_auc_roc"],
            "pr_auc": ae_metrics["ae_pr_auc"],
            "separation_ratio": ae_metrics["separation_ratio"],
            "normal_mse_mean": ae_metrics["normal_mse_mean"],
            "attack_mse_mean": ae_metrics["attack_mse_mean"],
        },
    }

    manifest["models"]["autoencoder"]["masked_indices"] = list(AE_MASKED_INDICES_V8)

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    log.info("  Manifest updated with autoencoder entry")


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(description="CLIF v8 Autoencoder Training")
    parser.add_argument("--skip-tuning", action="store_true",
                        help="Skip Optuna search, use default architecture")
    parser.add_argument("--n-trials", type=int, default=50,
                        help="Number of Optuna trials (default: 50)")
    parser.add_argument("--epochs", type=int, default=150,
                        help="Max training epochs (default: 150)")
    parser.add_argument("--patience", type=int, default=15,
                        help="Early stopping patience (default: 15)")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("CLIF v8 — AUTOENCODER TRAINING PIPELINE")
    log.info("=" * 70)
    log.info("  Date:     %s", datetime.now().isoformat())
    log.info("  Tuning:   %s", "SKIP" if args.skip_tuning else f"{args.n_trials} trials")
    log.info("  Epochs:   %d (patience=%d)", args.epochs, args.patience)

    # Check PyTorch
    import torch
    log.info("  PyTorch:  %s", torch.__version__)
    use_cuda = torch.cuda.is_available()
    if use_cuda:
        log.info("  GPU:      %s", torch.cuda.get_device_name(0))
        log.info("  VRAM:     %.1f GB", torch.cuda.get_device_properties(0).total_memory / 1e9)
    else:
        log.info("  GPU:      None (CPU training)")

    # ── 1. Load data ──
    train_df, val_df, test_df, feat_names = load_data()
    n_features = len(feat_names)

    X_train = train_df[feat_names].values.astype(np.float32)
    y_train = train_df["is_malicious"].values
    src_train = train_df["source_dataset"].values

    X_val = val_df[feat_names].values.astype(np.float32)
    y_val = val_df["is_malicious"].values

    X_test = test_df[feat_names].values.astype(np.float32)
    y_test = test_df["is_malicious"].values
    src_test = test_df["source_dataset"].values

    # Data is already z-scored — verify
    train_means = np.abs(X_train.mean(axis=0))
    train_stds = X_train.std(axis=0)
    log.info("  Feature means: max=%.4f (should be ~0)", train_means.max())
    log.info("  Feature stds:  mean=%.4f (should be ~1)", train_stds.mean())

    # ── 2. Filter to normal-only for AE training ──
    normal_train_mask = y_train == 0
    normal_val_mask = y_val == 0

    X_train_normal = X_train[normal_train_mask]
    X_val_normal = X_val[normal_val_mask]

    log.info("  Normal training samples: %d / %d (%.1f%%)",
             len(X_train_normal), len(X_train), 100 * len(X_train_normal) / len(X_train))
    log.info("  Normal val samples:      %d / %d (%.1f%%)",
             len(X_val_normal), len(X_val), 100 * len(X_val_normal) / len(X_val))

    # Apply masking (v8: none needed, but keep the code path)
    if AE_MASKED_INDICES_V8:
        log.info("  Masking %d feature indices: %s", len(AE_MASKED_INDICES_V8), AE_MASKED_INDICES_V8)
        X_train_normal = X_train_normal.copy()
        X_val_normal = X_val_normal.copy()
        X_train_normal[:, list(AE_MASKED_INDICES_V8)] = 0.0
        X_val_normal[:, list(AE_MASKED_INDICES_V8)] = 0.0

    # ── 3. Hyperparameter search ──
    if args.skip_tuning:
        log.info("  Skipping Optuna — using default params")
        best_params = dict(DEFAULT_PARAMS)
    else:
        best_params = run_optuna_search(X_train_normal, X_val_normal, n_trials=args.n_trials)

    best_params["input_dim"] = n_features

    # ── 4. Train final model ──
    ae, history = train_autoencoder(
        X_train_normal, X_val_normal, best_params,
        max_epochs=args.epochs, patience=args.patience,
    )

    # ── 5. Calibration ──
    # Use ALL training data (normal + attack) for reconstruction errors,
    # but calibration percentiles computed from NORMAL data only.
    X_all_train = X_train.copy()
    if AE_MASKED_INDICES_V8:
        X_all_train[:, list(AE_MASKED_INDICES_V8)] = 0.0

    calibration = compute_calibration(ae, X_all_train, y_train, src_train)

    # ── 6. Evaluate on test set ──
    X_test_masked = X_test.copy()
    if AE_MASKED_INDICES_V8:
        X_test_masked[:, list(AE_MASKED_INDICES_V8)] = 0.0

    ae_metrics = evaluate_autoencoder(ae, X_test_masked, y_test, src_test, calibration)

    # ── 7. Export ONNX ──
    onnx_path = MODEL_DIR / "autoencoder_v8.onnx"
    export_onnx(ae, onnx_path)

    onnx_valid = validate_onnx(ae, onnx_path, X_test_masked)
    if not onnx_valid:
        log.error("ONNX validation failed — aborting")
        sys.exit(1)

    # Save calibration
    cal_path = MODEL_DIR / "ae_calibration_v8.json"
    with open(cal_path, "w") as f:
        json.dump(calibration, f, indent=2)
    log.info("Calibration saved: %s", cal_path)

    # ── 8. Update manifest ──
    update_manifest(MANIFEST_PATH, ae_metrics, best_params, str(cal_path))

    # ── Final summary ──
    log.info("")
    log.info("=" * 70)
    log.info("TRAINING COMPLETE")
    log.info("=" * 70)
    log.info("  Model:       %s (%.2f MB)",
             onnx_path, onnx_path.stat().st_size / (1024 * 1024))
    log.info("  Calibration: %s", cal_path)
    log.info("  AUC-ROC:     %.4f", ae_metrics["ae_auc_roc"])
    log.info("  PR-AUC:      %.4f", ae_metrics["ae_pr_auc"])
    log.info("  Separation:  %.2fx (attack/normal MSE ratio)", ae_metrics["separation_ratio"])
    log.info("  Architecture: %d → %s → %d → %s → %d",
             n_features, list(best_params["hidden_dims"]),
             best_params["bottleneck_dim"],
             list(reversed(best_params["hidden_dims"])),
             n_features)
    log.info("  Parameters:  %d", ae.param_count())
    log.info("  ONNX valid:  %s", "✓" if onnx_valid else "✗")

    # Cleanup
    del ae
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


if __name__ == "__main__":
    main()
