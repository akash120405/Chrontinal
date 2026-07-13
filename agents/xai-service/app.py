"""
CLIF XAI Backend Service (port 8200) — v8
==========================================
FastAPI service providing perturbation-based explanations for the dashboard.

Endpoints:
  GET  /xai/status       → service health + model metadata
  GET  /model/features   → global feature importance (Gini impurity)
  POST /explain          → per-event perturbation attribution + classification
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("clif.xai")

# ── Configuration ────────────────────────────────────────────────────────────

MODEL_DIR = os.getenv("MODEL_DIR", "/models")
MODEL_LGBM_PATH = os.getenv("MODEL_LGBM_PATH", f"{MODEL_DIR}/lgbm_v8.onnx")
FEATURE_SCALER_PATH = os.getenv("FEATURE_SCALER_PATH", f"{MODEL_DIR}/feature_scaler_v8.json")
MANIFEST_PATH = os.getenv("MANIFEST_PATH", f"{MODEL_DIR}/manifest_v8.json")
LGBM_TXT_PATH = os.getenv("LGBM_TXT_PATH", f"{MODEL_DIR}/lgbm_v8.txt")
TOP_K = int(os.getenv("SHAP_TOP_K", "10"))
HOST = os.getenv("XAI_HOST", "0.0.0.0")
PORT = int(os.getenv("XAI_PORT", "8200"))

# ── v8 60-feature display names (7 layers) ──────────────────────────────────

DISPLAY_NAMES = {
    # Shared Core (9)
    "hour_sin": "Hour (sin)",
    "hour_cos": "Hour (cos)",
    "dow_sin": "Day of Week (sin)",
    "dow_cos": "Day of Week (cos)",
    "is_off_hours": "Off-Hours Flag",
    "log_type": "Log Type",
    "severity_numeric": "Severity Level",
    "message_length_log": "Message Length (log)",
    "message_entropy": "Message Entropy",
    # Network (15)
    "dst_port_bin": "Destination Port Bin",
    "protocol_numeric": "Protocol",
    "total_bytes_log": "Total Bytes (log)",
    "byte_ratio": "Byte Ratio",
    "total_packets_log": "Total Packets (log)",
    "packet_ratio": "Packet Ratio",
    "flow_duration_log": "Flow Duration (log)",
    "avg_pkt_size": "Avg Packet Size",
    "pkt_size_variance": "Packet Size Variance",
    "iat_mean": "Inter-Arrival Time Mean",
    "iat_stddev": "Inter-Arrival Time Stddev",
    "tcp_syn_flag": "TCP SYN Flag",
    "tcp_rst_flag": "TCP RST Flag",
    "tcp_fin_flag": "TCP FIN Flag",
    "retransmit_ratio": "Retransmit Ratio",
    # Auth (8)
    "auth_type_encoded": "Auth Type",
    "status_is_fail": "Auth Failure",
    "is_admin": "Admin Account",
    "src_dst_match": "Source-Dest Match",
    "is_remote": "Remote Login",
    "fail_rate": "Failure Rate",
    "unique_targets": "Unique Targets",
    "event_frequency": "Event Frequency",
    # DNS (8)
    "domain_length": "Domain Length",
    "domain_entropy": "Domain Entropy",
    "subdomain_depth": "Subdomain Depth",
    "digit_ratio": "Digit Ratio",
    "max_consonant_run": "Max Consonant Run",
    "bigram_frequency": "Bigram Frequency",
    "has_hex_pattern": "Has Hex Pattern",
    "tld_risk": "TLD Risk Score",
    # Web (7)
    "url_length": "URL Length",
    "url_entropy": "URL Entropy",
    "query_param_count": "Query Param Count",
    "has_sql_pattern": "SQL Injection Pattern",
    "has_xss_pattern": "XSS Pattern",
    "has_traversal": "Path Traversal",
    "http_method": "HTTP Method",
    # Email (7)
    "subject_length": "Subject Length",
    "body_length_log": "Body Length (log)",
    "subject_entropy": "Subject Entropy",
    "url_count": "URL Count",
    "caps_ratio": "Caps Ratio",
    "has_urgency": "Urgency Keywords",
    "has_financial": "Financial Keywords",
    # Cloud (6)
    "event_name_encoded": "Cloud Event Name",
    "is_sensitive_service": "Sensitive Service",
    "is_read_only": "Read-Only Action",
    "has_error": "Has Error",
    "identity_type_encoded": "Identity Type",
    "is_root": "Root Account",
}

FEATURE_CATEGORIES = {
    # Shared Core
    "hour_sin": "temporal", "hour_cos": "temporal",
    "dow_sin": "temporal", "dow_cos": "temporal",
    "is_off_hours": "temporal",
    "log_type": "metadata",
    "severity_numeric": "metadata",
    "message_length_log": "text", "message_entropy": "text",
    # Network
    "dst_port_bin": "network", "protocol_numeric": "network",
    "total_bytes_log": "traffic", "byte_ratio": "traffic",
    "total_packets_log": "traffic", "packet_ratio": "traffic",
    "flow_duration_log": "traffic",
    "avg_pkt_size": "traffic", "pkt_size_variance": "traffic",
    "iat_mean": "traffic", "iat_stddev": "traffic",
    "tcp_syn_flag": "network", "tcp_rst_flag": "network",
    "tcp_fin_flag": "network", "retransmit_ratio": "network",
    # Auth
    "auth_type_encoded": "identity", "status_is_fail": "identity",
    "is_admin": "identity", "src_dst_match": "identity",
    "is_remote": "identity", "fail_rate": "frequency",
    "unique_targets": "behavior", "event_frequency": "frequency",
    # DNS
    "domain_length": "dns", "domain_entropy": "dns",
    "subdomain_depth": "dns", "digit_ratio": "dns",
    "max_consonant_run": "dns", "bigram_frequency": "dns",
    "has_hex_pattern": "dns", "tld_risk": "dns",
    # Web
    "url_length": "web", "url_entropy": "web",
    "query_param_count": "web",
    "has_sql_pattern": "threat_intel", "has_xss_pattern": "threat_intel",
    "has_traversal": "threat_intel", "http_method": "web",
    # Email
    "subject_length": "email", "body_length_log": "email",
    "subject_entropy": "email", "url_count": "email",
    "caps_ratio": "email",
    "has_urgency": "threat_intel", "has_financial": "threat_intel",
    # Cloud
    "event_name_encoded": "cloud", "is_sensitive_service": "cloud",
    "is_read_only": "cloud", "has_error": "cloud",
    "identity_type_encoded": "cloud", "is_root": "cloud",
}

# ── Global state ─────────────────────────────────────────────────────────────

app = FastAPI(title="CLIF XAI Service", version="2.0.0")

_lgbm_session = None
_lgbm_input_name: str = ""
_feature_cols: List[str] = []
_manifest: Dict[str, Any] = {}
_feature_importance: Dict[str, int] = {}
_ready = False


def _load_models() -> None:
    """Load ONNX model, feature columns, manifest, and feature importances."""
    global _lgbm_session, _lgbm_input_name, _feature_cols, _manifest
    global _feature_importance, _ready

    import onnxruntime as ort

    # Feature columns — load from v8 scaler JSON or fallback to defaults
    fs_path = Path(FEATURE_SCALER_PATH)
    if fs_path.exists():
        with open(fs_path) as f:
            scaler_data = json.load(f)
        _feature_cols = scaler_data.get("feature_names", list(DISPLAY_NAMES.keys()))
        logger.info("Feature columns loaded from scaler: %d", len(_feature_cols))
    else:
        logger.warning("feature_scaler not found — using hardcoded v8 defaults")
        _feature_cols = list(DISPLAY_NAMES.keys())

    # Manifest
    mp = Path(MANIFEST_PATH)
    if mp.exists():
        with open(mp) as f:
            _manifest = json.load(f)
        logger.info("Manifest loaded: %s", _manifest.get("version", "?"))

    # LightGBM ONNX
    lgbm_path = Path(MODEL_LGBM_PATH)
    if not lgbm_path.exists():
        logger.error("LightGBM ONNX not found: %s", MODEL_LGBM_PATH)
        return

    opts = ort.SessionOptions()
    opts.inter_op_num_threads = 1
    opts.intra_op_num_threads = 2
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    _lgbm_session = ort.InferenceSession(
        str(lgbm_path), providers=["CPUExecutionProvider"], sess_options=opts,
    )
    _lgbm_input_name = _lgbm_session.get_inputs()[0].name
    logger.info("LightGBM ONNX loaded: %s", lgbm_path)

    # Feature importance from LightGBM text model
    txt_path = Path(LGBM_TXT_PATH)
    if txt_path.exists():
        _parse_feature_importance(txt_path)
    else:
        logger.warning("LightGBM text file not found — no global importance")

    _ready = True
    logger.info("XAI service ready (features=%d, top_k=%d)", len(_feature_cols), TOP_K)


def _parse_feature_importance(txt_path: Path) -> None:
    """Parse feature_importances section from LightGBM text model file."""
    global _feature_importance
    in_section = False
    for line in txt_path.read_text().splitlines():
        if line.strip() == "feature_importances:":
            in_section = True
            continue
        if in_section:
            m = re.match(r"^(\w+)=(\d+)$", line.strip())
            if m:
                _feature_importance[m.group(1)] = int(m.group(2))
            else:
                break  # End of section
    logger.info("Parsed %d feature importances", len(_feature_importance))


def _predict(X: np.ndarray) -> np.ndarray:
    """Run LightGBM inference. Returns anomaly probability array."""
    if X.dtype != np.float32:
        X = X.astype(np.float32)
    results = _lgbm_session.run(None, {_lgbm_input_name: X})
    if len(results) >= 2:
        return np.array(
            [d.get(1, d.get("1", 0.0)) for d in results[1]], dtype=np.float64,
        )
    return np.clip(np.array(results[0], dtype=np.float64).flatten(), 0.0, 1.0)


def _shap_explain(X_single: np.ndarray) -> Dict[str, Any]:
    """Perturbation-based SHAP attribution for a single event."""
    base_score = float(_predict(X_single)[0])
    contributions = []
    for i, fname in enumerate(_feature_cols):
        perturbed = X_single.copy()
        perturbed[0, i] = 0.0
        delta = base_score - float(_predict(perturbed)[0])
        contributions.append((fname, delta, float(X_single[0, i])))

    contributions.sort(key=lambda x: abs(x[1]), reverse=True)
    top = contributions[:TOP_K]

    # Build structured output
    features_out = []
    category_agg: Dict[str, float] = {}
    for name, delta, raw_val in top:
        cat = FEATURE_CATEGORIES.get(name, "other")
        features_out.append({
            "feature": name,
            "display_name": DISPLAY_NAMES.get(name, name),
            "shap_value": round(delta, 6),
            "abs_shap_value": round(abs(delta), 6),
            "feature_value": round(raw_val, 4),
            "raw_value": round(raw_val, 4),
            "impact": "positive" if delta > 0 else "negative",
            "category": cat,
        })
        category_agg[cat] = category_agg.get(cat, 0) + abs(delta)

    # Waterfall data
    waterfall = {
        "base_value": 0.5,
        "output_value": round(base_score, 6),
        "features": [
            {"feature": DISPLAY_NAMES.get(n, n), "value": round(d, 6)}
            for n, d, _ in top
        ],
    }

    # Human-readable summary
    parts = [
        f"{DISPLAY_NAMES.get(n, n)}={v:.2f} ({'+' if d > 0 else ''}{d:.4f})"
        for n, d, v in top[:5]
    ]
    drivers = f"Score {base_score:.4f} driven by: {', '.join(parts)}" if parts else ""

    return {
        "top_features": features_out,
        "waterfall": waterfall,
        "prediction_drivers": drivers,
        "category_attribution": {k: round(v, 6) for k, v in category_agg.items()},
        "model_type": "LightGBM (Binary)",
        "explainer_type": "Perturbation-based",
    }


def _classify_score(score: float) -> Dict[str, Any]:
    """Classify an anomaly score into attack/benign with category + severity."""
    is_attack = score >= 0.5
    if score >= 0.95:
        severity = "critical"
        category = "High-Confidence Attack"
    elif score >= 0.85:
        severity = "high"
        category = "Likely Attack"
    elif score >= 0.70:
        severity = "medium"
        category = "Suspicious Activity"
    elif score >= 0.50:
        severity = "low"
        category = "Possible Anomaly"
    else:
        severity = "info"
        category = "Normal" if score < 0.3 else "Low-Risk"
    return {
        "is_attack": is_attack,
        "confidence": round(score if is_attack else (1.0 - score), 4),
        "category": category,
        "severity": severity,
    }


# ── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    _load_models()


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/xai/status")
async def xai_status():
    lgbm_info = _manifest.get("lgbm", {})
    return {
        "available": _ready,
        "explainer_type": "Perturbation-based (per-feature zeroing)",
        "feature_count": len(_feature_cols),
        "top_k": TOP_K,
        "model_types": {
            "binary": "LightGBMClassifier",
            "multiclass": "N/A",
        },
        "model_version": _manifest.get("version", "unknown"),
        "trained_at": _manifest.get("trained_at"),
        "metrics": lgbm_info.get("metrics", {}),
    }


@app.get("/model/features")
async def model_features():
    total_imp = max(sum(_feature_importance.values()), 1)
    features = []
    for fname in _feature_cols:
        imp = _feature_importance.get(fname, 0)
        features.append({
            "feature": fname,
            "display_name": DISPLAY_NAMES.get(fname, fname),
            "importance": round(imp / total_imp, 6),
            "category": FEATURE_CATEGORIES.get(fname, "other"),
        })
    features.sort(key=lambda f: f["importance"], reverse=True)
    return {"features": features, "total_features": len(_feature_cols)}


@app.post("/explain")
async def explain_event(request: Request):
    if not _ready:
        return JSONResponse(
            {"error": "XAI service not ready"}, status_code=503,
        )

    try:
        raw_body = await request.body()
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return JSONResponse(
            {"error": f"Invalid JSON in request body: {e}"}, status_code=400,
        )

    # Build feature vector from request body
    vals = []
    for fname in _feature_cols:
        v = body.get(fname, 0.0)
        try:
            vals.append(float(v))
        except (TypeError, ValueError):
            vals.append(0.0)

    X = np.array([vals], dtype=np.float32)
    score = float(_predict(X)[0])

    classification = _classify_score(score)
    xai_data = _shap_explain(X)

    return {
        **classification,
        "explanation": xai_data["prediction_drivers"],
        "xai": xai_data,
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "ready": _ready}


# ── Cluster Health (aggregated agent health for dashboard) ───────────────────

import httpx  # noqa: E402 — late import, only used by cluster endpoint

CLUSTER_AGENTS = [
    {"name": "triage",   "url": "http://clif-triage-agent:8300/health"},
    {"name": "hunter",   "url": "http://clif-hunter-agent:8400/health"},
    {"name": "verifier", "url": "http://clif-verifier-agent:8500/health"},
    {"name": "xai",      "url": "http://localhost:8200/health"},
]


@app.get("/cluster/health")
async def cluster_health():
    """Check health of all AI agents from within the Docker network."""
    results = []
    async with httpx.AsyncClient(timeout=3.0) as client:
        for agent in CLUSTER_AGENTS:
            try:
                resp = await client.get(agent["url"])
                data = resp.json()
                results.append({
                    "name": agent["name"],
                    "status": "active" if data.get("status") in ("healthy", "ok") else data.get("status", "unknown"),
                    "health": data,
                })
            except Exception:
                results.append({
                    "name": agent["name"],
                    "status": "unreachable",
                    "health": {},
                })
    return {"agents": results}


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
