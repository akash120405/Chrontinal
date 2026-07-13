"""Benchmark per-type vs global ONNX LightGBM models."""
import onnxruntime as ort, numpy as np, time, os
ort.set_default_logger_severity(3)  # suppress warnings

model_dir = r"c:\CLIF\agents\triage\models"

models = {
    "lgbm_v8 (global, 60f)": ("lgbm_v8.onnx", 60),
    "lgbm_ids (24f)":        ("lgbm_ids.onnx", 24),
    "lgbm_netflow (24f)":    ("lgbm_netflow.onnx", 24),
    "lgbm_auth (17f)":       ("lgbm_auth.onnx", 17),
    "lgbm_dns (17f)":        ("lgbm_dns.onnx", 17),
    "lgbm_email (16f)":      ("lgbm_email.onnx", 16),
    "lgbm_windows (17f)":    ("lgbm_windows.onnx", 17),
}

for batch_size in [1, 10, 100, 1000]:
    print(f"\n=== Batch size: {batch_size} ===")
    print(f"{'Model':<28} {'Size_KB':>9} {'Time_ms':>10} {'Per_evt_us':>14}")
    print("-" * 65)
    for name, (fname, nf) in models.items():
        path = os.path.join(model_dir, fname)
        sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        X = np.random.randn(batch_size, nf).astype(np.float32)
        inp = sess.get_inputs()[0].name
        # warmup
        for _ in range(3):
            sess.run(None, {inp: X})
        # timed
        N = 200
        t0 = time.perf_counter()
        for _ in range(N):
            sess.run(None, {inp: X})
        elapsed = (time.perf_counter() - t0) / N * 1000  # ms
        size_kb = os.path.getsize(path) / 1024
        per_event = elapsed / batch_size * 1000  # microseconds
        print(f"{name:<28} {size_kb:>8.1f} {elapsed:>9.3f} {per_event:>13.1f}")
