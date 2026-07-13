"""Test XAI explain endpoint with synthetic feature vector."""
import json
import random
import urllib.request

# Get feature names
f = json.loads(urllib.request.urlopen("http://10.52.166.71:8200/model/features", timeout=10).read())
feature_names = [x["feature"] for x in f["features"]]
print("Feature count:", len(feature_names))

# Build a request with plausible values
random.seed(42)
body = {}
for fn in feature_names:
    if "entropy" in fn:
        body[fn] = 4.8
    elif "length" in fn or "bytes" in fn:
        body[fn] = 6.5
    elif "port" in fn:
        body[fn] = 3389.0
    elif "hour" in fn:
        body[fn] = 0.5
    else:
        body[fn] = random.random() * 2

req = urllib.request.Request(
    "http://10.52.166.71:8200/explain",
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json"},
)
d = json.loads(urllib.request.urlopen(req, timeout=30).read())

print("\n=== XAI Explain Result ===")
print("Keys:", list(d.keys()))
print("Score:", d.get("score"))
print("Label:", d.get("label"))
print("Confidence:", d.get("confidence"))
print("Risk level:", d.get("risk_level"))

expl = d.get("explanation", [])
print(f"\nExplanation type: {type(expl).__name__}, len: {len(expl) if isinstance(expl, list) else 'N/A'}")
if isinstance(expl, list) and expl:
    print("First item type:", type(expl[0]).__name__)
    if isinstance(expl[0], dict):
        print("First item:", expl[0])
    else:
        print("First 3:", expl[:3])

xai = d.get("xai", {})
print("\nXAI keys:", list(xai.keys()))
drivers = xai.get("prediction_drivers", [])
print(f"Drivers type: {type(drivers).__name__}")
if isinstance(drivers, str):
    print("Drivers (first 500 chars):", drivers[:500])
elif isinstance(drivers, list) and drivers:
    print(f"Drivers count: {len(drivers)}")
    print("Driver[0]:", drivers[0])

top = xai.get("top_features", [])
print(f"\nTop features type: {type(top).__name__}, count: {len(top) if isinstance(top, list) else 'N/A'}")
if isinstance(top, list) and top:
    print("top_features[0]:", top[0])
    for tf in top[:5]:
        print(f"  {tf.get('feature','?')}: importance={tf.get('importance',0):.4f}")

wf = xai.get("waterfall", [])
print(f"\nWaterfall type: {type(wf).__name__}, count: {len(wf) if isinstance(wf, list) else 'N/A'}")
if isinstance(wf, list) and wf:
    print("waterfall[0]:", wf[0])

cat = xai.get("category_attribution", {})
print(f"\nCategory attribution: {json.dumps(cat, indent=2)[:300] if cat else 'empty'}")

cf = xai.get("counterfactual")
if cf:
    print("\nCounterfactual:", json.dumps(cf, indent=2)[:300])
