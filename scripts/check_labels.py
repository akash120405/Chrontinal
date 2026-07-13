#!/usr/bin/env python3
"""Scan payload NDJSON for ground truth label fields."""
import json, collections

src = collections.Counter()
label_fields = collections.Counter()
attack_patterns = collections.Counter()
sample_msgs = {}

with open('/opt/clif/real_2m_payload.ndjson') as f:
    for i, line in enumerate(f):
        e = json.loads(line)
        st = e.get('source_type', '?')
        src[st] += 1
        msg = e.get('message', '')

        # Check for explicit label fields
        for k in ['label', 'attack_type', 'category', 'is_attack', 'class', 'threat_type']:
            if k in e:
                label_fields[f"{k}={e[k]}"] += 1

        # Infer from message patterns
        msg_lower = msg.lower()
        if 'attack' in msg_lower or 'malicious' in msg_lower or 'exploit' in msg_lower:
            attack_patterns[f"{st}:attack_keyword"] += 1
        elif 'normal' in msg_lower or 'benign' in msg_lower:
            attack_patterns[f"{st}:benign_keyword"] += 1

        # Save one sample per source_type
        if st not in sample_msgs:
            sample_msgs[st] = msg[:200]

print("=== SOURCE TYPES ===")
for k, v in src.most_common(20):
    print(f"  {k}: {v:,}")

print(f"\n=== EXPLICIT LABEL FIELDS ({len(label_fields)}) ===")
for k, v in label_fields.most_common(30):
    print(f"  {k}: {v:,}")

print(f"\n=== INFERRED ATTACK PATTERNS ===")
for k, v in attack_patterns.most_common(20):
    print(f"  {k}: {v:,}")

print(f"\n=== SAMPLE MESSAGES PER SOURCE ===")
for st, msg in sorted(sample_msgs.items()):
    print(f"  [{st}] {msg}")
