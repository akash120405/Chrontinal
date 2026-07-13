"""Analyze Windows EVTX attack events — what EventIDs and content patterns exist."""
import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
os.environ['ONNXRUNTIME_LOG_SEVERITY'] = '4'

from pathlib import Path
from collections import Counter
import re

ROOT = Path(__file__).resolve().parent.parent
TRIAGE_DIR = ROOT / "agents" / "triage"
sys.path.insert(0, str(TRIAGE_DIR))

# We need the EVTX parser
try:
    import Evtx.Evtx as evtx
    from lxml import etree
except ImportError:
    print("Need python-evtx and lxml: pip install python-evtx lxml")
    sys.exit(1)

EVTX_DIR = ROOT / "agents" / "Data" / "Latest_Dataset" / "02_Windows_Event" / "EVTX-ATTACK-SAMPLES"

# Parse a sample of EVTX events
eid_counter = Counter()
channel_counter = Counter()
provider_counter = Counter()
eid_by_category = {}
sample_messages = {}  # eid -> list of message samples

categories = sorted([d.name for d in EVTX_DIR.iterdir() if d.is_dir()])
total = 0
for cat in categories:
    cat_dir = EVTX_DIR / cat
    cat_eids = Counter()
    for evtx_path in sorted(cat_dir.glob("*.evtx"))[:5]:  # first 5 files per cat
        try:
            with evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = etree.fromstring(xml_str.encode('utf-8', errors='replace'))
                        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                        
                        eid_node = root.find('.//e:System/e:EventID', ns)
                        eid = int(eid_node.text) if eid_node is not None and eid_node.text else 0
                        
                        channel_node = root.find('.//e:System/e:Channel', ns)
                        channel = channel_node.text if channel_node is not None else ''
                        
                        provider_node = root.find('.//e:System/e:Provider', ns)
                        provider = provider_node.get('Name', '') if provider_node is not None else ''
                        
                        eid_counter[eid] += 1
                        channel_counter[channel] += 1
                        provider_counter[provider] += 1
                        cat_eids[eid] += 1
                        total += 1
                        
                        # Collect sample EventData for each EID
                        if eid not in sample_messages or len(sample_messages[eid]) < 2:
                            event_data = root.find('.//e:EventData', ns)
                            if event_data is not None:
                                parts = []
                                for data_node in event_data:
                                    name = data_node.get('Name', 'data')
                                    val = data_node.text or ''
                                    parts.append(f"{name}={val[:80]}")
                                msg = ' | '.join(parts)
                            else:
                                msg = '(no EventData)'
                            if eid not in sample_messages:
                                sample_messages[eid] = []
                            sample_messages[eid].append(f"[{cat}] {msg[:300]}")
                    except Exception:
                        pass
        except Exception:
            pass
    eid_by_category[cat] = cat_eids

print(f"Total events parsed: {total}")
print(f"\n{'=' * 80}")
print("Top 30 EventIDs:")
print(f"{'=' * 80}")
for eid, count in eid_counter.most_common(30):
    pct = count / total * 100
    # Check if this would be caught by Sysmon detector
    sysmon_eids = {1, 3, 5, 7, 8, 10, 11, 12, 13, 15, 17, 22, 23, 25, 26}
    security_eids = {4625, 4624, 4648, 4672, 4688, 4697, 4698, 4699, 4720, 4732, 1102}
    tag = ""
    if eid in sysmon_eids:
        tag = " [SYSMON]"
    elif eid in security_eids:
        tag = " [SECURITY]"
    print(f"  EID {eid:>6}: {count:>5} ({pct:>5.1f}%){tag}")

print(f"\n{'=' * 80}")
print("EventIDs by MITRE Category:")
print(f"{'=' * 80}")
for cat, eids in sorted(eid_by_category.items()):
    print(f"\n  {cat}:")
    for eid, count in eids.most_common(10):
        sysmon_eids = {1, 3, 5, 7, 8, 10, 11, 12, 13, 15, 17, 22, 23, 25, 26}
        security_eids = {4625, 4624, 4648, 4672, 4688, 4697, 4698, 4699, 4720, 4732, 1102}
        tag = ""
        if eid in sysmon_eids:
            tag = " [SYSMON]"
        elif eid in security_eids:
            tag = " [SECURITY]"
        print(f"    EID {eid:>6}: {count:>4}{tag}")

print(f"\n{'=' * 80}")
print("Sample EventData for top EventIDs:")
print(f"{'=' * 80}")
for eid, _ in eid_counter.most_common(15):
    print(f"\n  EID {eid}:")
    for msg in sample_messages.get(eid, [])[:1]:
        print(f"    {msg[:300]}")

print(f"\n{'=' * 80}")
print("Channels:")
for ch, count in channel_counter.most_common():
    print(f"  {ch}: {count}")
print(f"\nProviders:")
for p, count in provider_counter.most_common(15):
    print(f"  {p}: {count}")
