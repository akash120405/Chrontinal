"""Check how many EVTX events match various detection rules."""
import sys, os, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'agents' / 'triage'))

import Evtx.Evtx as evtx
from lxml import etree

EVTX_DIR = ROOT / "agents" / "Data" / "Latest_Dataset" / "02_Windows_Event" / "EVTX-ATTACK-SAMPLES"

# Current detection rules
SUSPICIOUS_EXES = {'powershell', 'pwsh', 'cmd', 'certutil', 'mshta', 'regsvr32',
    'rundll32', 'wmic', 'cscript', 'wscript', 'bitsadmin', 'msiexec',
    'psexec', 'net', 'net1', 'taskkill', 'schtasks', 'at', 'reg',
    'sc', 'whoami', 'nltest', 'dsquery', 'csvde', 'ldifde', 'ntdsutil',
    'vssadmin', 'wevtutil', 'bcdedit', 'fsutil', 'cipher', 'netsh'}

SUSPICIOUS_CMD = ['-enc', '-encodedcommand', 'invoke-expression', 'iex(', 'iex ',
    'invoke-mimikatz', 'invoke-command', 'downloadstring', 'downloadfile',
    'system.net.webclient', 'bitstransfer', 'start-bitstransfer',
    'net user', 'net localgroup', 'net group', 'whoami /priv',
    'mimikatz', 'sekurlsa', 'kerberos::list', 'lsadump',
    'procdump', 'comsvcs.dll', 'minidump', 'createdump',
    'reg save', 'reg export', 'shadow', 'vssadmin',
    'set-mppreference', 'add-mppreference', '-exclusion',
    '\\\\\\\\', 'invoke-wmimethod', 'invoke-cimmethod',
    'new-psdrive', 'test-netconnection', 'hidden', '-nop',
    '-w hidden', '-windowstyle', '-noprofile', '-executionpolicy bypass',
    'frombase64string']

CREDENTIAL_TARGETS = {'lsass.exe', 'lsass'}
PERSISTENCE_INDICATORS = ['\\currentversion\\run', '\\services\\', '\\startup']
SUSPICIOUS_PARENTS = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
    'mshta.exe', 'cscript.exe', 'wscript.exe', 'explorer.exe'}

# NEW expanded patterns
TEMP_PATTERNS = ['\\temp\\', '\\tmp\\', 'appdata\\local\\temp', 'appdata\\roaming']
SENSITIVE_FILES = ['login data', 'ntds.dit', 'sam', 'system32\\config\\sam',
    'security', 'credentials', '.kdbx', 'password', 'id_rsa',
    'web data', 'cookies']

# Parse and check each event
results = Counter()
total_attack = 0
sysmon_matched = 0
sysmon_total = 0
security_matched = 0
security_total = 0
bits_matched = 0
bits_total = 0
rdp_total = 0
defender_total = 0
other_matched = 0
other_total = 0

category_hits = Counter()
eid_hits = Counter()
eid_totals = Counter()
match_reasons = Counter()

categories = sorted([d.name for d in EVTX_DIR.iterdir() if d.is_dir()])
for cat in categories:
    cat_dir = EVTX_DIR / cat
    for evtx_path in sorted(cat_dir.glob("*.evtx")):
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
                        channel = (channel_node.text or '').lower() if channel_node is not None else ''
                        
                        provider_node = root.find('.//e:System/e:Provider', ns)
                        provider = (provider_node.get('Name', '') or '').lower() if provider_node is not None else ''

                        # Build message from EventData
                        event_data = root.find('.//e:EventData', ns)
                        parts = []
                        fields = {}
                        if event_data is not None:
                            for dn in event_data:
                                name = dn.get('Name', 'data')
                                val = (dn.text or '')
                                parts.append(f"{name}={val}")
                                fields[name.lower()] = val.lower()
                        msg = ' | '.join(parts).lower()
                        
                        total_attack += 1
                        eid_totals[eid] += 1
                        triggered = False
                        reasons = []

                        # === Sysmon checks ===
                        if 'sysmon' in channel or 'sysmon' in provider:
                            sysmon_total += 1
                            image = fields.get('image', '')
                            parent_image = fields.get('parentimage', '')
                            target = fields.get('targetfilename', fields.get('targetobject', ''))
                            cmd_line = fields.get('commandline', '')
                            
                            exe_name = image.rsplit('\\', 1)[-1].rsplit('.', 1)[0] if image else ''
                            parent_name = parent_image.rsplit('\\', 1)[-1].rsplit('.', 1)[0] if parent_image else ''
                            
                            # Original rules
                            if exe_name in SUSPICIOUS_EXES:
                                triggered = True
                                reasons.append(f'suspicious_exe:{exe_name}')
                            if any(p in msg for p in SUSPICIOUS_CMD):
                                triggered = True
                                reasons.append('suspicious_cmd')
                            if any(t in image for t in CREDENTIAL_TARGETS):
                                triggered = True
                                reasons.append('credential_target')
                            if any(p in target for p in PERSISTENCE_INDICATORS):
                                triggered = True
                                reasons.append('persistence')
                            if parent_name in SUSPICIOUS_PARENTS and exe_name in {'cmd', 'powershell', 'pwsh'}:
                                triggered = True
                                reasons.append('suspicious_parent')
                            
                            # NEW: Temp directory execution
                            if any(p in image for p in TEMP_PATTERNS):
                                triggered = True
                                reasons.append('temp_execution')
                            
                            # NEW: EID 8 (CreateRemoteThread) always suspicious
                            if eid == 8:
                                triggered = True
                                reasons.append('remote_thread')
                            
                            # NEW: EID 10 (ProcessAccess) to lsass
                            if eid == 10 and 'lsass' in msg:
                                triggered = True
                                reasons.append('lsass_access')
                            
                            # NEW: EID 17/18 (Pipe) with known attack pipes
                            if eid in (17, 18):
                                triggered = True
                                reasons.append('named_pipe')
                            
                            # NEW: EID 19/20 (WMI events) always suspicious
                            if eid in (19, 20):
                                triggered = True
                                reasons.append('wmi_event')
                            
                            # NEW: Any process with suspicious parent (not just cmd/ps)
                            if parent_name in SUSPICIOUS_PARENTS:
                                triggered = True
                                reasons.append(f'any_child_of:{parent_name}')
                            
                            # NEW: RuleName field contains a rule match (Sysmon rules)
                            rulename = fields.get('rulename', '')
                            if rulename and rulename != '(empty)' and rulename.strip():
                                triggered = True
                                reasons.append(f'sysmon_rulename:{rulename[:30]}')
                            
                            if triggered:
                                sysmon_matched += 1
                        
                        # === Security checks ===
                        elif 'security' in channel:
                            security_total += 1
                            obj_name = fields.get('objectname', '')
                            
                            # Existing severity check
                            if eid in {4625, 4697, 4698, 4699, 4720, 4732, 1102}:
                                triggered = True
                                reasons.append(f'security_high:{eid}')
                            elif eid in {4624, 4648, 4672, 4688, 4719}:
                                triggered = True
                                reasons.append(f'security_med:{eid}')
                            
                            # NEW: Object access to sensitive files
                            if eid == 4663 and any(s in obj_name for s in SENSITIVE_FILES):
                                triggered = True
                                reasons.append('sensitive_file_access')
                            
                            # NEW: AD modifications
                            if eid == 5136:
                                triggered = True
                                reasons.append('ad_modification')
                            
                            # NEW: Audit policy changes
                            if eid == 4719:
                                triggered = True
                                reasons.append('audit_policy_change')
                            
                            # NEW: Log cleared
                            if eid == 1102:
                                triggered = True
                                reasons.append('log_cleared')

                            if triggered:
                                security_matched += 1
                        
                        # === BITS checks ===
                        elif 'bits' in channel:
                            bits_total += 1
                            url = fields.get('url', '')
                            name = fields.get('name', '')
                            
                            # NEW: Flag BITS with non-Microsoft/Google URLs or suspicious filenames
                            if url and not any(d in url for d in ['microsoft.com', 'google.com', 'windowsupdate.com', 'windows.net']):
                                triggered = True
                                reasons.append('bits_suspicious_url')
                            
                            # NEW: BITS downloading to temp
                            if any(p in name for p in TEMP_PATTERNS):
                                triggered = True
                                reasons.append('bits_temp_download')
                            
                            # NEW: Any BITS activity during attack = at least note it
                            # This is the "context" problem - BITS events ARE attack artifacts
                            # but individual events look benign
                            
                            if triggered:
                                bits_matched += 1
                        
                        # === RDP checks ===
                        elif 'remotedesktop' in channel or 'terminal' in channel:
                            rdp_total += 1
                            # RDP channel events are inherently ambiguous
                            # Can't distinguish attack RDP from legitimate RDP
                        
                        # === Defender checks ===
                        elif 'defender' in channel:
                            defender_total += 1
                            triggered = True
                            reasons.append('defender_alert')
                        
                        else:
                            other_total += 1
                            if eid == 5156:  # Windows Filtering Platform
                                triggered = True
                                reasons.append('wfp_connection')
                            if triggered:
                                other_matched += 1
                        
                        if triggered:
                            results['matched'] += 1
                            category_hits[cat] += 1
                            eid_hits[eid] += 1
                            for r in reasons:
                                match_reasons[r] += 1
                    except Exception:
                        pass
        except Exception:
            pass

matched = results.get('matched', 0)
print(f"Total attack events: {total_attack}")
print(f"Total matched by expanded rules: {matched} ({matched/total_attack*100:.1f}%)")
print(f"\nBy channel:")
print(f"  Sysmon:   {sysmon_matched:>4}/{sysmon_total:<4} ({sysmon_matched/max(1,sysmon_total)*100:.0f}%)")
print(f"  Security: {security_matched:>4}/{security_total:<4} ({security_matched/max(1,security_total)*100:.0f}%)")
print(f"  BITS:     {bits_matched:>4}/{bits_total:<4} ({bits_matched/max(1,bits_total)*100:.0f}%)")
print(f"  RDP:      {'N/A':>4}/{rdp_total:<4} (not detectable individually)")
print(f"  Defender: {defender_total:>4}/{defender_total:<4} (100%)")
print(f"  Other:    {other_matched:>4}/{other_total:<4}")

print(f"\nTop match reasons:")
for reason, count in match_reasons.most_common(20):
    print(f"  {reason}: {count}")

print(f"\nEID detection rate (matched / total):")
for eid, total in eid_totals.most_common(20):
    hits = eid_hits.get(eid, 0)
    pct = hits / total * 100 if total > 0 else 0
    print(f"  EID {eid:>5}: {hits:>4}/{total:<4} ({pct:>5.1f}%)")

print(f"\nCategory detection rate:")
for cat in categories:
    cat_dir = EVTX_DIR / cat
    cat_total = sum(1 for _ in cat_dir.glob("*.evtx"))
    # This is approximate - count from eid_by_category
    cat_hit = category_hits.get(cat, 0)
    print(f"  {cat}: {cat_hit} matched")

print(f"\n--- Theoretical max recall with expanded rules ---")
print(f"  Matched: {matched}/{total_attack} = {matched/total_attack:.1%}")
# With 2000 synthetic benign events that should NOT match
total_events = total_attack + 2000
print(f"  Recall = {matched}/{total_attack} = {matched/total_attack:.3f}")
print(f"  If all matches are true positive and no benign matches: F1 = 2*1.0*{matched/total_attack:.3f}/(1.0+{matched/total_attack:.3f}) = {2*1.0*matched/total_attack/(1.0+matched/total_attack):.3f}")
