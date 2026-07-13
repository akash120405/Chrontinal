"""One-time fix for corrupted test_standalone_models.py"""
import pathlib

p = pathlib.Path(r"c:\CLIF\scripts\test_standalone_models.py")
content = p.read_text(encoding="utf-8")

# Fix 1: Remove duplicate empty _grade(f1): stub (line 1068-1069)
# There's "def _grade(f1):\n\ndef _grade(f1):" — remove first empty one
old1 = "def _grade(f1):\r\n\r\ndef _grade(f1):"
new1 = "def _grade(f1):"
if old1 in content:
    content = content.replace(old1, new1)
    print("Fix 1: Removed duplicate _grade stub (CRLF)")
else:
    old1_lf = old1.replace("\r\n", "\n")
    if old1_lf in content:
        content = content.replace(old1_lf, new1)
        print("Fix 1: Removed duplicate _grade stub (LF)")
    else:
        print("Fix 1: Pattern not found, skipping")

# Fix 2: Replace the tripled grade comparison section
# Find the start: '        change = "" if gm == gf else f"{gm} -> {gf}"'
# and end: the old code 'print(f"    {desc:<30} Grade: {grade:<5} {status}")'
# Replace with correct code

old2_marker = 'change = "" if gm == gf else f"{gm} -> {gf}"'
idx = content.find(old2_marker)
if idx == -1:
    print("Fix 2: Start marker not found, skipping")
else:
    # Find the end of the corrupted section — look for "# ── Main"
    end_marker = "# ── Main"
    end_idx = content.find(end_marker, idx)
    if end_idx == -1:
        print("Fix 2: End marker not found, skipping")
    else:
        # Get line ending style
        le = "\r\n" if "\r\n" in content else "\n"
        
        # Find start of the line with 'change = ...'
        line_start = content.rfind(le, 0, idx)
        if line_start == -1:
            line_start = 0
        else:
            line_start += len(le)
        
        # Build replacement
        replacement = (
            f'        change = "" if gm == gf else f"{{gm}} -> {{gf}}"{le}'
            f'        print(f"  {{desc:<30}} {{gm:>12}} {{gf:>12}} {{change:>12}}"){le}'
            f'    print(){le}'
            f'{le}'
            f'{le}'
        )
        
        content = content[:line_start] + replacement + content[end_idx:]
        print(f"Fix 2: Replaced corrupted grade comparison (chars {line_start}-{end_idx})")

p.write_text(content, encoding="utf-8")
print("File written successfully")

# Verify
content2 = p.read_text(encoding="utf-8")
print(f"File length: {len(content2)}")
if "fused_scoreses" in content2:
    print("WARNING: fused_scoreses still present!")
if "grades.get" in content2:
    print("WARNING: old grades.get still present!")
if content2.count("def _grade") == 1:
    print("OK: Exactly 1 _grade definition")
else:
    print(f"WARNING: {content2.count('def _grade')} _grade definitions")
