import re

with open('main.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove from primary_detectors list
old = '    if _HAS_OP_PROFILE:         primary_detectors.append(OperationalProfileSynthesiser(cfg))\n'
new = '    # OperationalProfileSynthesiser runs AFTER the detector loop (needs all_findings)\n'
content = content.replace(old, new)

# Find where all_findings loop ends and insert post-loop call
old2 = '    # -- Hardware Fingerprinting'
new2 = '''    # -- OperationalProfileSynthesiser (runs after all findings are collected)
    if _HAS_OP_PROFILE:
        try:
            op_synth = OperationalProfileSynthesiser(cfg)
            op_synth.set_findings(all_findings)
            op_findings = op_synth.analyze(all_events)
            if op_findings:
                print(f"  -> {len(op_findings)} finding(s): OperationalProfileSynthesiser")
            all_findings.extend(op_findings)
        except Exception as exc:
            print(f"  [WARN] OperationalProfileSynthesiser error: {exc}")

    # -- Hardware Fingerprinting'''
content = content.replace(old2, new2)

with open('main.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("main.py patched")
