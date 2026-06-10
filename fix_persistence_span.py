#!/usr/bin/env python3
"""
Fix persistence_tracker.py span_days calculation.
Problem: _extract_session_fingerprint sets prior_start/prior_end to None.
Fix: Read generated_at from the report dict and store as prior_start.
"""

path = r"C:\RH\rayhunter-threat-analyzer\detectors\persistence_tracker.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix: populate prior_start from generated_at in _extract_session_fingerprint
OLD_FINGERPRINT = '''            return {
                "label":       report.get("_report_file", "unknown"),
                "cids":        cids,
                "jitter_ms":   jitter_ms,
                "techniques":  techniques,
                "prior_start": None,
                "prior_end":   None,
            }'''

NEW_FINGERPRINT = '''            # Extract report date from generated_at field
            prior_start = None
            gen_at = report.get("generated_at")
            if gen_at:
                try:
                    from datetime import timezone
                    gen_str = str(gen_at).replace("Z", "+00:00")
                    prior_start = datetime.fromisoformat(gen_str)
                    if prior_start.tzinfo is None:
                        prior_start = prior_start.replace(tzinfo=timezone.utc)
                except (ValueError, AttributeError):
                    prior_start = None

            return {
                "label":       report.get("_report_file", "unknown"),
                "cids":        cids,
                "jitter_ms":   jitter_ms,
                "techniques":  techniques,
                "prior_start": prior_start,
                "prior_end":   prior_start,  # use same date for both
            }'''

if OLD_FINGERPRINT not in content:
    print("ERROR: Could not find fingerprint return block")
    idx = content.find('"prior_start": None')
    print("Context:", content[idx-100:idx+200])
else:
    content = content.replace(OLD_FINGERPRINT, NEW_FINGERPRINT)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — prior_start now populated from generated_at")
