path = r'C:\RH\rayhunter-threat-analyzer\detectors\attack_campaign_segmenter.py'
with open(path, 'r') as f:
    content = f.read()

old = '            start_ts = ts_events[start_idx][0]\n            end_ts   = ts_events[end_idx-1][0]\n            duration_days = (end_ts - start_ts) / 86400'
new = '''            start_ts = ts_events[start_idx][0]
            end_ts   = ts_events[end_idx-1][0]
            # Clamp to valid investigation window (2025-01-01 to 2027-01-01)
            MIN_TS = 1735689600  # 2025-01-01 UTC
            MAX_TS = 1798761600  # 2027-01-01 UTC
            start_ts_clamped = max(min(start_ts, MAX_TS), MIN_TS)
            end_ts_clamped   = max(min(end_ts, MAX_TS), MIN_TS)
            duration_days = (end_ts_clamped - start_ts_clamped) / 86400'''

if old in content:
    content = content.replace(old, new)
    with open(path, 'w') as f:
        f.write(content)
    print('Fixed')
else:
    print('String not found - check manually')
