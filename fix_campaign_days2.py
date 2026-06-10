path = r'C:\RH\rayhunter-threat-analyzer\detectors\attack_campaign_segmenter.py'
with open(path, 'r') as f:
    content = f.read()

fixes = 0
MIN_TS = 1735689600  # 2025-01-01 UTC
MAX_TS = 1798761600  # 2027-01-01 UTC
CLAMP = f"max(min(ts_events[-1][0],{MAX_TS}),{MIN_TS}) - max(min(ts_events[0][0],{MAX_TS}),{MIN_TS})"

# Fix 1: duration_days calculation
old1 = '            start_ts = ts_events[start_idx][0]\n            end_ts   = ts_events[end_idx-1][0]\n            duration_days = (end_ts - start_ts) / 86400'
new1 = f'''            start_ts = ts_events[start_idx][0]
            end_ts   = ts_events[end_idx-1][0]
            MIN_TS = {MIN_TS}  # 2025-01-01 UTC
            MAX_TS = {MAX_TS}  # 2027-01-01 UTC
            start_ts_clamped = max(min(start_ts, MAX_TS), MIN_TS)
            end_ts_clamped   = max(min(end_ts, MAX_TS), MIN_TS)
            duration_days = (end_ts_clamped - start_ts_clamped) / 86400'''
if old1 in content:
    content = content.replace(old1, new1)
    fixes += 1

# Fix 2: evidence total surveillance period
old2 = '            f"Total surveillance period: "\n            f"{(ts_events[-1][0] - ts_events[0][0])/86400:.0f} days",'
new2 = f'            f"Total surveillance period: "\n            f"{{({CLAMP})/86400:.0f}} days",'
if old2 in content:
    content = content.replace(old2, new2)
    fixes += 1

# Fix 3: finding title
old3 = '                f"{(ts_events[-1][0] - ts_events[0][0])/86400:.0f} Day Timeline"'
new3 = f'                f"{{({CLAMP})/86400:.0f}} Day Timeline"'
if old3 in content:
    content = content.replace(old3, new3)
    fixes += 1

with open(path, 'w') as f:
    f.write(content)
print(f'Fixed {fixes}/3 issues')
