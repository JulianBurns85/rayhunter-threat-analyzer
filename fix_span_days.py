path = r'C:\RH\rayhunter-threat-analyzer\detectors\persistence_tracker.py'
with open(path, 'r') as f:
    content = f.read()

old = '"3. {span_days}+ day persistence rules out testing or accidental interference.\n"'
new = 'f"3. {span_days}+ day persistence rules out testing or accidental interference.\n"'
content = content.replace(old, new)

with open(path, 'w') as f:
    f.write(content)

with open(path, 'r') as f:
    check = f.read()

if 'f"3. {span_days}+' in check:
    print('Fixed')
else:
    print('FAILED - checking line 178:')
    lines = check.splitlines()
    print(lines[177])
