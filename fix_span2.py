path = r'C:\RH\rayhunter-threat-analyzer\detectors\persistence_tracker.py'
with open(path, 'r') as f:
    content = f.read()

old = '                "3. {span_days}+ day persistence rules out testing or accidental interference.\\n"'
new = '                f"3. {span_days}+ day persistence rules out testing or accidental interference.\\n"'

if old in content:
    content = content.replace(old, new)
    with open(path, 'w') as f:
        f.write(content)
    print('Fixed')
else:
    # Try without escaped newline
    old2 = '"3. {span_days}+ day persistence rules out testing or accidental interference.\n"'
    if old2 in content:
        new2 = 'f"3. {span_days}+ day persistence rules out testing or accidental interference.\n"'
        content = content.replace(old2, new2)
        with open(path, 'w') as f:
            f.write(content)
        print('Fixed (variant 2)')
    else:
        print('String not found - printing surrounding context:')
        idx = content.find('{span_days}+ day persistence')
        if idx >= 0:
            print(repr(content[idx-50:idx+80]))
        else:
            print('span_days persistence string not found at all')
