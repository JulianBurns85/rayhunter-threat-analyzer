import json, os

report_files = [f for f in os.listdir('.') if f.startswith('rayhunter_report_') and f.endswith('.json')]
if not report_files:
    print("No report found")
else:
    report_files.sort()
    data = json.load(open(report_files[-1]))
    events = data.get('events', [])
    print(f"Total events in JSON: {len(events)}")
    types = set()
    for e in events[:500]:
        mt = e.get('message_type') or e.get('type') or e.get('msg_type')
        if mt:
            types.add(str(mt).lower()[:50])
    for t in sorted(types)[:30]:
        print(repr(t))
