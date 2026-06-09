path = r'C:\RH\rayhunter-threat-analyzer\detectors\fusion_engine.py'
with open(path, 'r') as f:
    content = f.read()

old1 = 'def _get(f, attr, default=""):\n    return str(getattr(f, attr, default) or default)'
new1 = 'def _get(f, attr, default=""):\n    if isinstance(f, dict):\n        return str(f.get(attr, default) or default)\n    return str(getattr(f, attr, default) or default)'
content = content.replace(old1, new1)

old2 = 'event_count = int(getattr(f, "event_count", 0) or 0)'
new2 = 'event_count = int(f.get("event_count", 0) if isinstance(f, dict) else getattr(f, "event_count", 0) or 0)'
content = content.replace(old2, new2)

with open(path, 'w') as f:
    f.write(content)
print('Fixed')
