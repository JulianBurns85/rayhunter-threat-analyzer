import sys, yaml
sys.path.insert(0, '.')
cfg = yaml.safe_load(open('config.yaml'))
from parsers.pcap_parser import PcapParser
from pathlib import Path
p = PcapParser(cfg)
all_events = []
for f in list(Path(r'C:\Users\Jessum Chap\Desktop\June Ray Files\09.06.26').glob('*.pcapng'))[:4]:
    all_events.extend(p.parse(f))
releases = [e for e in all_events if 'release' in str(e.get('msg_type','')).lower()]
print(f'Total releases: {len(releases)}')
tacs = set(e.get('tac') for e in releases)
print(f'TACs on release events: {tacs}')
for r in releases[:5]:
    print('  tac=' + str(r.get('tac')) + ' ts=' + str(r.get('ts_epoch')) + ' cid=' + str(r.get('cid')))
