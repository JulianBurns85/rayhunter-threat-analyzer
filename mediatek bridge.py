import re
import json

def parse_mediatek_radio_log(file_path):
    events = []
    
    # Regex to capture Timestamp, Cell ID (mCi), Physical Cell ID (mPci), TAC, and Frequency (mEarfcn)
    cell_pattern = re.compile(
        r'^(?P<timestamp>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+radio.*?MTKSST.*?CellIdentityLte:\{\s*mCi=(?P<mCi>\d+)\s+mPci=(?P<mPci>\d+)\s+mTac=(?P<mTac>\d+)\s+mEarfcn=(?P<mEarfcn>\d+)'
    )
    
    # Regex to capture Reject Causes (like Auth Rejects)
    reject_pattern = re.compile(
        r'^(?P<timestamp>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+radio.*?MTKSST.*?rejectCause=(?P<rejectCause>[1-9]\d*)'
    )

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # 1. Look for Cell Connections / Handovers
            cell_match = cell_pattern.search(line)
            if cell_match:
                event = cell_match.groupdict()
                event['type'] = 'CELL_IDENTITY'
                events.append(event)
                continue
                
            # 2. Look for Network Rejects (Crucial for finding forced downgrades/rejects)
            reject_match = reject_pattern.search(line)
            if reject_match:
                event = reject_match.groupdict()
                event['type'] = 'NETWORK_REJECT'
                events.append(event)

    return json.dumps(events, indent=2)

# Run the parser
json_output = parse_mediatek_radio_log("radio_2026-06-11-22-56-45.txt")
print(json_output)