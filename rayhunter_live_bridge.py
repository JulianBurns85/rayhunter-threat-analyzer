import asyncio
import glob
import json
import os
import aiohttp
import numpy as np
import websockets

RRC_NAS_STATES = [
    "00: IDLE_CAMPED",
    "01: MIB_SIB1_SYNC",
    "02: SIB2_3_CELL_CFG",
    "03: PAGING_TMSI",
    "04: RRC_CONN_REQ",
    "05: RRC_CONN_SETUP",
    "06: NAS_ATTACH_REQ",
    "07: NAS_AUTH_REQ",
    "08: NAS_AUTH_RESP",
    "09: SEC_MODE_CMD",
    "10: SEC_MODE_COMP",
    "11: NAS_ATTACH_ACC",
    "12: RRC_RECONFIG",
    "13: RRC_RELEASE",
    "14: NAS_ID_REQ_IMSI",
    "15: NAS_TAU_REJECT"
]

EVENT_TO_STATE_ID = {
    "RRC_IDLE": 0,
    "MIB": 1, "SIB1": 1,
    "SIB2": 2, "SIB3": 2,
    "PAGING": 3,
    "RRC_CONNECTION_REQUEST": 4,
    "RRC_CONNECTION_SETUP": 5,
    "ATTACH_REQUEST": 6,
    "AUTHENTICATION_REQUEST": 7,
    "AUTHENTICATION_RESPONSE": 8,
    "SECURITY_MODE_COMMAND": 9,
    "SECURITY_MODE_COMPLETE": 10,
    "ATTACH_ACCEPT": 11,
    "RRC_CONNECTION_RECONFIGURATION": 12,
    "RRC_CONNECTION_RELEASE": 13,
    "IDENTITY_REQUEST_IMSI": 14,
    "TRACKING_AREA_UPDATE_REJECT": 15,
}

# Byte/ASCII signature hints for scanning raw .qmdl / .pcap binaries
BINARY_KEYWORDS = {
    b"MIB": 1, b"SIB1": 1, b"SIB2": 2,
    b"Paging": 3, b"RRCConnectionRequest": 4, b"RRCConnectionSetup": 5,
    b"Attach request": 6, b"Authentication request": 7,
    b"Security mode command": 9, b"Attach accept": 11,
    b"RRCConnectionRelease": 13, b"Identity request": 14,
    b"Tracking area update reject": 15
}

NUM_STATES = len(RRC_NAS_STATES)
SEQ_WINDOW = 8
RAYHUNTER_HOST = "http://192.168.1.1:8080"

BENIGN_FLOWS = [
    [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0],
    [0, 3, 4, 5, 9, 10, 12, 13, 0],
]

def build_carrier_baseline_tensor():
    tensor = np.full((SEQ_WINDOW, NUM_STATES, NUM_STATES), 0.002, dtype=np.float32)
    for flow in BENIGN_FLOWS:
        for step in range(len(flow) - 1):
            s_idx = step % SEQ_WINDOW
            u, v = flow[step], flow[step + 1]
            tensor[s_idx, u, v] += 8.0
            tensor[:, u, v] += 2.5
    return tensor

class RayhunterLiveBridge:
    def __init__(self, device_url=RAYHUNTER_HOST):
        self.device_url = device_url.rstrip("/")
        self.base_tensor = build_carrier_baseline_tensor()
        self.active_tensor = self.base_tensor.copy()
        self.anomaly_heatmap = np.zeros((NUM_STATES, NUM_STATES), dtype=np.float32)
        self.clients = set()
        self.prev_state = 0
        self.step_idx = 0
        self.event_log = []
        self.seen_event_ids = set()

    async def ws_handler(self, websocket):
        self.clients.add(websocket)
        try:
            async for _ in websocket:
                pass
        except Exception:
            pass
        finally:
            self.clients.discard(websocket)

    def compute_entropy(self):
        w2d = self.active_tensor.max(axis=0)
        probs = w2d / np.maximum(w2d.sum(axis=1, keepdims=True), 1e-9)
        safe_p = np.where(probs > 1e-9, probs, 1.0)
        row_h = -np.sum(probs * np.log2(safe_p), axis=1)
        return float(np.mean(row_h))

    def process_transition(self, next_state: int, raw_label: str):
        u = self.prev_state
        v = next_state
        s_idx = self.step_idx % SEQ_WINDOW

        row_probs = self.base_tensor[s_idx, u] / np.sum(self.base_tensor[s_idx, u])
        prob_uv = float(row_probs[v])
        surprise_bits = round(-np.log2(max(prob_uv, 1e-6)), 2)

        self.active_tensor[s_idx, u, v] = min(40.0, self.active_tensor[s_idx, u, v] + 6.0)
        if surprise_bits > 5.5:
            self.anomaly_heatmap[u, v] = min(35.0, self.anomaly_heatmap[u, v] + surprise_bits * 2.2)
            severity = "CRITICAL_IMSI_CATCHER" if surprise_bits > 8.5 else "RRC_ANOMALY_WARN"
            print(f"🚨 [{severity}] {raw_label}: {RRC_NAS_STATES[u]} -> {RRC_NAS_STATES[v]} ({surprise_bits} bits)")
        else:
            severity = "NOMINAL_3GPP_HOMEOSIS"

        self.event_log.insert(0, {
            "transition": f"{RRC_NAS_STATES[u][:14]} → {RRC_NAS_STATES[v][:14]}",
            "surprise": f"{surprise_bits:.2f} bits",
            "severity": severity,
            "step": f"S{s_idx}"
        })
        self.event_log = self.event_log[:12]

        self.prev_state = v
        self.step_idx += 1
        return surprise_bits, severity

    async def broadcast_frame(self, mode_label: str, severity: str, surprise_bits: float):
        self.active_tensor = (self.active_tensor * 0.94) + (self.base_tensor * 0.06)
        self.anomaly_heatmap *= 0.96

        proj = self.active_tensor.max(axis=0)
        payload = json.dumps({
            "weights": np.round(proj / max(float(np.max(proj)), 1e-6), 3).tolist(),
            "anomalies": np.round(self.anomaly_heatmap / 35.0, 3).tolist(),
            "labels": RRC_NAS_STATES,
            "report": {
                "mode": mode_label,
                "status": severity,
                "mean_entropy": round(self.compute_entropy(), 3),
                "max_surprise": surprise_bits,
                "events": self.event_log
            }
        })

        for client in list(self.clients):
            try:
                await client.send(payload)
            except Exception:
                self.clients.discard(client)

    async def poll_rayhunter_api(self, session):
        for endpoint in (f"{self.device_url}/api/analysis", f"{self.device_url}/api/qmdl-manifest"):
            try:
                async with session.get(endpoint, timeout=1.5) as resp:
                    if resp.status == 200:
                        return await resp.json()
            except Exception:
                continue
        return None

    def extract_offline_capture_sequence(self):
        """Finds any local .pcap/.qmdl/.json file and extracts state transitions."""
        captures = glob.glob("*.pcap") + glob.glob("*.qmdl") + glob.glob("*.json")
        for filepath in captures:
            if filepath.lower() == "package.json":
                continue
            seq = []
            try:
                with open(filepath, "rb") as f:
                    blob = f.read(1024 * 512)
                # Scan chunks for 3GPP signaling markers
                chunk_size = 256
                for i in range(0, len(blob), chunk_size):
                    chunk = blob[i:i + chunk_size]
                    for marker, st_id in BINARY_KEYWORDS.items():
                        if marker in chunk:
                            seq.append((st_id, f"{os.path.basename(filepath)}:{marker.decode()}"))
                if len(seq) >= 3:
                    return os.path.basename(filepath), seq
            except Exception:
                continue
        return None, []

    async def run(self):
        print(f"[*] Rayhunter Bridge Armed (Target: {self.device_url} | Fallback: Local .pcap/.qmdl)")
        print("[+] WebSocket HUD active on ws://localhost:8765 -> Open rayhunter_hud.html")

        offline_idx = 0
        async with websockets.serve(self.ws_handler, "localhost", 8765):
            async with aiohttp.ClientSession() as session:
                while True:
                    api_data = await self.poll_rayhunter_api(session)
                    surprise_bits = 0.0
                    severity = "NOMINAL_3GPP_HOMEOSIS"

                    if api_data and isinstance(api_data, dict):
                        mode_label = f"LIVE HOTSPOT: {self.device_url}"
                        events = api_data.get("events", []) or api_data.get("entries", [])
                        for ev in events:
                            ev_id = str(ev.get("id") or ev.get("timestamp") or hash(str(ev)))
                            if ev_id in self.seen_event_ids:
                                continue
                            self.seen_event_ids.add(ev_id)
                            msg_type = str(ev.get("message_type") or ev.get("type") or "").upper()
                            for key, state_id in EVENT_TO_STATE_ID.items():
                                if key in msg_type:
                                    surprise_bits, severity = self.process_transition(state_id, msg_type)
                                    break
                        await self.broadcast_frame(mode_label, severity, surprise_bits)
                        await asyncio.sleep(0.25)
                    else:
                        cap_name, seq = self.extract_offline_capture_sequence()
                        if seq:
                            st_id, label = seq[offline_idx % len(seq)]
                            offline_idx += 1
                            surprise_bits, severity = self.process_transition(st_id, label)
                            await self.broadcast_frame(f"OFFLINE REPLAY: {cap_name}", severity, surprise_bits)
                            await asyncio.sleep(0.22)
                        else:
                            # Idle baseline heartbeat while waiting for hotspot or capture drop
                            flow = BENIGN_FLOWS[0]
                            st_id = flow[offline_idx % len(flow)]
                            offline_idx += 1
                            surprise_bits, severity = self.process_transition(st_id, "BASELINE_IDLE")
                            await self.broadcast_frame("STANDBY (DROP .PCAP/.QMDL OR CONNECT HOTSPOT)", severity, surprise_bits)
                            await asyncio.sleep(0.35)

if __name__ == "__main__":
    bridge = RayhunterLiveBridge()
    asyncio.run(bridge.run())
