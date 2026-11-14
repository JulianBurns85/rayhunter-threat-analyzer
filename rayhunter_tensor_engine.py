import asyncio
import json
import time
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

NUM_STATES = len(RRC_NAS_STATES)
SEQ_WINDOW = 8

BENIGN_FLOWS = [
    [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0],
    [0, 3, 4, 5, 9, 10, 12, 13, 0],
    [0, 1, 2, 0, 3, 0]
]

ATTACK_SCENARIOS = {
    "stingray_imsi": {
        "name": "STINGRAY PRE-AUTH IMSI HARVEST",
        "seq": [0, 1, 4, 5, 6, 14, 14, 13]
    },
    "downgrade_2g": {
        "name": "FORCED TAU-REJECT 2G DOWNGRADE",
        "seq": [0, 3, 4, 5, 6, 15, 13, 15]
    },
    "paging_storm": {
        "name": "SILENT SMS / PAGING EXHAUSTION",
        "seq": [0, 3, 3, 3, 3, 4, 13, 3]
    }
}

def build_carrier_baseline_tensor():
    tensor = np.full((SEQ_WINDOW, NUM_STATES, NUM_STATES), 0.002, dtype=np.float32)
    for flow in BENIGN_FLOWS:
        for step in range(len(flow) - 1):
            s_idx = step % SEQ_WINDOW
            u, v = flow[step], flow[step + 1]
            tensor[s_idx, u, v] += 8.0
            tensor[:, u, v] += 2.5
    return tensor

class RayhunterTensorEngine:
    def __init__(self):
        self.base_tensor = build_carrier_baseline_tensor()
        self.active_tensor = self.base_tensor.copy()
        self.anomaly_heatmap = np.zeros((NUM_STATES, NUM_STATES), dtype=np.float32)
        self.clients = set()
        self.attack_queue = []
        self.selected_slice = -1
        self.event_log = []

    async def ws_handler(self, websocket):
        self.clients.add(websocket)
        try:
            async for message in websocket:
                data = json.loads(message)
                if data.get("type") == "INJECT_ATTACK":
                    key = data.get("scenario", "stingray_imsi")
                    if key in ATTACK_SCENARIOS:
                        self.attack_queue.append(ATTACK_SCENARIOS[key])
                        print(f"\n[!] HUD COMMAND: Injected Cellular Attack -> {ATTACK_SCENARIOS[key]['name']}")
                elif data.get("type") == "SELECT_SLICE":
                    self.selected_slice = int(data.get("slice", -1))
        except Exception:
            pass
        finally:
            self.clients.discard(websocket)

    def compute_entropy(self):
        w2d = self.active_tensor.max(axis=0)
        probs = w2d / np.maximum(w2d.sum(axis=1, keepdims=True), 1e-9)
        safe_p = np.where(probs > 1e-9, probs, 1.0)
        row_h = -np.sum(probs * np.log2(safe_p), axis=1)
        return row_h, float(np.mean(row_h))

    async def run_telemetry_loop(self):
        print("[*] Initializing Rayhunter 3GPP RRC/NAS State-Tensor Engine...")
        print("[+] Listening on ws://localhost:8765 -> Open rayhunter_hud.html!")

        step_counter = 0
        async with websockets.serve(self.ws_handler, "localhost", 8765):
            while True:
                if self.attack_queue:
                    scenario = self.attack_queue.pop(0)
                    seq = scenario["seq"]
                    mode_label = scenario["name"]
                    is_attack = True
                else:
                    seq = BENIGN_FLOWS[step_counter % len(BENIGN_FLOWS)]
                    mode_label = "BENIGN 4G LTE CARRIER ATTACH"
                    is_attack = False

                step_counter += 1

                for i in range(len(seq) - 1):
                    if not is_attack and self.attack_queue:
                        break

                    s_idx = i % SEQ_WINDOW
                    u, v = seq[i], seq[i + 1]

                    row_probs = self.base_tensor[s_idx, u] / np.sum(self.base_tensor[s_idx, u])
                    prob_uv = float(row_probs[v])
                    surprise_bits = round(-np.log2(max(prob_uv, 1e-6)), 2)

                    self.active_tensor[s_idx, u, v] = min(40.0, self.active_tensor[s_idx, u, v] + 6.0)
                    if surprise_bits > 5.5:
                        self.anomaly_heatmap[u, v] = min(35.0, self.anomaly_heatmap[u, v] + surprise_bits * 2.2)
                        severity = "CRITICAL_IMSI_CATCHER" if surprise_bits > 8.5 else "RRC_ANOMALY_WARN"
                    else:
                        severity = "NOMINAL_3GPP_HOMEOSIS"

                    self.event_log.insert(0, {
                        "transition": f"{RRC_NAS_STATES[u][:14]} → {RRC_NAS_STATES[v][:14]}",
                        "surprise": f"{surprise_bits:.2f} bits",
                        "severity": severity,
                        "step": f"S{s_idx}"
                    })
                    self.event_log = self.event_log[:12]

                    self.active_tensor = (self.active_tensor * 0.92) + (self.base_tensor * 0.08)
                    self.anomaly_heatmap *= 0.96

                    _, mean_h = self.compute_entropy()

                    if 0 <= self.selected_slice < SEQ_WINDOW:
                        proj = self.active_tensor[self.selected_slice]
                    else:
                        proj = self.active_tensor.max(axis=0)

                    payload = json.dumps({
                        "weights": np.round(proj / max(float(np.max(proj)), 1e-6), 3).tolist(),
                        "anomalies": np.round(self.anomaly_heatmap / 35.0, 3).tolist(),
                        "labels": RRC_NAS_STATES,
                        "report": {
                            "mode": mode_label,
                            "status": severity,
                            "mean_entropy": round(mean_h, 3),
                            "max_surprise": surprise_bits,
                            "events": self.event_log
                        }
                    })

                    for client in list(self.clients):
                        try:
                            await client.send(payload)
                        except Exception:
                            self.clients.discard(client)

                    await asyncio.sleep(0.18 if is_attack else 0.12)

if __name__ == "__main__":
    engine = RayhunterTensorEngine()
    asyncio.run(engine.run_telemetry_loop())