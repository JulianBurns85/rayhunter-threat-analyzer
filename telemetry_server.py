import asyncio
import json
import numpy as np

class TelemetryBroadcaster:
    def __init__(self, host="localhost", port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        self.custom_wave_queue = []
        self.selected_slice = -1  # -1 = Max Projection, 0..6 = specific positional slice

    async def register(self, websocket):
        self.clients.add(websocket)
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data.get("type") == "CUSTOM_AUDIT":
                        raw_targets = data.get("targets", [])
                        valid = [t.strip() for t in raw_targets if 4 <= len(t.strip()) <= 8]
                        if valid:
                            self.custom_wave_queue.append(valid)
                            print(f"\n[!] HUD COMMAND: Queued Custom Policy Audit Wave -> {valid}")
                    elif data.get("type") == "SELECT_SLICE":
                        self.selected_slice = int(data.get("slice", -1))
                        mode_str = "MAX PROJECTION" if self.selected_slice == -1 else f"SLICE [{self.selected_slice}]"
                        print(f"\n[*] HUD VIEW: Switched 3D Lattice to {mode_str}")
                except Exception as e:
                    print(f"[!] Telemetry parse error: {e}")
        except Exception:
            pass
        finally:
            self.clients.discard(websocket)

    async def broadcast_state(self, weights_2d, row_entropies, report):
        if not self.clients:
            return

        w_max = float(np.max(weights_2d))
        norm_w = (weights_2d / max(w_max, 1e-6)).astype(np.float32)

        payload = json.dumps({
            "weights": np.round(norm_w, 3).tolist(),
            "entropies": np.round(row_entropies, 2).tolist(),
            "report": report
        })

        dead_clients = set()
        for client in list(self.clients):
            try:
                await client.send(payload)
            except Exception:
                dead_clients.add(client)
        self.clients -= dead_clients