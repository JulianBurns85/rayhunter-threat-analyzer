from collections import defaultdict

class FlashCatchDetector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.name = "FlashCatchDetector"
        # Alert if we see >2 MAC failures on the same PCI within 1500ms
        self.time_window_ms = 1500
        self.failure_threshold = 2

    def analyze(self, events):
        findings = []
        tracker = defaultdict(list)
        
        for event in events:
            log_code = event.get("log_code", "")
            nas_type = event.get("nas_type", None)
            emm_cause = event.get("emm_cause", None)
            
            # Filter for 0xB0EC (LTE NAS EMM Plain OTA Incoming) or NAS Type 0x5C (Auth Failure)
            if log_code == "0xB0EC" or nas_type == 0x5C:
                
                # Check for EMM Cause #20 (0x14 in hex) -> MAC failure
                if emm_cause in [0x14, 20]:
                    pci = event.get("serving_pci", "Unknown_PCI")
                    timestamp = event.get("timestamp_ms", 0)
                    
                    if not timestamp:
                        continue
                        
                    tracker[pci].append(timestamp)
                    
                    # Purge timestamps outside the 1500ms rolling window
                    tracker[pci] = [t for t in tracker[pci] if (timestamp - t) <= self.time_window_ms]
                    
                    # Trigger threshold
                    if len(tracker[pci]) > self.failure_threshold:
                        findings.append(self._make_finding(pci, tracker[pci]))
                        # Clear tracker for this PCI to prevent duplicate alert spam in the same burst
                        tracker[pci] = []
                        
        return findings

    def _make_finding(self, pci, timestamps):
        # Conforms to Rayhunter's expected finding schema
        return {
            "title": "FlashCatch Authentication Anomaly Detected",
            "detector": self.name,
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "description": (
                f"Detected a rapid succession of NAS Authentication Failures (Cause #20: MAC failure) "
                f"on PCI {pci}. This strongly indicates an IMSI catcher using the FlashCatch "
                f"technique to grab the IMSI and seamlessly reject the UE without causing a denial of service."
            ),
            "evidence": [
                f"Registered {len(timestamps)} consecutive invalid MAC vectors on PCI {pci} within a {self.time_window_ms}ms window."
            ],
            "rogue_pci": pci,
            "source": "rf_corpus" 
        }