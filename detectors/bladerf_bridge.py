"""
BladeRFBridge — bladeRF 2.0 micro xA4 capture parser
Converts bladeRF capture outputs into ObservedSignal objects for FleetSignatureDetector.

Supported input formats:
  - SigMF (.sigmf-meta + .sigmf-data)
  - Raw IQ binary (.bin, .sc16q11, .cs16)
  - bladeRF-cli spectrum CSV (--script scan output)
  - gr-scan / GQRX CSV exports
  - RTL-SDR power scan CSV (compatible format)
  - Manual observation dicts (for CASTNET node integration)

All processing is PASSIVE — reads existing capture files only.
No transmission. No device control.

Version: 1.0 | June 2026
"""

import json
import csv
import struct
import logging
import math
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Iterator
from collections import defaultdict

from .fleet_signature_detector import ObservedSignal

logger = logging.getLogger(__name__)


# ─── SIGNAL CLASSIFICATION CONSTANTS ─────────────────────────────────
# Based on known Australian frequency allocations (ACMA band plan)

AU_BAND_MAP = {
    # TETRA — Government Radio Network (380-400MHz)
    (380.0, 400.0): {"type": "tetra", "band": "GRN_VIC", "carrier": "motorola_grn"},
    # LTE Band 28 (700MHz) — dominant AU mobile band
    (703.0, 748.0): {"type": "lte", "band": "B28", "carrier": "telstra_or_optus_or_vodafone"},
    (758.0, 803.0): {"type": "lte", "band": "B28_DL", "carrier": "telstra_or_optus_or_vodafone"},
    # LTE Band 3 (1800MHz)
    (1710.0, 1785.0): {"type": "lte", "band": "B3", "carrier": "telstra_or_optus"},
    (1805.0, 1880.0): {"type": "lte", "band": "B3_DL", "carrier": "telstra_or_optus"},
    # LTE Band 1 (2100MHz)
    (1920.0, 1980.0): {"type": "lte", "band": "B1", "carrier": "vodafone"},
    (2110.0, 2170.0): {"type": "lte", "band": "B1_DL", "carrier": "vodafone"},
    # APCO P25 (800MHz) — AFP national
    (806.0, 869.0):  {"type": "p25", "band": "800MHz", "carrier": "afp"},
    # 915MHz ISM — smart meters, IoT
    (902.0, 928.0):  {"type": "ismsub_ghz", "band": "915mhz_ism_au", "carrier": None},
    # GSM 900 (anomalous post-2017 AU)
    (890.0, 915.0):  {"type": "gsm", "band": "B8", "carrier": "roaming_or_rogue"},
    # Bluetooth / BLE / WiFi 2.4GHz ISM
    (2400.0, 2483.5): {"type": "ble_or_wifi", "band": "2.4GHz_ISM", "carrier": None},
    # WiFi 5GHz / OcuSync3 / FLIR
    (5150.0, 5850.0): {"type": "wifi_or_ocusync3", "band": "5GHz", "carrier": None},
    # DJI OcuSync 3 specific channels
    (5725.0, 5875.0): {"type": "ocusync3", "band": "5.8GHz_ISM", "carrier": None},
    # LTE-M / NB-IoT (uses B28 — detected by power signature)
    # UHF CB (Australian)
    (476.4, 477.4):  {"type": "uhf_cb", "band": "UHF_CB_AU", "carrier": None},
    # ADS-B (drone transponders >5.7kg)
    (1089.0, 1091.0): {"type": "adsb", "band": "1090MHz", "carrier": None},
}

# Telstra vs Optus vs Vodafone carrier detection on B28
# Based on known EARFCN allocations (public ACMA register)
TELSTRA_B28_EARFCN = range(9210, 9260)   # DL 758-768MHz approx
OPTUS_B28_EARFCN   = range(9260, 9310)   # DL 768-778MHz approx
VODAFONE_B28_EARFCN = range(9310, 9360)  # DL 778-788MHz approx

# Power thresholds for LTE-M vs full LTE discrimination
# LTE-M trackers are typically -105 to -120 dBm RSRP
# Phones typically -70 to -100 dBm
LTE_M_RSRP_THRESHOLD_DBM = -105.0

# OcuSync3 hop rate (Hz) — used to distinguish from static WiFi
OCUSYNC3_MIN_HOP_RATE_HZ = 40


@dataclass
class SpectrumSample:
    """A single frequency/power measurement from the bladeRF."""
    freq_mhz: float
    power_dbm: float
    timestamp: datetime
    bandwidth_mhz: float = 1.0
    duration_ms: float = 0.0
    sample_rate_mhz: float = 0.0
    notes: str = ""


@dataclass
class DetectedEmission:
    """A processed emission event — above noise floor at a known frequency."""
    freq_mhz: float
    power_dbm: float
    bandwidth_mhz: float
    duration_ms: float
    timestamp: datetime
    burst_type: str = "continuous"   # continuous | burst | hop
    hop_rate_hz: float = 0.0
    interval_to_next_s: float = 0.0
    raw_type: str = ""               # from band map lookup
    carrier_hint: str = ""


class BladeRFBridge:
    """
    Converts bladeRF capture data into ObservedSignal objects.

    Usage:
        bridge = BladeRFBridge()

        # From SigMF
        signals = bridge.from_sigmf("capture.sigmf-meta")

        # From bladeRF-cli CSV scan
        signals = bridge.from_bladerf_csv("scan.csv")

        # From raw IQ
        signals = bridge.from_raw_iq("capture.bin", center_freq_mhz=700, sample_rate_mhz=20)

        # Feed to detector
        results = detector.analyze(signals, location=(lat, lon))
    """

    def __init__(self, noise_floor_dbm: float = -100.0,
                 min_burst_duration_ms: float = 20.0):
        self.noise_floor_dbm = noise_floor_dbm
        self.min_burst_duration_ms = min_burst_duration_ms

    # ─── FORMAT PARSERS ──────────────────────────────────────────────

    def from_sigmf(self, meta_path: str) -> list[ObservedSignal]:
        """
        Parse SigMF capture (.sigmf-meta + .sigmf-data).
        bladeRF-cli can export SigMF with: bladeRF-cli -e "rx config ... format=sigmf"
        """
        meta_path = Path(meta_path)
        data_path = meta_path.with_suffix(".sigmf-data")

        if not meta_path.exists():
            raise FileNotFoundError(f"SigMF meta not found: {meta_path}")

        with open(meta_path) as f:
            meta = json.load(f)

        global_meta = meta.get("global", {})
        center_freq_hz = global_meta.get("core:frequency", 0)
        sample_rate_hz = global_meta.get("core:sample_rate", 1)
        datatype = global_meta.get("core:datatype", "ci16_le")
        center_freq_mhz = center_freq_hz / 1e6
        sample_rate_mhz = sample_rate_hz / 1e6

        captures = meta.get("captures", [{}])
        ts_str = captures[0].get("core:datetime", datetime.now(timezone.utc).isoformat())
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            timestamp = datetime.now(timezone.utc)

        logger.info(
            f"SigMF: center={center_freq_mhz:.3f}MHz "
            f"rate={sample_rate_mhz:.1f}MHz datatype={datatype}"
        )

        if data_path.exists():
            samples = self._read_iq_file(data_path, datatype)
            spectrum = self._iq_to_spectrum(
                samples, center_freq_mhz, sample_rate_mhz, timestamp
            )
        else:
            logger.warning(f"SigMF data file not found: {data_path} — metadata only")
            spectrum = []

        annotations = meta.get("annotations", [])
        annotated = self._apply_sigmf_annotations(spectrum, annotations, sample_rate_hz)

        return self._spectrum_to_signals(annotated if annotated else spectrum)

    def from_bladerf_csv(self, csv_path: str) -> list[ObservedSignal]:
        """
        Parse bladeRF-cli spectrum scan CSV output.

        Generate with:
          bladeRF-cli -e "rx config frequency=700000000 bandwidth=20000000"
          bladeRF-cli --script scan_b28.brf > scan_b28.csv

        Or use gr-scan / GQRX spectrum export (same format supported).

        Expected columns: frequency_hz, power_dbm  (or: freq, power, timestamp)
        """
        csv_path = Path(csv_path)
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV not found: {csv_path}")

        samples = []
        timestamp = datetime.now(timezone.utc)

        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            # Try to detect format from first line
            first_line = f.readline().strip()
            f.seek(0)

            reader = csv.DictReader(f)
            fieldnames = [fn.lower().strip() for fn in (reader.fieldnames or [])]

            freq_col = next(
                (fn for fn in fieldnames if "freq" in fn or "hz" in fn), None
            )
            power_col = next(
                (fn for fn in fieldnames if "power" in fn or "dbm" in fn
                 or "level" in fn or "rssi" in fn), None
            )
            time_col = next(
                (fn for fn in fieldnames if "time" in fn or "stamp" in fn), None
            )

            if not freq_col or not power_col:
                # Try positional fallback (freq, power)
                f.seek(0)
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 2:
                        continue
                    try:
                        freq_hz = float(row[0])
                        power = float(row[1])
                        ts = datetime.now(timezone.utc)
                        if len(row) > 2:
                            try:
                                ts = datetime.fromisoformat(row[2])
                            except Exception:
                                pass
                        freq_mhz = freq_hz / 1e6 if freq_hz > 1e4 else freq_hz
                        samples.append(SpectrumSample(
                            freq_mhz=freq_mhz, power_dbm=power, timestamp=ts
                        ))
                    except ValueError:
                        continue
            else:
                for row in reader:
                    try:
                        freq_raw = float(row.get(freq_col, 0))
                        freq_mhz = freq_raw / 1e6 if freq_raw > 1e4 else freq_raw
                        power = float(row.get(power_col, -120))
                        ts = timestamp
                        if time_col and row.get(time_col):
                            try:
                                ts = datetime.fromisoformat(row[time_col])
                            except Exception:
                                pass
                        samples.append(SpectrumSample(
                            freq_mhz=freq_mhz, power_dbm=power, timestamp=ts
                        ))
                    except (ValueError, KeyError):
                        continue

        logger.info(f"CSV: {len(samples)} samples from {csv_path.name}")
        emissions = self._detect_emissions(samples)
        return self._emissions_to_signals(emissions)

    def from_raw_iq(self, bin_path: str,
                    center_freq_mhz: float,
                    sample_rate_mhz: float,
                    datatype: str = "ci16_le",
                    timestamp: datetime = None) -> list[ObservedSignal]:
        """
        Parse raw IQ binary file from bladeRF.

        Capture with:
          bladeRF-cli -e "rx config frequency=700000000 bandwidth=20000000 \
                          n=4000000 format=bin file=capture_b28.bin"

        datatype options: ci16_le (int16 IQ), cu8 (uint8 IQ), cf32_le (float32 IQ)
        """
        bin_path = Path(bin_path)
        if not bin_path.exists():
            raise FileNotFoundError(f"IQ file not found: {bin_path}")

        ts = timestamp or datetime.now(timezone.utc)
        samples = self._read_iq_file(bin_path, datatype)
        spectrum = self._iq_to_spectrum(samples, center_freq_mhz, sample_rate_mhz, ts)
        emissions = self._detect_emissions(spectrum)
        return self._emissions_to_signals(emissions)

    def from_gqrx_csv(self, csv_path: str) -> list[ObservedSignal]:
        """
        Parse GQRX spectrum export CSV.
        Format: # Frequency [Hz], S+N [dBFS], N [dBFS], S [dBFS]
        Export via GQRX: Tools > Remote Control (use gqrx-scan or manual export)
        """
        csv_path = Path(csv_path)
        samples = []

        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) < 2:
                    continue
                try:
                    freq_hz = float(parts[0])
                    power_dbm = float(parts[1])
                    samples.append(SpectrumSample(
                        freq_mhz=freq_hz / 1e6,
                        power_dbm=power_dbm,
                        timestamp=datetime.now(timezone.utc)
                    ))
                except ValueError:
                    continue

        logger.info(f"GQRX CSV: {len(samples)} samples from {csv_path.name}")
        emissions = self._detect_emissions(samples)
        return self._emissions_to_signals(emissions)

    def from_manual(self, observations: list[dict]) -> list[ObservedSignal]:
        """
        Convert manual observation dicts to ObservedSignals.
        For CASTNET node integration — Android app sends JSON observations.

        Expected dict format:
        {
            "type": "ble",
            "freq_mhz": 2440.0,
            "manufacturer_id": "0x004C",
            "advertisement_interval_ms": 500,
            "separation_indicator": true,
            "rsrp_dbm": -85,
            "carrier": "telstra",
            "band": "B28",
            "payload_type": "apple_nearby_action",
            "mac": "AA:BB:CC:DD:EE:FF",
            "lat": -38.1100,
            "lon": 145.2780,
            "ts": "2026-06-06T04:30:00Z"
        }
        """
        signals = []
        for obs in observations:
            try:
                ts_raw = obs.get("ts") or obs.get("timestamp")
                try:
                    ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)

                sig = ObservedSignal(
                    signal_type=obs.get("type", "unknown"),
                    freq_mhz=obs.get("freq_mhz"),
                    carrier=obs.get("carrier"),
                    band=obs.get("band"),
                    manufacturer_id=obs.get("manufacturer_id"),
                    service_uuid=obs.get("service_uuid"),
                    advertisement_interval_ms=obs.get("advertisement_interval_ms"),
                    rsrp_dbm=obs.get("rsrp_dbm"),
                    burst_duration_ms=obs.get("burst_duration_ms"),
                    burst_interval_s=obs.get("burst_interval_s"),
                    payload_type=obs.get("payload_type"),
                    ssid=obs.get("ssid"),
                    mac_address=obs.get("mac"),
                    separation_indicator=obs.get("separation_indicator"),
                    timestamp=ts,
                    latitude=obs.get("lat"),
                    longitude=obs.get("lon"),
                    raw_metadata=obs.get("metadata", {})
                )
                signals.append(sig)
            except Exception as e:
                logger.warning(f"Skipping malformed observation: {e}")

        logger.info(f"Manual: {len(signals)} observations parsed")
        return signals

    # ─── IQ PROCESSING ───────────────────────────────────────────────

    def _read_iq_file(self, path: Path, datatype: str) -> list[complex]:
        """Read IQ samples from binary file."""
        data = path.read_bytes()
        samples = []

        if datatype in ("ci16_le", "cs16"):
            # int16 I/Q pairs, little endian — bladeRF default
            n = len(data) // 4
            for i in range(n):
                I = struct.unpack_from("<h", data, i * 4)[0]
                Q = struct.unpack_from("<h", data, i * 4 + 2)[0]
                samples.append(complex(I / 2048.0, Q / 2048.0))

        elif datatype == "cu8":
            # uint8 offset binary (RTL-SDR style)
            n = len(data) // 2
            for i in range(n):
                I = (data[i * 2] - 127.5) / 127.5
                Q = (data[i * 2 + 1] - 127.5) / 127.5
                samples.append(complex(I, Q))

        elif datatype == "cf32_le":
            # float32 IQ pairs
            n = len(data) // 8
            for i in range(n):
                I = struct.unpack_from("<f", data, i * 8)[0]
                Q = struct.unpack_from("<f", data, i * 8 + 4)[0]
                samples.append(complex(I, Q))

        else:
            logger.warning(f"Unknown datatype {datatype} — trying ci16_le")
            return self._read_iq_file(path, "ci16_le")

        logger.info(f"Read {len(samples)} IQ samples ({datatype}) from {path.name}")
        return samples

    def _iq_to_spectrum(self, samples: list[complex],
                        center_freq_mhz: float,
                        sample_rate_mhz: float,
                        timestamp: datetime,
                        fft_size: int = 1024) -> list[SpectrumSample]:
        """
        Convert IQ samples to spectrum via FFT.
        Simple implementation — no windowing for brevity.
        For production, use numpy/scipy if available.
        """
        spectrum = []

        try:
            import numpy as np
            # Use numpy FFT if available — much faster
            chunk_size = min(fft_size, len(samples))
            iq_array = np.array(samples[:chunk_size])
            fft_result = np.fft.fftshift(np.fft.fft(iq_array, n=fft_size))
            power_db = 20 * np.log10(np.abs(fft_result) / fft_size + 1e-10)
            freq_bins = np.fft.fftshift(
                np.fft.fftfreq(fft_size, d=1.0 / sample_rate_mhz)
            )
            for i, (freq_offset, power) in enumerate(zip(freq_bins, power_db)):
                spectrum.append(SpectrumSample(
                    freq_mhz=center_freq_mhz + freq_offset,
                    power_dbm=float(power),
                    timestamp=timestamp,
                    bandwidth_mhz=sample_rate_mhz / fft_size
                ))
            logger.info(f"FFT: {len(spectrum)} bins (numpy)")

        except ImportError:
            # Pure Python fallback — slower but dependency-free
            logger.warning("numpy not available — using pure Python FFT (slower)")
            n = min(fft_size, len(samples))
            freqs = [center_freq_mhz + (i - n // 2) * sample_rate_mhz / n
                     for i in range(n)]
            for i, freq in enumerate(freqs):
                # Simple power estimate — DFT for this bin only
                total = sum(
                    samples[k] * complex(
                        math.cos(-2 * math.pi * i * k / n),
                        math.sin(-2 * math.pi * i * k / n)
                    ) for k in range(n)
                )
                power = 20 * math.log10(abs(total) / n + 1e-10)
                spectrum.append(SpectrumSample(
                    freq_mhz=freq, power_dbm=power, timestamp=timestamp,
                    bandwidth_mhz=sample_rate_mhz / n
                ))

        return spectrum

    def _apply_sigmf_annotations(self, spectrum: list[SpectrumSample],
                                  annotations: list[dict],
                                  sample_rate_hz: float) -> list[SpectrumSample]:
        """Apply SigMF annotations to spectrum samples."""
        if not annotations or not spectrum:
            return spectrum

        annotated = list(spectrum)
        for ann in annotations:
            label = ann.get("core:label", "")
            comment = ann.get("core:comment", "")
            sample_start = ann.get("core:sample_start", 0)
            sample_count = ann.get("core:sample_count", 0)

            time_offset_s = sample_start / sample_rate_hz if sample_rate_hz else 0
            duration_ms = (sample_count / sample_rate_hz * 1000) if sample_rate_hz else 0

            for sample in annotated:
                if label and (label in sample.notes or not sample.notes):
                    sample.notes = f"{label} {comment}".strip()
                    sample.duration_ms = duration_ms

        return annotated

    # ─── EMISSION DETECTION ──────────────────────────────────────────

    def _detect_emissions(self, spectrum: list[SpectrumSample]) -> list[DetectedEmission]:
        """
        Identify emission events from spectrum samples.
        Groups adjacent above-threshold samples into discrete emissions.
        """
        if not spectrum:
            return []

        sorted_samples = sorted(spectrum, key=lambda s: s.freq_mhz)
        noise = self.noise_floor_dbm

        emissions = []
        current_group = []

        for sample in sorted_samples:
            if sample.power_dbm > noise + 6:  # 6dB above noise = emission
                current_group.append(sample)
            else:
                if current_group:
                    emission = self._group_to_emission(current_group)
                    if emission and emission.duration_ms >= self.min_burst_duration_ms:
                        emissions.append(emission)
                    current_group = []

        if current_group:
            emission = self._group_to_emission(current_group)
            if emission:
                emissions.append(emission)

        # Detect bursts by looking at temporal gaps in same-frequency emissions
        self._detect_burst_patterns(emissions, spectrum)

        logger.info(f"Detected {len(emissions)} emissions above noise floor")
        return emissions

    def _group_to_emission(self, group: list[SpectrumSample]) -> Optional[DetectedEmission]:
        """Convert a group of adjacent spectrum samples to a single DetectedEmission."""
        if not group:
            return None

        center_freq = sum(s.freq_mhz for s in group) / len(group)
        peak_power = max(s.power_dbm for s in group)
        bandwidth = group[-1].freq_mhz - group[0].freq_mhz + group[0].bandwidth_mhz
        timestamp = min(s.timestamp for s in group)
        duration = sum(s.duration_ms for s in group) or 100.0

        # Band map lookup
        raw_type = ""
        carrier_hint = ""
        for (low, high), info in AU_BAND_MAP.items():
            if low <= center_freq <= high:
                raw_type = info["type"]
                carrier_hint = info.get("carrier", "") or ""
                break

        return DetectedEmission(
            freq_mhz=center_freq,
            power_dbm=peak_power,
            bandwidth_mhz=bandwidth,
            duration_ms=duration,
            timestamp=timestamp,
            raw_type=raw_type,
            carrier_hint=carrier_hint
        )

    def _detect_burst_patterns(self, emissions: list[DetectedEmission],
                                spectrum: list[SpectrumSample]):
        """
        Analyse temporal patterns to classify burst types and intervals.
        Metronomic bursts = GPS tracker. Frequency hopping = OcuSync/WiFi.
        """
        # Group by frequency band (within 1MHz)
        freq_groups = defaultdict(list)
        for s in spectrum:
            if s.power_dbm > self.noise_floor_dbm + 6:
                bucket = round(s.freq_mhz)
                freq_groups[bucket].append(s)

        for emission in emissions:
            freq_bucket = round(emission.freq_mhz)
            nearby = freq_groups.get(freq_bucket, [])
            if len(nearby) < 2:
                continue

            timestamps = sorted(s.timestamp for s in nearby)
            if len(timestamps) < 2:
                continue

            intervals = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)

            if std_dev < avg_interval * 0.05 and avg_interval < 300:
                # Metronomic — GPS tracker / fleet tracking
                emission.burst_type = "metronomic"
                emission.interval_to_next_s = avg_interval
            elif len(set(round(s.freq_mhz) for s in nearby)) > 3:
                # Multiple frequencies = hopping
                emission.burst_type = "hop"
                emission.hop_rate_hz = 1.0 / avg_interval if avg_interval > 0 else 0
            else:
                emission.burst_type = "burst"

    # ─── EMISSION → SIGNAL CONVERSION ────────────────────────────────

    def _emissions_to_signals(self, emissions: list[DetectedEmission]) -> list[ObservedSignal]:
        """Convert detected emissions to ObservedSignal objects."""
        signals = []
        for e in emissions:
            sig = self._classify_emission(e)
            if sig:
                signals.append(sig)
        logger.info(f"Converted {len(signals)} emissions to ObservedSignals")
        return signals

    def _spectrum_to_signals(self, spectrum: list[SpectrumSample]) -> list[ObservedSignal]:
        emissions = self._detect_emissions(spectrum)
        return self._emissions_to_signals(emissions)

    def _classify_emission(self, e: DetectedEmission) -> Optional[ObservedSignal]:
        """
        Apply domain knowledge to classify an emission into a specific signal type.
        """
        sig_type = e.raw_type

        # Resolve ambiguous types using power and burst characteristics
        if sig_type == "ble_or_wifi":
            # BLE is narrowband (~1MHz), WiFi is wideband (~20MHz)
            sig_type = "ble" if e.bandwidth_mhz < 5 else "wifi"

        elif sig_type == "wifi_or_ocusync3":
            # OcuSync3 hops; WiFi stays on fixed channels
            if e.burst_type == "hop" and e.hop_rate_hz >= OCUSYNC3_MIN_HOP_RATE_HZ:
                sig_type = "ocusync3"
            else:
                sig_type = "wifi"

        elif sig_type == "lte" and e.power_dbm <= LTE_M_RSRP_THRESHOLD_DBM:
            # Very low power LTE on B28 = likely LTE-M tracker not phone
            if e.burst_type == "metronomic":
                sig_type = "lte_m"

        # Carrier refinement on B28
        carrier = e.carrier_hint or ""
        if sig_type == "lte" and "700" in str(e.freq_mhz) or (703 <= e.freq_mhz <= 803):
            carrier = self._identify_b28_carrier(e.freq_mhz)

        return ObservedSignal(
            signal_type=sig_type,
            freq_mhz=e.freq_mhz,
            carrier=carrier if carrier else None,
            band=self._freq_to_band(e.freq_mhz),
            rsrp_dbm=e.power_dbm,
            burst_duration_ms=e.duration_ms,
            burst_interval_s=e.interval_to_next_s if e.interval_to_next_s > 0 else None,
            timestamp=e.timestamp
        )

    def _identify_b28_carrier(self, freq_mhz: float) -> str:
        """
        Estimate carrier from B28 downlink frequency.
        Based on known Australian EARFCN allocations.
        """
        if 758.0 <= freq_mhz <= 768.0:
            return "telstra"
        elif 768.0 <= freq_mhz <= 778.0:
            return "optus"
        elif 778.0 <= freq_mhz <= 803.0:
            return "vodafone"
        return "telstra_or_optus_or_vodafone"

    def _freq_to_band(self, freq_mhz: float) -> Optional[str]:
        """Map frequency to band designation."""
        for (low, high), info in AU_BAND_MAP.items():
            if low <= freq_mhz <= high:
                return info.get("band")
        return None
