"""
provenance.py — label every finding by what it's built on, hide nothing.

For a personal triage tool: keep ALL findings, but tag each with a provenance
class so you always know whether a finding is backed by bytes in THIS capture
set or inferred from history/CASTNET/external assumption.

Provenance classes (most-grounded to least):
  MEASURED    - derived from events decoded in this run (cell IDs, RRC msgs, reject loop)
  FIRMWARE    - from the Shannon IMS bugreport (independent baseband log)
  HISTORICAL  - from CASTNET store / 394-session corpus (real data, but not THIS capture)
  INFERRED    - hardware attribution / behavioural narrative built on assumptions
  PENDING     - detector active but no data yet ("awaiting X")

Adds f["provenance"] to each finding. Pure labelling; never drops anything.
"""

import re

# detectors that read this run's decoded events directly
MEASURED_DETECTORS = {
    "novelciddetector", "cidrotationdetector", "handoverinjectdetector",
    "proximitytrackdetector", "cellsummary", "cellidsummary",
    "crntitargetprofiler", "nasentropyscorer", "ciphernegotiationsequenceanalyser",
    "roguetowerdetector", "earfcnanomalydetector", "paginganomalydetector",
}
# detectors that read the CASTNET store / multi-session corpus
HISTORICAL_DETECTORS = {
    "crosscarriertimercorrelator", "regulatoryescalationscorer",
    "behavioralrhythmfingerprinter", "operatorrhythmprofiler",
    "attackintensityscorer", "attackcampaignsegmenter",
    "crosssessionpersistencetracker", "jitterdnatracker",
    "silentperioddetector", "regulatoryeventcorrelator",
    "tuckertaxonomyscorer",
}
# detectors that synthesise/attribute rather than measure
INFERRED_DETECTORS = {
    "hardwareattributionenginev2", "dualdevicetemporalsegregator",
    "simultaneouciddiscriminator", "simultaneousciddiscriminator",
    "dualunittriangulator", "platformfusionengine",
}

PENDING_MARKERS = ("awaiting", "no sib", "no timer", "no nas timer",
                   "monitor active", "no rf capture")
FIRMWARE_DETECTORS = {"shannonimsparser", "shannonimslogparser", "shannonims"}
FIRMWARE_MARKERS = ("shannon ims", "bugreport-", "baseband log",
                    "rogue firmware event")
HISTORICAL_MARKERS = ("castnet", "394-session", "394 session", "corpus baseline",
                      "sessions analysed", "15 days monitored", "detection density")


def _blob(f):
    parts = [str(f.get(k, "")) for k in ("title", "description", "technique")]
    ev = f.get("evidence")
    if isinstance(ev, list):
        parts += [str(x) for x in ev]
    elif ev:
        parts.append(str(ev))
    return " ".join(parts).lower()


def classify(f):
    name = str(f.get("detector", "")).lower().replace("_", "").replace(" ", "")
    blob = _blob(f)

    # explicit override if a detector already tagged itself
    src = f.get("source")
    if src == "castnet":
        return "HISTORICAL"
    if src == "known_location":
        return "INFERRED"
    if (src == "bugreport" or name in FIRMWARE_DETECTORS
            or any(m in blob for m in FIRMWARE_MARKERS)):
        return "FIRMWARE"

    if any(m in blob for m in PENDING_MARKERS):
        return "PENDING"
    if name in HISTORICAL_DETECTORS or any(m in blob for m in HISTORICAL_MARKERS):
        return "HISTORICAL"
    if name in INFERRED_DETECTORS:
        return "INFERRED"
    if name in MEASURED_DETECTORS:
        return "MEASURED"
    # default: if it cites this-run artefacts (file names, .qmdl/.ndjson) call it measured
    if re.search(r"\.(qmdl|ndjson|pcapng)\b", blob):
        return "MEASURED"
    return "INFERRED"  # conservative: unlabelled synthesis is inferred, not measured


PROV_LABEL = {
    "MEASURED":   "[MEASURED]   byte-backed from this capture set",
    "DISPUTED":   "[DISPUTED]   cites this capture but msg NOT in decode (reconcile: UNVERIFIED)",
    "FIRMWARE":   "[FIRMWARE]   from Shannon IMS baseband log (independent)",
    "HISTORICAL": "[HISTORICAL] from CASTNET / multi-session corpus (NOT this capture)",
    "INFERRED":   "[INFERRED]   attribution/narrative built on assumptions",
    "PENDING":    "[PENDING]    detector active, no data yet",
}
PROV_ORDER = ["MEASURED", "FIRMWARE", "DISPUTED", "HISTORICAL", "INFERRED", "PENDING"]


def tag_all(findings):
    """Add provenance to every finding. Returns the same list (mutated)."""
    for f in findings:
        cls = classify(f)
        if f.get("verification_status") == "UNVERIFIED" and cls == "MEASURED":
            cls = "DISPUTED"
        f["provenance"] = cls
    return findings


def provenance_summary(findings):
    """Return printable lines: counts + grouped finding titles by class."""
    buckets = {k: [] for k in PROV_ORDER}
    for f in findings:
        buckets.setdefault(f.get("provenance", "INFERRED"), []).append(f)

    lines = []
    lines.append("=" * 64)
    lines.append("PROVENANCE MAP — what each finding is actually built on")
    lines.append("=" * 64)
    for cls in PROV_ORDER:
        fs = buckets.get(cls, [])
        if not fs:
            continue
        lines.append(f"\n{PROV_LABEL[cls]}  ({len(fs)})")
        for f in fs:
            sev = f.get("severity", "?")
            conf = f.get("confidence", "?")
            title = str(f.get("title", ""))[:70]
            lines.append(f"    {sev:<5} {conf:<9} {title}")

    # the honest headline
    measured = len(buckets.get("MEASURED", [])) + len(buckets.get("FIRMWARE", []))
    disputed = len(buckets.get("DISPUTED", []))
    historical = len(buckets.get("HISTORICAL", []))
    inferred = len(buckets.get("INFERRED", []))
    lines.append("\n" + "-" * 64)
    lines.append(f"  Byte-backed (MEASURED+FIRMWARE): {measured}")
    lines.append(f"  Disputed (cites capture, not in decode): {disputed}")
    lines.append(f"  Historical/CASTNET:              {historical}")
    lines.append(f"  Inferred/attribution:            {inferred}")
    lines.append("-" * 64)
    lines.append("  NOTE: severity scores below count ALL findings. For a grounded")
    lines.append("  read, weight MEASURED+FIRMWARE first; treat HISTORICAL/INFERRED")
    lines.append("  as leads to verify, not conclusions.")
    return lines
