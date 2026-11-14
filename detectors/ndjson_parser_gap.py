#!/usr/bin/env python3
"""Report Rayhunter NDJSON messages the phone parser skipped.

Counts come from one summary event per NDJSON file (msg_type
"NDJSON Parser Gap"). Encrypted NAS skips are expected after a
Security Mode Command. They are not IMSI Identity Requests.
"""

from typing import Dict, List

from detectors.base import BaseDetector, make_finding


class NdjsonParserGapDetector(BaseDetector):
    name = "NdjsonParserGapDetector"
    description = "Rayhunter NDJSON parser-gap summary (encrypted NAS, incomplete NAS, MAC framed)"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        summaries = [
            e for e in events
            if e.get("msg_type") == "NDJSON Parser Gap" and e.get("source_type") == "ndjson"
        ]
        if not summaries:
            return []

        totals: Dict[str, int] = {}
        records = 0
        for ev in summaries:
            records += int(ev.get("ndjson_records") or 0)
            for bucket, count in (ev.get("parser_gap_counts") or {}).items():
                totals[bucket] = totals.get(bucket, 0) + int(count)

        encrypted = totals.get("Encrypted NAS message", 0)
        incomplete = totals.get("Incomplete NAS message", 0)
        timing = totals.get("ServingCellTiming zero-record assertion", 0)
        mac = totals.get("Unsupported LTE MAC framed", 0)
        other = totals.get("Other parser gap", 0)
        skipped = sum(totals.values())

        evidence = [
            f"NDJSON files: {len(summaries)}",
            f"Packet records: {records}",
            f"Encrypted NAS message (skipped by Rayhunter): {encrypted}",
            f"Incomplete NAS message: {incomplete}",
            f"ServingCellTiming zero-record assertion: {timing}",
            f"Unsupported LTE MAC framed: {mac}",
            f"Other parser gap: {other}",
            "",
            "Encrypted NAS is a protected PDU. Rayhunter records the skip and",
            "does not expose an IMSI. Identity type is read from a plaintext",
            "Identity Request (nas-eps.emm.id_type2): 1=IMSI, 2=IMEI, 3=IMEISV, 4=TMSI.",
        ]
        return [make_finding(
            detector=self.name,
            title=(
                f"NDJSON parser gaps — {encrypted} encrypted NAS skipped, "
                f"{skipped} skip(s) in {len(summaries)} file(s)"
            ),
            description=(
                f"Rayhunter left {skipped} message(s) undecoded across "
                f"{len(summaries)} NDJSON file(s), including {encrypted} encrypted "
                f"NAS PDU(s). Those skips are capture-completeness notes. They are "
                f"not pre-security IMSI Identity Requests."
            ),
            severity="INFO",
            confidence="CONFIRMED",
            technique="Rayhunter skipped_message_reason tally",
            evidence=evidence,
            hardware_hint="Ciphered NAS after security setup is normal LTE. It does not identify the platform.",
            action=(
                "1. Do not cite an encrypted-NAS skip as an IMSI harvest.\n"
                "2. Read identity type from the PCAP: nas-eps.emm.id_type2 on "
                "nas-eps.nas_msg_emm_type == 0x55.\n"
                "3. Ciphered frames are listed with a nas-eps.ciphered_msg display filter."
            ),
            spec_ref="3GPP TS 24.301 §4.4.4 (NAS security header); TS 33.401",
        )]
