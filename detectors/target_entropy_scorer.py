#!/usr/bin/env python3
"""
TargetEntropyScorer — Shannon entropy of paging/harvest TARGETS.

Companion to NASEntropyScorer. Where that detector measures the entropy of
message TYPES (proving the platform runs a repetitive machine loop), this
detector measures the entropy of the message TARGETS — the m-TMSI / C-RNTI
identifiers being paged or harvested.

The distinction matters because it separates two very different operations:

  HIGH target entropy  → mass-surveillance sweep. The platform interacts
                         with hundreds of unique identifiers roughly equally.
                         Every device on the cell is being touched. This is
                         indiscriminate collection (DRTBox-style dragnet).

  LOW target entropy   → active targeted hunt. A small number of identifiers
                         dominate the distribution. The platform is hunting
                         specific devices, not sweeping the area.
                         Near-zero entropy = a single target dominates.

Shannon entropy:  H = -Σ p(x) * log2(p(x))

  Maximum entropy (uniform over N targets): log2(N)
  Minimum entropy (one target, all pages):  0

Normalised entropy (H / log2(N)) gives a 0..1 score independent of how many
identifiers appear, so a 3-target capture and a 300-target capture are
directly comparable.

Evidence basis (Cranbourne East corpus):
  - m-TMSI d8736117 paged 402 times in 2.04h (25 May 2026)
  - That single identifier dominating the paging distribution is the
    signature of a targeted hunt, NOT a mass sweep. This detector
    quantifies that domination as a single number.

This is the mathematical counter to a "you were just near a mass-collection
device" defence: low target entropy shows YOU specifically were the target.

Reference: Shannon (1948). Target-distribution entropy as targeting
discriminator — novel application, Hidden Blade investigation 2026.

Place this file in: detectors/target_entropy_scorer.py
"""

from collections import Counter
from typing import List, Dict
import math

from .base import BaseDetector, make_finding


# ── Thresholds ───────────────────────────────────────────────────────── #
_MIN_TARGETS = 5          # need at least this many distinct identifiers to score
_MIN_EVENTS = 30          # need at least this many target-bearing events
# Normalised entropy bands (H / Hmax, range 0..1)
_TARGETED_MAX = 0.40      # <= this = targeted hunt (a few IDs dominate)
_SWEEP_MIN = 0.80         # >= this = mass sweep (near-uniform over many IDs)
# Single-target domination: one ID is >= this fraction of all events
_DOMINATION_FRAC = 0.50
_TOP_N_REPORT = 8


class TargetEntropyScorer(BaseDetector):
    """
    Shannon entropy of the TARGET identifier distribution.

    Low entropy  = a few identifiers dominate = active targeted hunt.
    High entropy = many identifiers touched equally = mass sweep.
    """

    name = "TargetEntropyScorer"
    description = (
        "Shannon entropy of paging/harvest target distribution — "
        "separates targeted hunt (low entropy) from mass sweep (high entropy)"
    )

    # ------------------------------------------------------------------ #
    # Target identifier extraction
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_targets(events: List[Dict]) -> Dict[str, List[str]]:
        """
        Pull target identifiers out of the event 'msg' string field.

        Mirrors paging_target.py extraction: identifiers live inside the
        free-text 'msg' field, not in dedicated keys. Returns a dict of
        {identifier_type: [values...]}.
        """
        targets: Dict[str, List[str]] = {"m-TMSI": [], "C-RNTI": [], "S-TMSI": []}

        for ev in events:
            msg = str(ev.get("msg", ""))
            if not msg:
                # some pipelines also expose message_type/msg_type only — skip,
                # those carry no target identifier
                continue

            for key in ("m-TMSI", "C-RNTI", "S-TMSI"):
                marker = key + ":"
                if marker in msg:
                    try:
                        raw = msg.split(marker)[1].split()[0]
                        val = raw.strip("[](),")
                        if val:
                            targets[key].append(val)
                    except (IndexError, AttributeError):
                        continue

        return targets

    @staticmethod
    def _shannon_entropy(values: List[str]) -> float:
        """H = -Σ p(x) log2 p(x) over the value distribution."""
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        h = 0.0
        for c in counts.values():
            p = c / total
            h -= p * math.log2(p)
        return h

    # ------------------------------------------------------------------ #
    # Main analysis entry point
    # ------------------------------------------------------------------ #
    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        target_sets = self._extract_targets(events)

        for id_type, values in target_sets.items():
            if len(values) < _MIN_EVENTS:
                continue

            counts = Counter(values)
            n_unique = len(counts)
            if n_unique < _MIN_TARGETS:
                # Too few distinct IDs to compute meaningful entropy, but this
                # itself is a targeting signal — handle as domination below.
                pass

            total = len(values)
            entropy = self._shannon_entropy(values)
            max_entropy = math.log2(n_unique) if n_unique > 1 else 0.0
            norm_entropy = (entropy / max_entropy) if max_entropy > 0 else 0.0

            # Domination: does a single identifier own most of the events?
            top_id, top_count = counts.most_common(1)[0]
            domination = top_count / total if total else 0.0

            # ── Classification ──────────────────────────────────────── #
            is_targeted = (norm_entropy <= _TARGETED_MAX) or (domination >= _DOMINATION_FRAC)
            is_sweep = norm_entropy >= _SWEEP_MIN and n_unique >= 20

            if not (is_targeted or is_sweep):
                continue  # ambiguous middle band — no finding

            if is_targeted:
                # The more one ID dominates, the more severe
                if domination >= 0.75 or norm_entropy <= 0.20:
                    severity = "CRITICAL"
                    confidence = "CONFIRMED"
                else:
                    severity = "HIGH"
                    confidence = "PROBABLE"
                classification = "TARGETED HUNT"
            else:
                severity = "MEDIUM"
                confidence = "PROBABLE"
                classification = "MASS SWEEP"

            top_targets = counts.most_common(_TOP_N_REPORT)

            evidence = [
                f"Target identifier type: {id_type}",
                f"Total target-bearing events: {total:,}",
                f"Distinct identifiers: {n_unique}",
                "",
                "ENTROPY:",
                f"  Target entropy:    {entropy:.4f} bits",
                f"  Maximum possible:  {max_entropy:.4f} bits (log2 of {n_unique} IDs)",
                f"  Normalised:        {norm_entropy:.4f} (0=single target, 1=uniform sweep)",
                "",
                f"DOMINATION:",
                f"  Top identifier: {top_id}",
                f"  Top count:      {top_count:,} of {total:,} ({domination*100:.1f}%)",
                "",
                "INTERPRETATION:",
                f"  Targeted-hunt band: normalised entropy <= {_TARGETED_MAX}",
                f"  Mass-sweep band:    normalised entropy >= {_SWEEP_MIN}",
                f"  This capture:       {norm_entropy:.4f}  ->  {classification}",
                "",
                "TOP TARGETS:",
            ]
            for tid, c in top_targets:
                evidence.append(f"  {tid}: {c:,} ({c/total*100:.1f}%)")

            if classification == "TARGETED HUNT":
                summary = (
                    f"{id_type} distribution shows active targeted hunting — "
                    f"normalised entropy {norm_entropy:.3f} (target {top_id} "
                    f"is {domination*100:.0f}% of all {id_type} events). This is "
                    f"selective targeting, not indiscriminate area collection."
                )
            else:
                summary = (
                    f"{id_type} distribution shows mass-sweep collection — "
                    f"normalised entropy {norm_entropy:.3f} across {n_unique} "
                    f"identifiers touched near-equally (indiscriminate dragnet)."
                )

            findings.append(make_finding(
                detector=self.name,
                title=f"Target Entropy: {classification} ({id_type})",
                severity=severity,
                confidence=confidence,
                summary=summary,
                evidence=evidence,
            ))

        return findings
