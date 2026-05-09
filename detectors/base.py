#!/usr/bin/env python3
"""Base class for all threat detectors."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime


SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

CONFIDENCE_LEVELS = {
    "CONFIRMED": 3,
    "PROBABLE": 2,
    "SUSPECTED": 1,
}


def make_finding(
    detector: str,
    title: str,
    description: str,
    severity: str,
    confidence: str,
    technique: str,
    evidence: List[str],
    events: List[Dict] = None,
    hardware_hint: str = None,
    action: str = None,
    cve: str = None,
    spec_ref: str = None,
) -> Dict:
    """Construct a standardised threat finding dict."""
    return {
        "detector": detector,
        "title": title,
        "description": description,
        "severity": severity,
        "severity_score": SEVERITY_LEVELS.get(severity, 0),
        "confidence": confidence,
        "confidence_score": CONFIDENCE_LEVELS.get(confidence, 0),
        "technique": technique,
        "evidence": evidence,
        "event_count": len(events) if events else 0,
        "hardware_hint": hardware_hint,
        "recommended_action": action,
        "spec_reference": spec_ref,
        "found_at": datetime.utcnow().isoformat(),
    }


class BaseDetector(ABC):
    """Abstract base class for all threat detectors."""

    name = "BaseDetector"
    description = ""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.thresholds = cfg.get("thresholds", {})

    @abstractmethod
    def analyze(self, events: List[Dict]) -> List[Dict]:
        """Analyze a list of normalised events, return list of findings."""
        pass

    def filter_by_type(self, events: List[Dict], msg_types: List[str]) -> List[Dict]:
        """Filter events to those matching any of the given message type strings."""
        msg_types_lower = [m.lower() for m in msg_types]
        return [
            e for e in events
            if any(
                m in str(e.get("msg_type", "")).lower()
                for m in msg_types_lower
            )
        ]

    def parse_timestamp(self, ev: Dict) -> float:
        """Parse event timestamp to Unix float. Returns 0.0 on failure."""
        ts = ev.get("timestamp")
        if not ts:
            return 0.0
        try:
            from dateutil import parser as dtparser
            dt = dtparser.parse(str(ts))
            return dt.timestamp()
        except Exception:
            pass
        try:
            return float(str(ts))
        except (ValueError, TypeError):
            return 0.0
