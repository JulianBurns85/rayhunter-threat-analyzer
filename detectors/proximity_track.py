#!/usr/bin/env python3
"""Proximity tracking detector stub — logic is in handover_inject.py."""
from typing import List, Dict
from .base import BaseDetector


class ProximityTrackDetector(BaseDetector):
    name = "ProximityTrackDetector"
    description = "ProSe proximity tracking (see HandoverInjectDetector for implementation)"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        # Logic merged into HandoverInjectDetector._detect_prose_tracking
        return []
