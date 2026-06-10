#!/usr/bin/env python3
"""
RSRPDirectionalWedge — collapse the TA=7 distance ring into a bearing wedge.

THE PROBLEM
-----------
Timing Advance gives DISTANCE only. TA=7 puts the transmitter on a ring of
radius ~547m around the subject — a full 360 degrees of possibility. TA cannot
tell you WHICH direction.

THE METHOD
----------
RSRP (received power) falls off predictably with distance. If we have power
readings from the SAME rogue CID at multiple known positions, each reading
constrains the transmitter's location: a receiver that hears the cell LOUDER
is closer to it.

This tool fuses:
  1. A fixed reference node (tablet, always at home) — the anchor.
  2. Roving node samples (phone) that recorded the rogue CID at known GPS.
  3. The COST-231 Hata path-loss model to convert RSRP deltas -> distance ratios.

Each roving sample that hears the rogue cell pulls the probable transmitter
location toward that sample's bearing. Accumulate enough and the 360-degree
ring collapses to a probable emission wedge.

IMPORTANT HONEST CONSTRAINTS
----------------------------
- This ONLY works on samples where the roving node actually saw the SAME rogue
  CID (same eNB / CID / EARFCN) as the home transmitter. If the installation is
  stationary near home, distant trips (20-100km) will have NO rogue-CID hits —
  the phone is on legitimate towers out there. Those samples are correctly
  ignored. Useful data = the neighbourhood cluster at varying positions.
- COST-231 Hata is a statistical urban/suburban model. It gives a PROBABLE
  bearing, not a survey-grade fix. Treat output as "investigate this arc",
  not "dig here".
- Multipath, walls, and antenna orientation add noise. More samples = tighter
  wedge. A handful of samples gives a rough sector; dozens give a real wedge.

OUTPUT
------
A probable bearing (degrees from North) and an angular spread (the wedge),
plus the supporting per-sample geometry. Designed to feed straight into the
GhostNet map as an arc overlay on the existing TA ring.

Reference: COST-231 Hata model (European Cooperation in Science & Technology,
1999). RSRP multipoint localisation — standard SDR DF technique applied to a
fixed-transmitter civilian case.
"""

import math
import json
from typing import List, Dict, Optional, Tuple


# ── Path-loss model constants (COST-231 Hata, suburban) ──────────────── #
# These are the standard suburban-area parameters. Cranbourne East is
# outer-suburban, so suburban is the right correction factor.
_FREQ_MHZ = 763.0          # Band 28 (Telstra 700MHz) downlink approx centre
_BASE_HEIGHT_M = 10.0      # assumed transmitter antenna height (rooftop install)
_MOBILE_HEIGHT_M = 1.5     # receiver height (phone in hand / on dash)


def _cost231_pathloss_db(distance_m: float) -> float:
    """
    COST-231 Hata path loss in dB for a given distance (suburban).
    Returns expected path loss; we use DIFFERENCES so absolute calibration
    cancels out.
    """
    if distance_m < 1.0:
        distance_m = 1.0
    d_km = distance_m / 1000.0
    f = _FREQ_MHZ
    hb = _BASE_HEIGHT_M
    hm = _MOBILE_HEIGHT_M

    # Mobile antenna height correction (small/medium city)
    a_hm = (1.1 * math.log10(f) - 0.7) * hm - (1.56 * math.log10(f) - 0.8)

    # COST-231 Hata base formula
    L = (46.3 + 33.9 * math.log10(f) - 13.82 * math.log10(hb)
         - a_hm + (44.9 - 6.55 * math.log10(hb)) * math.log10(d_km))
    # suburban correction (Cm = 0 for suburban; 3 for metro). Use 0.
    return L


def _haversine_m(lat1, lon1, lat2, lon2) -> float:
    """Distance in metres between two lat/lon points."""
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(a))


def _bearing_deg(lat1, lon1, lat2, lon2) -> float:
    """Initial bearing from point 1 to point 2, degrees from North (0-360)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1)*math.sin(p2) - math.sin(p1)*math.cos(p2)*math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def _offset_point(lat, lon, bearing_deg, distance_m):
    """Project a point distance_m along bearing from (lat,lon)."""
    R = 6371000.0
    br = math.radians(bearing_deg)
    p1 = math.radians(lat)
    l1 = math.radians(lon)
    dr = distance_m / R
    p2 = math.asin(math.sin(p1)*math.cos(dr) + math.cos(p1)*math.sin(dr)*math.cos(br))
    l2 = l1 + math.atan2(math.sin(br)*math.sin(dr)*math.cos(p1),
                         math.cos(dr) - math.sin(p1)*math.sin(p2))
    return math.degrees(p2), math.degrees(l2)


class RSRPDirectionalWedge:
    """
    Estimate transmitter bearing from multipoint RSRP samples + TA ring.
    """

    def __init__(self,
                 subject_lat: float,
                 subject_lon: float,
                 ta_radius_m: float = 547.0,
                 ta_tolerance_m: float = 78.0):
        self.subject_lat = subject_lat
        self.subject_lon = subject_lon
        self.ta_radius_m = ta_radius_m
        self.ta_tolerance_m = ta_tolerance_m

    def estimate_distance_from_rsrp(self,
                                    rsrp_dbm: float,
                                    ref_rsrp_dbm: float,
                                    ref_distance_m: float) -> float:
        """
        Given a reference (rsrp, distance) pair, estimate distance for another
        rsrp using the path-loss model. Solves COST-231 for distance.

        Higher RSRP => closer. The delta between sample and reference path loss
        equals the delta in RSRP (transmit power & antenna gain cancel).
        """
        # path loss delta implied by rsrp delta
        # rsrp = TxPower - pathloss  =>  pathloss = TxPower - rsrp
        # delta_pathloss = ref_rsrp - rsrp   (if sample is weaker, more loss)
        ref_pl = _cost231_pathloss_db(ref_distance_m)
        sample_pl = ref_pl + (ref_rsrp_dbm - rsrp_dbm)

        # invert COST-231 for distance given path loss
        f = _FREQ_MHZ
        hb = _BASE_HEIGHT_M
        hm = _MOBILE_HEIGHT_M
        a_hm = (1.1 * math.log10(f) - 0.7) * hm - (1.56 * math.log10(f) - 0.8)
        const = (46.3 + 33.9 * math.log10(f) - 13.82 * math.log10(hb) - a_hm)
        slope = (44.9 - 6.55 * math.log10(hb))
        log_d_km = (sample_pl - const) / slope
        d_km = 10 ** log_d_km
        return max(1.0, d_km * 1000.0)

    def analyze(self,
                reference_sample: Dict,
                roving_samples: List[Dict]) -> Dict:
        """
        reference_sample: fixed node anchor
            {"rsrp": -78.0, "lat":..., "lon":...}  (tablet at home)
        roving_samples: list of phone samples that SAW THE SAME ROGUE CID
            [{"rsrp": -72.0, "lat":..., "lon":..., "ts":..., "cid":...}, ...]

        Returns wedge estimate dict.
        """
        ref_rsrp = float(reference_sample["rsrp"])
        ref_lat = float(reference_sample.get("lat", self.subject_lat))
        ref_lon = float(reference_sample.get("lon", self.subject_lon))
        ref_dist = _haversine_m(self.subject_lat, self.subject_lon, ref_lat, ref_lon)
        if ref_dist < 1.0:
            ref_dist = self.ta_radius_m  # reference is at subject; anchor to ring

        per_sample = []
        bearing_votes = []   # (bearing, weight)

        for s in roving_samples:
            try:
                rsrp = float(s["rsrp"])
                slat = float(s["lat"])
                slon = float(s["lon"])
            except (KeyError, TypeError, ValueError):
                continue

            # estimate this sample's distance to the transmitter
            est_dist = self.estimate_distance_from_rsrp(rsrp, ref_rsrp, ref_dist)

            # The transmitter lies ~est_dist from the sample position AND
            # ~ta_radius from the subject. The bearing from subject toward the
            # sample is informative — but a sample only votes that the Tx is in
            # ITS direction if the sample is CLOSE to the Tx (loud). A weak
            # sample is evidence the Tx is NOT that way; we encode that by
            # weighting votes by proximity-to-Tx, so distant samples contribute
            # almost nothing rather than pulling the mean toward themselves.
            samp_bearing_from_subject = _bearing_deg(
                self.subject_lat, self.subject_lon, slat, slon)
            samp_offset = _haversine_m(self.subject_lat, self.subject_lon, slat, slon)

            # Proximity-to-Tx weight: closer estimated distance = stronger vote.
            # Use inverse-distance so a 340m sample dominates a 1000m sample.
            prox = (self.ta_radius_m / est_dist) ** 2  # quadratic emphasis
            # Only samples offset from subject carry bearing information
            offset_weight = min(1.0, samp_offset / (self.ta_radius_m * 0.5))
            weight = prox * offset_weight

            if samp_offset >= 5.0:  # ignore samples basically on top of subject
                bearing_votes.append((samp_bearing_from_subject, weight))

            per_sample.append({
                "rsrp": rsrp,
                "est_dist_to_tx_m": round(est_dist, 1),
                "offset_from_subject_m": round(samp_offset, 1),
                "bearing_from_subject_deg": round(samp_bearing_from_subject, 1),
                "weight": round(weight, 3),
            })

        if not bearing_votes:
            return {
                "status": "INSUFFICIENT_DATA",
                "reason": ("No roving samples with usable offset + RSRP for the "
                           "rogue CID. Need phone samples that saw the same CID "
                           "from positions away from the subject address."),
                "per_sample": per_sample,
            }

        # Circular mean of weighted bearings
        sin_sum = sum(w * math.sin(math.radians(b)) for b, w in bearing_votes)
        cos_sum = sum(w * math.cos(math.radians(b)) for b, w in bearing_votes)
        mean_bearing = (math.degrees(math.atan2(sin_sum, cos_sum)) + 360.0) % 360.0

        # Angular spread (circular standard deviation) -> wedge half-width
        R = math.sqrt(sin_sum**2 + cos_sum**2) / sum(w for _, w in bearing_votes)
        R = max(1e-6, min(1.0, R))
        circ_std_deg = math.degrees(math.sqrt(-2.0 * math.log(R)))
        wedge_half = max(7.5, min(90.0, circ_std_deg))  # floor 7.5deg, cap 90

        # Probable transmitter point: on the TA ring, at mean bearing
        tx_lat, tx_lon = _offset_point(
            self.subject_lat, self.subject_lon, mean_bearing, self.ta_radius_m)

        return {
            "status": "OK",
            "n_votes": len(bearing_votes),
            "probable_bearing_deg": round(mean_bearing, 1),
            "wedge_half_width_deg": round(wedge_half, 1),
            "wedge_arc_deg": round(wedge_half * 2, 1),
            "concentration_R": round(R, 3),
            "ta_radius_m": self.ta_radius_m,
            "probable_tx_latlon": [round(tx_lat, 6), round(tx_lon, 6)],
            "wedge_edges_deg": [round((mean_bearing - wedge_half) % 360, 1),
                                round((mean_bearing + wedge_half) % 360, 1)],
            "per_sample": per_sample,
            "caveat": ("Probable bearing from statistical path-loss model. "
                       "Investigate this arc; not a survey-grade fix."),
        }


if __name__ == "__main__":
    # Demonstration with synthetic but realistic geometry.
    # Subject at Cranbourne East; assume true transmitter is NORTHEAST of house.
    SUBJ_LAT, SUBJ_LON = -38.1100, 145.2780
    wedge = RSRPDirectionalWedge(SUBJ_LAT, SUBJ_LON, ta_radius_m=547.0)

    # Tablet at home hears rogue CID at -78 dBm (reference anchor)
    reference = {"rsrp": -78.0, "lat": SUBJ_LAT, "lon": SUBJ_LON}

    # Phone samples around the neighbourhood that saw the SAME rogue CID.
    # Samples taken NE of the house hear it louder (closer to a NE transmitter).
    rov = [
        {"rsrp": -70.0, "lat": -38.1075, "lon": 145.2805, "cid": 137713165},  # NE, loud
        {"rsrp": -72.0, "lat": -38.1080, "lon": 145.2800, "cid": 137713165},  # NE, loud
        {"rsrp": -85.0, "lat": -38.1130, "lon": 145.2755, "cid": 137713165},  # SW, weak
        {"rsrp": -83.0, "lat": -38.1125, "lon": 145.2760, "cid": 137713165},  # SW, weak
        {"rsrp": -74.0, "lat": -38.1078, "lon": 145.2808, "cid": 137713165},  # NE, loud
        {"rsrp": -88.0, "lat": -38.1135, "lon": 145.2750, "cid": 137713165},  # SW, weak
    ]

    result = wedge.analyze(reference, rov)
    print(json.dumps(result, indent=2))
