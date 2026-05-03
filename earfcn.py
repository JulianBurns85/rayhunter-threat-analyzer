#!/usr/bin/env python3
"""
EARFCN to Frequency Converter
==============================
Converts LTE E-ARFCN (E-UTRA Absolute Radio Frequency Channel Number)
to actual downlink/uplink frequencies in MHz, and identifies the
LTE band. Cross-references against ACMA licensed spectrum bands.

Source: 3GPP TS 36.101 Table 5.7.3-1
"""

from typing import Optional, Tuple, Dict

# LTE Band definitions: (band, dl_low_MHz, dl_high_MHz, ul_low_MHz, ul_high_MHz,
#                        earfcn_dl_low, earfcn_dl_high, earfcn_ul_low, earfcn_ul_high,
#                        name, notes)
LTE_BANDS = [
    (1,   2110, 2170, 1920, 1980, 0,     599,   18000, 18599, "Band 1",  "2100 MHz — used by Telstra/Optus in AU"),
    (2,   1930, 1990, 1850, 1910, 600,   1199,  18600, 19199, "Band 2",  "1900 MHz PCS"),
    (3,   1805, 1880, 1710, 1785, 1200,  1949,  19200, 19949, "Band 3",  "1800 MHz — used by Telstra/Vodafone AU"),
    (4,   2110, 2155, 1710, 1755, 1950,  2399,  19950, 20399, "Band 4",  "AWS-1"),
    (5,   869,  894,  824,  849,  2400,  2649,  20400, 20649, "Band 5",  "850 MHz — used by Telstra/Optus AU"),
    (7,   2620, 2690, 2500, 2570, 2750,  3449,  20750, 21449, "Band 7",  "2600 MHz"),
    (8,   925,  960,  880,  915,  3450,  3799,  21450, 21799, "Band 8",  "900 MHz — used by Vodafone/Optus AU"),
    (12,  729,  746,  699,  716,  5010,  5179,  23010, 23179, "Band 12", "700 MHz Lower A"),
    (13,  746,  756,  777,  787,  5180,  5279,  23180, 23279, "Band 13", "700 MHz Upper C"),
    (17,  734,  746,  704,  716,  5730,  5849,  23730, 23849, "Band 17", "700 MHz Lower B"),
    (18,  860,  875,  815,  830,  5850,  5999,  23850, 23999, "Band 18", "850 MHz Lower"),
    (19,  875,  890,  830,  845,  6000,  6149,  24000, 24149, "Band 19", "850 MHz Upper — used in Japan/AU"),
    (20,  791,  821,  832,  862,  6150,  6449,  24150, 24449, "Band 20", "800 MHz DD — used in EU"),
    (25,  1930, 1995, 1850, 1915, 8040,  8689,  26040, 26689, "Band 25", "1900 MHz+"),
    (26,  859,  894,  814,  849,  8690,  9039,  26690, 27039, "Band 26", "850 MHz"),
    (28,  758,  803,  703,  748,  9210,  9659,  27210, 27659, "Band 28", "700 MHz APT — major AU band (Telstra/Vodafone/Optus)"),
    (29,  717,  728,  None, None, 9660,  9769,  None,  None,  "Band 29", "700 MHz Lower D (DL only)"),
    (30,  2350, 2360, 2305, 2315, 9770,  9869,  27660, 27759, "Band 30", "2300 MHz WCS"),
    (34,  2010, 2025, 2010, 2025, 36200, 36349, 36200, 36349, "Band 34", "TDD 2000 MHz"),
    (38,  2570, 2620, 2570, 2620, 37750, 38249, 37750, 38249, "Band 38", "TDD 2600 MHz"),
    (39,  1880, 1920, 1880, 1920, 38250, 38649, 38250, 38649, "Band 39", "TDD 1900 MHz"),
    (40,  2300, 2400, 2300, 2400, 38650, 39649, 38650, 39649, "Band 40", "TDD 2300 MHz — used by Telstra AU"),
    (41,  2496, 2690, 2496, 2690, 39650, 41589, 39650, 41589, "Band 41", "TDD 2500 MHz"),
    (42,  3400, 3600, 3400, 3600, 41590, 43589, 41590, 43589, "Band 42", "TDD 3500 MHz"),
    (43,  3600, 3800, 3600, 3800, 43590, 45589, 43590, 45589, "Band 43", "TDD 3700 MHz"),
    (66,  2110, 2200, 1710, 1780, 66436, 67335, 131972, 132671, "Band 66", "AWS-3"),
]

# ACMA licensed bands in Australia — for cross-reference
ACMA_AU_LICENSED = {
    "Band 1":  "Licensed — Telstra/Optus 2100 MHz",
    "Band 3":  "Licensed — Telstra/Vodafone/Optus 1800 MHz",
    "Band 5":  "Licensed — Telstra/Optus 850 MHz",
    "Band 8":  "Licensed — Vodafone/Optus 900 MHz",
    "Band 28": "Licensed — Telstra/Vodafone/Optus 700 MHz APT (primary LTE band AU)",
    "Band 40": "Licensed — Telstra 2300 MHz TDD",
}


def earfcn_to_info(earfcn: int) -> Dict:
    """
    Convert an EARFCN to frequency info dict.
    
    Returns:
        dict with keys: earfcn, band, band_name, dl_freq_mhz, ul_freq_mhz,
                       acma_status, notes, is_suspicious
    """
    result = {
        "earfcn": earfcn,
        "band": None,
        "band_name": "Unknown",
        "dl_freq_mhz": None,
        "ul_freq_mhz": None,
        "acma_status": "Unknown — not in ACMA AU licensed band table",
        "notes": "",
        "is_suspicious": False,
    }

    for (band, dl_low, dl_high, ul_low, ul_high,
         earfcn_dl_low, earfcn_dl_high, earfcn_ul_low, earfcn_ul_high,
         band_name, notes) in LTE_BANDS:

        # Check downlink EARFCN range
        if earfcn_dl_low <= earfcn <= earfcn_dl_high:
            # Calculate exact DL frequency
            # DL freq = dl_low + 0.1 * (earfcn - earfcn_dl_low)
            offset = earfcn - earfcn_dl_low
            dl_freq = round(dl_low + 0.1 * offset, 1)
            
            # Calculate UL frequency (FDD offset, fixed per band)
            ul_freq = None
            if ul_low and earfcn_ul_low:
                ul_freq = round(ul_low + 0.1 * offset, 1)

            result.update({
                "band": band,
                "band_name": band_name,
                "dl_freq_mhz": dl_freq,
                "ul_freq_mhz": ul_freq,
                "notes": notes,
                "acma_status": ACMA_AU_LICENSED.get(band_name,
                    f"Not in primary AU licensed table — verify ACMA register"),
            })
            # Flag if EARFCN is in a licensed band but shouldn't be broadcasting here
            result["is_suspicious"] = band_name not in ACMA_AU_LICENSED
            return result

        # Check uplink EARFCN range (for completeness)
        if earfcn_ul_low and earfcn_ul_low <= earfcn <= earfcn_ul_high:
            offset = earfcn - earfcn_ul_low
            ul_freq = round(ul_low + 0.1 * offset, 1)
            result.update({
                "band": band,
                "band_name": f"{band_name} (UL)",
                "ul_freq_mhz": ul_freq,
                "notes": notes,
                "acma_status": ACMA_AU_LICENSED.get(band_name, "Not in primary AU table"),
            })
            return result

    return result


def format_earfcn(earfcn: int) -> str:
    """Return human-readable EARFCN description for reports."""
    info = earfcn_to_info(earfcn)
    if info["dl_freq_mhz"]:
        return (f"EARFCN {earfcn} = {info['dl_freq_mhz']} MHz DL "
                f"({info['band_name']}) — {info['acma_status']}")
    return f"EARFCN {earfcn} — band unknown"


def annotate_events_with_freq(events: list) -> list:
    """Add freq_info to all events that have an earfcn field."""
    for ev in events:
        earfcn = ev.get("earfcn")
        if earfcn and isinstance(earfcn, (int, float)):
            ev["freq_info"] = earfcn_to_info(int(earfcn))
    return events


def summarise_earfcns(events: list) -> list:
    """Return sorted list of unique EARFCN info dicts from events."""
    seen = {}
    for ev in events:
        earfcn = ev.get("earfcn")
        if earfcn and isinstance(earfcn, (int, float)):
            k = int(earfcn)
            if k not in seen:
                seen[k] = earfcn_to_info(k)
                seen[k]["count"] = 0
            seen[k]["count"] = seen[k].get("count", 0) + 1
    return sorted(seen.values(), key=lambda x: x.get("count", 0), reverse=True)
