# Source-tagging the CASTNET detectors

Root-cause fix for the bleed-through: each detector that reads external data
(CASTNET history, known transmitter locations) stamps its findings with a
`source` tag, so a reviewer — and the guard — can tell capture-derived findings
from history-derived ones.

## The four detectors to tag
- detectors/cross_carrier_timer_correlator.py
- detectors/regulatory_escalation_scorer.py
- detectors/regulatory_correlator.py
- detectors/attack_intensity_scorer.py
(plus any other that reads castnet_*.csv / the CASTNET store)

## The change (one line per return)
Each detector's `analyze()` ends by returning a list of make_finding() dicts.
Wrap that return:

```python
from corpus_guard import tag_source
...
    return [tag_source(f, "castnet") for f in findings]
```

For a detector that derives location from your KNOWN transmitter positions
(kml_exporter, geographic_baseline_exhibit, dual_unit_triangulator):

```python
    return [tag_source(f, "known_location") for f in findings]
```

That's it. `tag_source` just sets f["source"] and returns f, so it's safe to
wrap any existing return.

## Why it matters
- check_source_tags() stops flagging them (they're now honestly labelled).
- check_geo_provenance() passes known_location findings cleanly.
- The report can render "observed in this capture" (source=capture, the default
  for untagged) separately from "corroborated against CASTNET history"
  (source=castnet). CASTNET data stays usable as cross-reference — it just can
  never again masquerade as fresh capture output.

## Optional: make 'capture' explicit
In base.py make_finding(), the default source is absent (treated as "capture").
If you want it explicit, add to the returned dict:
    "source": "capture",
and the four CASTNET detectors override it to "castnet" via tag_source.
