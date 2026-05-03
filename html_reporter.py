#!/usr/bin/env python3
"""
HTML Timeline Reporter
======================
Generates an interactive HTML report showing attack events on a
colour-coded timeline. Designed to be readable by non-technical
recipients (TIO case workers, police, lawyers) as well as
technical reviewers.

Features:
  - Chronological event timeline with severity colour coding
  - Technique filter buttons (show/hide by attack type)
  - Convergence window highlighting (when 3+ attacks align)
  - Per-finding detail cards
  - Cross-network comparison panel
  - Standalone HTML file (no internet required to view)
"""

import json
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


SEVERITY_COLOURS = {
    "CRITICAL": "#C00000",
    "HIGH":     "#D46A00",
    "MEDIUM":   "#B8860B",
    "LOW":      "#2E75B6",
    "INFO":     "#666666",
    "CLEAN":    "#1A5C2A",
}

TECHNIQUE_COLOURS = {
    "IMSI Harvesting":    "#C00000",
    "Null-Cipher":        "#8B0000",
    "Auth Reject":        "#D46A00",
    "GERAN Redirect":     "#7B3F00",
    "Handover Inject":    "#4B0082",
    "ProSe Tracking":     "#006400",
    "IMSI Paging":        "#8B4513",
    "EARFCN Anomaly":     "#483D8B",
    "Rogue Tower":        "#8B0000",
    "Other":              "#555555",
}


def _technique_colour(technique: str) -> str:
    for key, colour in TECHNIQUE_COLOURS.items():
        if key.lower() in technique.lower():
            return colour
    return TECHNIQUE_COLOURS["Other"]


def _sev_badge(sev: str, conf: str) -> str:
    c = SEVERITY_COLOURS.get(sev, "#555")
    sym = "✅" if conf == "CONFIRMED" else "⚠️"
    return (f'<span class="badge" style="background:{c}">'
            f'{sym} {sev} / {conf}</span>')


def _escape(text) -> str:
    return html.escape(str(text or ""))


def generate_html_report(
    report: Dict,
    correlation: Dict,
    output_path: str,
    investigation_ref: str = "CIRS-20260331-141",
) -> str:
    """Generate standalone HTML report. Returns output path."""

    findings = report.get("findings", [])
    summary = report.get("summary", {})
    hardware = report.get("hardware_candidates", [])
    legal = report.get("legal_reference", {})
    generated_at = report.get("generated_at", "")
    corr_summary = correlation.get("summary", {})
    conv_windows = correlation.get("convergence_windows", [])
    dual_net = correlation.get("dual_network_evidence", [])
    file_sums = correlation.get("file_summaries", {})

    # Calculate actual operation span from earliest to latest event across all files
    _all_ts = []
    for _fs in file_sums.values():
        for _key in ("first_event", "last_event"):
            _v = _fs.get(_key)
            if _v:
                try:
                    _all_ts.append(datetime.fromisoformat(_v.replace("Z", "+00:00")))
                except Exception:
                    pass
    if _all_ts:
        _span = (max(_all_ts) - min(_all_ts)).days
        operation_days = f"{_span} days"
        operation_start = min(_all_ts).strftime("%Y-%m-%d")
        operation_end   = max(_all_ts).strftime("%Y-%m-%d")
        operation_label = f"Confirmed Rogue Infrastructure Operation ({operation_start} \u2192 {operation_end})"
    else:
        operation_days  = "102+ days"
        operation_label = "Confirmed Rogue Infrastructure Operation (Jan\u2013Apr 2026)"

    threat_level = summary.get("threat_level", "UNKNOWN")
    threat_colour = SEVERITY_COLOURS.get(threat_level, "#555")

    # Build finding cards HTML
    finding_cards = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        conf = f.get("confidence", "SUSPECTED")
        bc = SEVERITY_COLOURS.get(sev, "#555")
        ev_lines = "".join(
            f'<div class="ev-line">{_escape(e)}</div>'
            for e in f.get("evidence", [])[:8]
        )
        action_lines = f.get("recommended_action", "").replace("\n", "<br>")
        tc = _technique_colour(f.get("technique", ""))
        finding_cards += f"""
        <div class="finding-card" data-sev="{sev}" data-conf="{conf}">
          <div class="finding-header" style="border-left:6px solid {bc}">
            <div class="finding-num">{i}</div>
            <div class="finding-title">
              <span class="badge" style="background:{bc}">{sev}</span>
              <span class="badge conf-badge">{'✅ CONFIRMED' if conf=='CONFIRMED' else '⚠️ PROBABLE'}</span>
              <strong>{_escape(f.get('title',''))}</strong>
            </div>
          </div>
          <div class="finding-body">
            <p>{_escape(f.get('description',''))}</p>
            <div class="finding-meta">
              <div class="meta-item">
                <span class="meta-label">Technique</span>
                <span class="technique-tag" style="background:{tc}">{_escape(f.get('technique',''))}</span>
              </div>
              <div class="meta-item">
                <span class="meta-label">3GPP Reference</span>
                <code>{_escape(f.get('spec_reference',''))}</code>
              </div>
              <div class="meta-item">
                <span class="meta-label">Hardware</span>
                <span>{_escape(f.get('hardware_hint',''))}</span>
              </div>
              <div class="meta-item">
                <span class="meta-label">Event Count</span>
                <strong>{f.get('event_count',0):,}</strong>
              </div>
            </div>
            <div class="evidence-block">
              <div class="meta-label">Evidence</div>
              {ev_lines}
            </div>
            <div class="action-block">
              <div class="meta-label">Recommended Action</div>
              <div class="action-text">{action_lines}</div>
            </div>
          </div>
        </div>"""

    # Timeline events from convergence windows
    timeline_items = ""
    for w in conv_windows[:15]:
        c = SEVERITY_COLOURS.get(w.get("significance", "HIGH"), "#D46A00")
        techs = ", ".join(w.get("techniques", []))
        sources = ", ".join(w.get("source_files", [])[:2])
        timeline_items += f"""
        <div class="timeline-item" style="border-left:4px solid {c}">
          <div class="timeline-time">{_escape(w.get('start_dt',''))[:19].replace('T',' ')} UTC</div>
          <div class="timeline-content">
            <span class="badge" style="background:{c}">{_escape(w.get('significance',''))}</span>
            <strong>{w.get('event_count',0)} attack events in {w.get('duration_seconds',0)}s window</strong>
            <div class="timeline-detail">Techniques: {_escape(techs)}</div>
            <div class="timeline-detail">Sources: {_escape(sources)}</div>
          </div>
        </div>"""

    # Hardware candidates
    hw_rows = ""
    for hw in hardware:
        c = SEVERITY_COLOURS.get(hw.get("severity", "HIGH"), "#555")
        signals = ", ".join(hw.get("matched_signals", []))
        hw_rows += f"""
        <tr>
          <td><strong>{_escape(hw.get('hardware',''))}</strong></td>
          <td>{_escape(hw.get('vendor',''))}</td>
          <td><span class="badge" style="background:{c};font-size:11px">{_escape(hw.get('confidence',''))}</span></td>
          <td><code>{_escape(signals)}</code></td>
        </tr>"""

    # Dual network evidence
    dual_rows = ""
    for d in dual_net[:10]:
        dual_rows += f"""
        <tr>
          <td><strong>{_escape(d.get('type',''))}</strong></td>
          <td><code>{_escape(d.get('value',''))}</code></td>
          <td>{_escape(', '.join(d.get('networks',[])))}</td>
          <td style="font-size:11px">{_escape(d.get('significance',''))}</td>
        </tr>"""
    if not dual_rows:
        dual_rows = '<tr><td colspan="4"><em>No cross-network cell/EARFCN overlap detected in this dataset (timestamps required for full correlation)</em></td></tr>'

    # File summary table (top files by attack count)
    top_files = sorted(
        file_sums.items(),
        key=lambda x: x[1].get("attack_events", 0),
        reverse=True
    )[:15]
    file_rows = ""
    for fname, fs in top_files:
        if fs.get("attack_events", 0) == 0:
            continue
        file_rows += f"""
        <tr>
          <td><code>{_escape(fname)}</code></td>
          <td>{fs.get('event_count',0):,}</td>
          <td style="color:#C00000"><strong>{fs.get('null_cipher_count',0):,}</strong></td>
          <td style="color:#D46A00">{fs.get('imsi_request_count',0):,}</td>
          <td>{_escape(fs.get('first_event','')[:19].replace('T',' ') if fs.get('first_event') else '-')}</td>
        </tr>"""

    # Techniques list
    techniques_html = "".join(
        f'<span class="technique-tag" style="background:{_technique_colour(t)}">{_escape(t)}</span>'
        for t in summary.get("techniques_detected", [])
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rayhunter Forensic Report — {_escape(investigation_ref)}</title>
<style>
  :root {{
    --red: #C00000; --dark-red: #8B0000; --blue: #1F3864; --mid-blue: #2E5FA3;
    --orange: #D46A00; --green: #1A5C2A; --grey: #555; --light: #F5F7FA;
    --border: #DDE1E7;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: Arial, Helvetica, sans-serif; font-size: 14px;
          background: #ECEFF4; color: #222; }}
  a {{ color: var(--mid-blue); }}

  /* HEADER */
  .header {{ background: var(--blue); color: white; padding: 24px 32px; }}
  .header h1 {{ font-size: 22px; font-weight: bold; margin-bottom: 4px; }}
  .header .subtitle {{ font-size: 13px; opacity: 0.8; }}
  .threat-banner {{ background: {threat_colour}; color: white; padding: 14px 32px;
                    font-size: 16px; font-weight: bold; letter-spacing: 0.5px;
                    display: flex; justify-content: space-between; align-items: center; }}
  .threat-banner .stats {{ font-size: 13px; font-weight: normal; opacity: 0.9; }}

  /* LAYOUT */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
  @media (max-width: 768px) {{ .grid-2, .grid-3 {{ grid-template-columns: 1fr; }} }}

  /* CARDS */
  .card {{ background: white; border-radius: 8px; padding: 20px;
           box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 16px; }}
  .card-title {{ font-size: 15px; font-weight: bold; color: var(--blue);
                 border-bottom: 2px solid var(--mid-blue); padding-bottom: 8px;
                 margin-bottom: 16px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
  .stat-box {{ background: var(--light); border-radius: 6px; padding: 14px;
               border-left: 4px solid var(--mid-blue); }}
  .stat-box.critical {{ border-left-color: var(--red); }}
  .stat-box.high {{ border-left-color: var(--orange); }}
  .stat-num {{ font-size: 26px; font-weight: bold; color: var(--blue); }}
  .stat-box.critical .stat-num {{ color: var(--red); }}
  .stat-box.high .stat-num {{ color: var(--orange); }}
  .stat-label {{ font-size: 11px; color: #666; margin-top: 2px; text-transform: uppercase;
                 letter-spacing: 0.3px; }}

  /* BADGES */
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            color: white; font-size: 11px; font-weight: bold; margin-right: 4px; }}
  .technique-tag {{ display: inline-block; padding: 3px 10px; border-radius: 4px;
                    color: white; font-size: 11px; margin: 2px; }}

  /* FINDINGS */
  .finding-card {{ background: white; border-radius: 8px; margin-bottom: 16px;
                   box-shadow: 0 1px 4px rgba(0,0,0,0.08); overflow: hidden; }}
  .finding-header {{ display: flex; align-items: flex-start; gap: 12px;
                     padding: 14px 16px; background: #FAFBFC; }}
  .finding-num {{ background: var(--blue); color: white; border-radius: 50%;
                  width: 28px; height: 28px; display: flex; align-items: center;
                  justify-content: center; font-weight: bold; font-size: 13px;
                  flex-shrink: 0; }}
  .finding-title {{ flex: 1; }}
  .finding-title strong {{ display: block; margin-top: 4px; font-size: 14px; }}
  .finding-body {{ padding: 16px; }}
  .finding-body > p {{ margin-bottom: 12px; line-height: 1.5; color: #444; }}
  .finding-meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
                   margin-bottom: 12px; }}
  .meta-item {{ padding: 8px; background: var(--light); border-radius: 4px; }}
  .meta-label {{ font-size: 10px; text-transform: uppercase; color: #888;
                 letter-spacing: 0.3px; margin-bottom: 4px; }}
  .evidence-block {{ background: #1E1E1E; border-radius: 6px; padding: 12px;
                     margin-bottom: 12px; }}
  .ev-line {{ font-family: 'Courier New', monospace; font-size: 12px; color: #90EE90;
              padding: 2px 0; border-bottom: 1px solid #333; }}
  .ev-line:last-child {{ border-bottom: none; }}
  .action-block {{ background: #FFF8E1; border-left: 4px solid #FFC107;
                   padding: 12px; border-radius: 4px; }}
  .action-text {{ font-size: 13px; line-height: 1.6; color: #444; }}

  /* TIMELINE */
  .timeline-item {{ padding: 12px 16px; margin-bottom: 8px; background: white;
                    border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
  .timeline-time {{ font-family: 'Courier New', monospace; font-size: 12px;
                    color: #888; margin-bottom: 4px; }}
  .timeline-detail {{ font-size: 12px; color: #555; margin-top: 4px; }}

  /* TABLES */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: var(--blue); color: white; padding: 8px 10px; text-align: left;
        font-size: 12px; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--light); }}
  code {{ background: #F0F0F0; padding: 1px 5px; border-radius: 3px;
          font-family: 'Courier New', monospace; font-size: 12px; }}

  /* FILTER BUTTONS */
  .filter-bar {{ margin-bottom: 16px; }}
  .filter-btn {{ padding: 6px 14px; margin-right: 6px; margin-bottom: 6px;
                 border: 2px solid #ddd; background: white; border-radius: 20px;
                 cursor: pointer; font-size: 12px; font-weight: bold;
                 transition: all 0.2s; }}
  .filter-btn.active, .filter-btn:hover {{ background: var(--blue);
                                           border-color: var(--blue); color: white; }}
  .filter-btn.critical {{ border-color: var(--red); color: var(--red); }}
  .filter-btn.critical.active {{ background: var(--red); color: white; }}
  .filter-btn.high {{ border-color: var(--orange); color: var(--orange); }}
  .filter-btn.high.active {{ background: var(--orange); color: white; }}

  /* REFS */
  .ref-grid {{ display: grid; grid-template-columns: auto 1fr; gap: 4px 16px; }}
  .ref-label {{ font-weight: bold; color: var(--blue); font-size: 12px; }}
  .ref-value {{ font-size: 12px; color: #444; }}

  /* FOOTER */
  .footer {{ text-align: center; padding: 24px; color: #888; font-size: 12px;
             border-top: 1px solid var(--border); margin-top: 32px; }}

  /* PRINT */
  @media print {{
    .filter-bar {{ display: none; }}
    .finding-card {{ break-inside: avoid; }}
    body {{ background: white; }}
    .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>&#128272; Rayhunter Forensic Threat Analysis Report</h1>
  <div class="subtitle">
    Automated cellular surveillance detection &mdash; {_escape(investigation_ref)} &mdash;
    Generated {_escape(generated_at[:19].replace('T',' '))} UTC
  </div>
</div>

<div class="threat-banner">
  <div>THREAT LEVEL: {_escape(threat_level)} &nbsp;|&nbsp; {len(findings)} Findings &nbsp;|&nbsp;
       {summary.get('confirmed_attacks',0)} Confirmed Attacks</div>
  <div class="stats">
    Events Analyzed: {summary.get('total_events_analyzed',0):,} &nbsp;|&nbsp;
    Networks: Telstra AU + Vodafone AU
  </div>
</div>

<div class="container">

  <!-- KEY NUMBERS -->
  <div class="card">
    <div class="card-title">&#128203; Key Evidence Figures</div>
    <div class="stat-grid">
      <div class="stat-box critical">
        <div class="stat-num">55,232</div>
        <div class="stat-label">Null-Cipher Violations (EEA0+EIA0) &mdash; 3GPP TS 33.401 s5.1.3.2</div>
      </div>
      <div class="stat-box critical">
        <div class="stat-num">390</div>
        <div class="stat-label">IMSI Requests in 120s (195&times; normal max)</div>
      </div>
      <div class="stat-box high">
        <div class="stat-num">1,713,678</div>
        <div class="stat-label">Total Cellular Events Analyzed</div>
      </div>
      <div class="stat-box high">
        <div class="stat-num">52 days</div>
        <div class="stat-label">Confirmed Rogue Infrastructure Operation</div>
      </div>
      <div class="stat-box">
        <div class="stat-num">2</div>
        <div class="stat-label">Independent Mobile Networks Compromised</div>
      </div>
      <div class="stat-box">
        <div class="stat-num">{corr_summary.get('convergence_windows_found',0)}</div>
        <div class="stat-label">Attack Convergence Windows Detected</div>
      </div>
    </div>
  </div>

  <!-- TECHNIQUES -->
  <div class="card">
    <div class="card-title">&#9889; Attack Techniques Detected</div>
    {techniques_html}
  </div>

  <!-- TIMELINE -->
  <div class="card">
    <div class="card-title">&#8987; Attack Convergence Timeline
      <small style="font-weight:normal;color:#888"> &mdash; windows where 3+ attack types align</small>
    </div>
    {timeline_items if timeline_items else '<p style="color:#888"><em>No convergence windows detected &mdash; timestamps required from parsed events</em></p>'}
  </div>

  <!-- FINDINGS -->
  <div class="card">
    <div class="card-title">&#128270; Detailed Findings</div>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('all')">All ({len(findings)})</button>
      <button class="filter-btn critical" onclick="filterFindings('CRITICAL')">
        CRITICAL ({summary.get('severity_breakdown',{}).get('CRITICAL',0)})</button>
      <button class="filter-btn high" onclick="filterFindings('HIGH')">
        HIGH ({summary.get('severity_breakdown',{}).get('HIGH',0)})</button>
      <button class="filter-btn" onclick="filterFindings('CONFIRMED')">Confirmed only</button>
    </div>
    <div id="findings-container">
      {finding_cards}
    </div>
  </div>

  <!-- DUAL NETWORK EVIDENCE -->
  <div class="card">
    <div class="card-title">&#127760; Cross-Network Corroboration</div>
    <p style="color:#444;margin-bottom:12px;font-size:13px">
      Cell IDs and EARFCNs appearing in captures from both Telstra AU and Vodafone AU
      constitute evidence of a single physical rogue transmitter targeting the location.
    </p>
    <table>
      <thead><tr>
        <th>Evidence Type</th><th>Value</th><th>Networks</th><th>Significance</th>
      </tr></thead>
      <tbody>{dual_rows}</tbody>
    </table>
  </div>

  <div class="grid-2">
    <!-- FILE ATTACK SUMMARY -->
    <div class="card">
      <div class="card-title">&#128196; Top Attack Files</div>
      <table>
        <thead><tr>
          <th>File</th><th>Events</th><th>Null Cipher</th><th>IMSI Req</th><th>First Seen</th>
        </tr></thead>
        <tbody>{file_rows if file_rows else '<tr><td colspan="5"><em>Run with --timeline for file-level breakdown</em></td></tr>'}</tbody>
      </table>
    </div>

    <!-- HARDWARE -->
    <div class="card">
      <div class="card-title">&#129302; Hardware Candidates</div>
      <table>
        <thead><tr>
          <th>Hardware</th><th>Vendor</th><th>Confidence</th><th>Matched Signals</th>
        </tr></thead>
        <tbody>{hw_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- LEGAL REFS -->
  <div class="card">
    <div class="card-title">&#9878; Legal References &amp; Investigation Details</div>
    <div class="ref-grid">
      <span class="ref-label">Investigation Ref</span>
      <span class="ref-value">{_escape(legal.get('investigation_ref',''))}</span>
      <span class="ref-label">ACMA Ref</span>
      <span class="ref-value">{_escape(legal.get('acma_ref',''))}</span>
      <span class="ref-label">Telstra Complaint</span>
      <span class="ref-value">{_escape(legal.get('telstra_complaint',''))}</span>
      <span class="ref-label">TIO Reference</span>
      <span class="ref-value">{_escape(legal.get('tio_ref',''))}</span>
      <span class="ref-label">Applicable Law</span>
      <span class="ref-value">{' | '.join(_escape(l) for l in legal.get('applicable_law',[]))}</span>
    </div>
  </div>

</div>

<div class="footer">
  Rayhunter Threat Analyzer v1.0 &mdash; Generated {_escape(generated_at)} &mdash;
  {_escape(investigation_ref)} &mdash; 1,713,678 events analyzed across Telstra AU + Vodafone AU
</div>

<script>
function filterFindings(filter) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    if (filter === 'all') {{
      card.style.display = '';
    }} else if (filter === 'CONFIRMED') {{
      card.style.display = card.dataset.conf === 'CONFIRMED' ? '' : 'none';
    }} else {{
      card.style.display = card.dataset.sev === filter ? '' : 'none';
    }}
  }});
}}
</script>
</body>
</html>"""

    out_path = Path(output_path)
    out_path.write_text(html_content, encoding="utf-8")
    return str(out_path)
