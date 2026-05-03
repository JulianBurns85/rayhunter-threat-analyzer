#!/usr/bin/env python3
"""
html_reporter_v2.py
===================
Rayhunter Threat Analyzer v2.0 - Standalone HTML Report Generator

Generates a professional, self-contained HTML report from the full_report
dict produced by _build_full_report() in main.py.

Designed to be readable by non-technical recipients:
  - ACMA field officers (Brian E / Steve H)
  - TIO case workers
  - Victoria Police
  - Legal counsel

Usage:
    from html_reporter_v2 import generate_v2_html_report
    path = generate_v2_html_report(full_report, output_dir="reports")
"""

import html as html_module
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
SEVERITY_HEX = {
    "CRITICAL": "#C8102E",
    "HIGH":     "#E05C00",
    "MEDIUM":   "#B8860B",
    "LOW":      "#2E75B6",
    "INFO":     "#4A4A4A",
    "CLEAN":    "#1A5C2A",
}

THREAT_GRADIENT = {
    "CRITICAL": "linear-gradient(135deg, #1a0005 0%, #2d0010 50%, #1a0005 100%)",
    "HIGH":     "linear-gradient(135deg, #1a0800 0%, #2d1400 50%, #1a0800 100%)",
    "MEDIUM":   "linear-gradient(135deg, #0d0a00 0%, #1a1500 50%, #0d0a00 100%)",
    "LOW":      "linear-gradient(135deg, #000a1a 0%, #001428 50%, #000a1a 100%)",
    "INFO":     "linear-gradient(135deg, #0a0a0a 0%, #151515 50%, #0a0a0a 100%)",
    "CLEAN":    "linear-gradient(135deg, #001a05 0%, #002d0a 50%, #001a05 100%)",
}


def _e(text) -> str:
    """HTML-escape a value safely."""
    return html_module.escape(str(text)) if text is not None else ""


def _sev_colour(sev: str) -> str:
    return SEVERITY_HEX.get(str(sev).upper(), "#666666")


def _score_colour(score: float) -> str:
    if score >= 9:   return "#C8102E"
    if score >= 7:   return "#E05C00"
    if score >= 5:   return "#B8860B"
    if score >= 3:   return "#2E75B6"
    return "#4A4A4A"


def _css() -> str:
    return """
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

    :root {
        --bg:           #0a0b0d;
        --bg2:          #0f1114;
        --bg3:          #141720;
        --border:       #1e2230;
        --border2:      #2a3048;
        --text:         #c8ccd8;
        --text-dim:     #5a6070;
        --text-bright:  #e8eaf0;
        --accent:       #c8102e;
        --accent2:      #e05c00;
        --mono:         'Share Tech Mono', 'Courier New', monospace;
        --sans:         'Rajdhani', 'Segoe UI', sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        background: var(--bg);
        color: var(--text);
        font-family: var(--sans);
        font-size: 15px;
        line-height: 1.6;
        min-height: 100vh;
    }

    /* ── TOP HEADER ── */
    .site-header {
        background: #050607;
        border-bottom: 1px solid var(--border);
        padding: 0 40px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        height: 56px;
        position: sticky;
        top: 0;
        z-index: 100;
    }
    .site-header .brand {
        font-family: var(--mono);
        font-size: 13px;
        color: var(--text-dim);
        letter-spacing: 0.08em;
    }
    .site-header .brand span { color: var(--accent); }
    .site-header .run-meta {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--text-dim);
        text-align: right;
    }

    /* ── HERO BANNER ── */
    .hero {
        padding: 56px 40px 48px;
        border-bottom: 1px solid var(--border);
        position: relative;
        overflow: hidden;
    }
    .hero::before {
        content: '';
        position: absolute;
        inset: 0;
        background: var(--threat-gradient, var(--bg));
        opacity: 0.85;
        z-index: 0;
    }
    .hero-inner { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; }

    .threat-badge {
        display: inline-block;
        font-family: var(--mono);
        font-size: 11px;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        padding: 4px 12px;
        border: 1px solid currentColor;
        border-radius: 2px;
        margin-bottom: 20px;
    }

    .hero h1 {
        font-family: var(--mono);
        font-size: clamp(28px, 4vw, 48px);
        font-weight: 400;
        letter-spacing: -0.02em;
        color: var(--text-bright);
        line-height: 1.1;
        margin-bottom: 8px;
    }
    .hero h1 .threat-word { font-weight: 700; }

    .hero .subtitle {
        font-size: 14px;
        color: var(--text-dim);
        font-family: var(--mono);
        letter-spacing: 0.05em;
        margin-bottom: 40px;
    }

    /* ── STAT ROW ── */
    .stat-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 16px;
        max-width: 900px;
    }

    .stat-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid var(--border2);
        border-radius: 4px;
        padding: 16px 20px;
        position: relative;
        overflow: hidden;
    }
    .stat-card::after {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: var(--accent-line, var(--accent));
    }
    .stat-card .label {
        font-family: var(--mono);
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--text-dim);
        margin-bottom: 8px;
    }
    .stat-card .value {
        font-family: var(--mono);
        font-size: 26px;
        font-weight: 700;
        color: var(--text-bright);
        line-height: 1;
    }
    .stat-card .unit {
        font-size: 11px;
        color: var(--text-dim);
        margin-top: 4px;
        font-family: var(--mono);
    }

    /* ── MAIN LAYOUT ── */
    .page-body {
        max-width: 1200px;
        margin: 0 auto;
        padding: 40px 40px 80px;
    }

    .section {
        margin-bottom: 48px;
    }
    .section-title {
        font-family: var(--mono);
        font-size: 11px;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: var(--text-dim);
        padding-bottom: 10px;
        border-bottom: 1px solid var(--border);
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .section-title::before {
        content: '';
        width: 3px;
        height: 14px;
        background: var(--accent);
        border-radius: 1px;
        flex-shrink: 0;
    }

    /* ── OPERATOR ASSESSMENT ── */
    .assessment-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 24px;
    }
    @media (max-width: 700px) { .assessment-grid { grid-template-columns: 1fr; } }

    .assessment-card {
        background: var(--bg2);
        border: 1px solid var(--border);
        border-radius: 4px;
        overflow: hidden;
    }
    .assessment-card .card-header {
        background: var(--bg3);
        border-bottom: 1px solid var(--border);
        padding: 12px 20px;
        font-family: var(--mono);
        font-size: 10px;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        color: var(--text-dim);
    }
    .assessment-card .card-body { padding: 20px; }

    .kv-table { width: 100%; border-collapse: collapse; }
    .kv-table tr + tr td { border-top: 1px solid var(--border); }
    .kv-table td { padding: 8px 0; vertical-align: top; }
    .kv-table td:first-child {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--text-dim);
        letter-spacing: 0.06em;
        width: 42%;
        padding-right: 16px;
    }
    .kv-table td:last-child {
        font-family: var(--mono);
        font-size: 13px;
        color: var(--text-bright);
    }

    .danger-meter {
        margin-top: 12px;
    }
    .danger-meter .bar-bg {
        height: 6px;
        background: var(--border2);
        border-radius: 3px;
        overflow: hidden;
        margin-top: 6px;
    }
    .danger-meter .bar-fill {
        height: 100%;
        border-radius: 3px;
        transition: width 1.2s cubic-bezier(.16,1,.3,1);
    }

    .tag {
        display: inline-block;
        font-family: var(--mono);
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 2px;
        border: 1px solid;
        margin: 2px 3px 2px 0;
    }

    /* ── HARDWARE CANDIDATES ── */
    .hw-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 16px;
    }
    .hw-card {
        background: var(--bg2);
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 18px 20px;
        position: relative;
    }
    .hw-card .hw-score {
        position: absolute;
        top: 16px; right: 18px;
        font-family: var(--mono);
        font-size: 22px;
        font-weight: 700;
        opacity: 0.9;
    }
    .hw-card .hw-name {
        font-family: var(--sans);
        font-size: 15px;
        font-weight: 700;
        color: var(--text-bright);
        margin-bottom: 4px;
        padding-right: 50px;
        letter-spacing: 0.02em;
    }
    .hw-card .hw-type {
        font-family: var(--mono);
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--text-dim);
        margin-bottom: 12px;
    }
    .hw-card .hw-desc {
        font-size: 13px;
        color: var(--text-dim);
        line-height: 1.5;
    }

    /* ── FINDINGS ── */
    .finding {
        background: var(--bg2);
        border: 1px solid var(--border);
        border-left: 3px solid var(--sev-colour, #666);
        border-radius: 0 4px 4px 0;
        margin-bottom: 16px;
        overflow: hidden;
    }
    .finding-header {
        display: flex;
        align-items: flex-start;
        gap: 16px;
        padding: 18px 24px;
        cursor: pointer;
        user-select: none;
        transition: background 0.15s;
    }
    .finding-header:hover { background: rgba(255,255,255,0.02); }

    .finding-sev {
        flex-shrink: 0;
        font-family: var(--mono);
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        padding: 3px 8px;
        border: 1px solid currentColor;
        border-radius: 2px;
        margin-top: 2px;
    }
    .finding-meta { flex: 1; min-width: 0; }
    .finding-title {
        font-family: var(--sans);
        font-size: 16px;
        font-weight: 600;
        color: var(--text-bright);
        letter-spacing: 0.02em;
        margin-bottom: 4px;
    }
    .finding-technique {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--text-dim);
        letter-spacing: 0.06em;
    }
    .finding-toggle {
        flex-shrink: 0;
        font-family: var(--mono);
        font-size: 16px;
        color: var(--text-dim);
        transition: transform 0.2s;
        margin-top: 2px;
    }
    .finding.open .finding-toggle { transform: rotate(180deg); }

    .finding-body {
        display: none;
        padding: 0 24px 20px;
        border-top: 1px solid var(--border);
    }
    .finding.open .finding-body { display: block; }

    .finding-desc {
        font-size: 14px;
        color: var(--text);
        line-height: 1.65;
        margin: 16px 0 20px;
    }

    .evidence-block {
        background: #060809;
        border: 1px solid var(--border);
        border-radius: 3px;
        padding: 14px 16px;
        margin-bottom: 16px;
    }
    .evidence-block .ev-label {
        font-family: var(--mono);
        font-size: 10px;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        color: var(--text-dim);
        margin-bottom: 10px;
    }
    .evidence-item {
        font-family: var(--mono);
        font-size: 12px;
        color: #8fa0b8;
        padding: 3px 0;
        border-bottom: 1px solid #111318;
        word-break: break-all;
    }
    .evidence-item:last-child { border-bottom: none; }
    .evidence-item .ts { color: var(--text-dim); }
    .evidence-item .ev-type { color: #e08040; }

    .action-block {
        background: rgba(200,16,46,0.05);
        border: 1px solid rgba(200,16,46,0.2);
        border-radius: 3px;
        padding: 14px 16px;
    }
    .action-block .ac-label {
        font-family: var(--mono);
        font-size: 10px;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        color: #c8102e;
        margin-bottom: 8px;
    }
    .action-block .ac-text {
        font-size: 13px;
        color: var(--text);
        line-height: 1.6;
        font-family: var(--mono);
        white-space: pre-wrap;
    }

    /* ── CELL ID TABLE ── */
    .cell-table {
        width: 100%;
        border-collapse: collapse;
        font-family: var(--mono);
        font-size: 13px;
    }
    .cell-table th {
        background: var(--bg3);
        border-bottom: 1px solid var(--border2);
        padding: 10px 14px;
        text-align: left;
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--text-dim);
        font-weight: 600;
    }
    .cell-table td {
        padding: 9px 14px;
        border-bottom: 1px solid var(--border);
        color: var(--text);
        vertical-align: middle;
    }
    .cell-table tr:hover td { background: rgba(255,255,255,0.015); }
    .cell-table .rogue-flag {
        display: inline-block;
        background: rgba(200,16,46,0.15);
        color: #c8102e;
        border: 1px solid rgba(200,16,46,0.4);
        border-radius: 2px;
        padding: 1px 6px;
        font-size: 10px;
        letter-spacing: 0.08em;
        margin-left: 8px;
    }
    .obs-bar-wrap { width: 100px; }
    .obs-bar-bg {
        height: 4px;
        background: var(--border2);
        border-radius: 2px;
        overflow: hidden;
    }
    .obs-bar-fill {
        height: 100%;
        background: #2E75B6;
        border-radius: 2px;
    }

    /* ── CITATION REGISTRY ── */
    .cite-list { list-style: none; }
    .cite-item {
        display: flex;
        gap: 16px;
        padding: 10px 0;
        border-bottom: 1px solid var(--border);
        font-size: 13px;
    }
    .cite-item:last-child { border-bottom: none; }
    .cite-num {
        font-family: var(--mono);
        color: var(--text-dim);
        flex-shrink: 0;
        min-width: 28px;
        padding-top: 1px;
    }
    .cite-body { flex: 1; }
    .cite-title { color: var(--text-bright); margin-bottom: 2px; }
    .cite-url { font-family: var(--mono); font-size: 11px; color: #4a6888; word-break: break-all; }

    /* ── FOOTER ── */
    .footer {
        background: #050607;
        border-top: 1px solid var(--border);
        padding: 24px 40px;
        font-family: var(--mono);
        font-size: 11px;
        color: var(--text-dim);
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 16px;
        flex-wrap: wrap;
    }
    .footer .hash { word-break: break-all; }

    /* ── IMSI RATIO BAR ── */
    .ratio-track {
        position: relative;
        height: 28px;
        background: var(--bg3);
        border: 1px solid var(--border);
        border-radius: 3px;
        overflow: hidden;
        margin-top: 12px;
    }
    .ratio-fill {
        height: 100%;
        background: linear-gradient(90deg, #c8102e, #e05c00);
        transition: width 1.5s cubic-bezier(.16,1,.3,1);
    }
    .ratio-markers {
        position: absolute;
        inset: 0;
        display: flex;
        align-items: center;
    }
    .ratio-marker {
        position: absolute;
        top: 0; bottom: 0;
        width: 1px;
        background: rgba(255,255,255,0.15);
    }
    .ratio-label {
        position: absolute;
        top: 50%;
        transform: translateY(-50%);
        font-family: var(--mono);
        font-size: 10px;
        color: rgba(255,255,255,0.5);
        padding: 0 6px;
        pointer-events: none;
        white-space: nowrap;
    }
    .ratio-value {
        position: absolute;
        right: 10px; top: 50%;
        transform: translateY(-50%);
        font-family: var(--mono);
        font-size: 13px;
        font-weight: 700;
        color: white;
    }
    """


def _js() -> str:
    return """
    document.querySelectorAll('.finding-header').forEach(function(header) {
        header.addEventListener('click', function() {
            var finding = this.closest('.finding');
            finding.classList.toggle('open');
        });
    });

    // Animate bars on load
    window.addEventListener('load', function() {
        document.querySelectorAll('[data-width]').forEach(function(el) {
            setTimeout(function() {
                el.style.width = el.getAttribute('data-width');
            }, 300);
        });
    });
    """


def _hw_tier_colour(tier: str) -> str:
    t = str(tier).upper()
    if "COMMERCIAL" in t:  return "#E05C00"
    if "STATE" in t:       return "#C8102E"
    if "AMATEUR" in t:     return "#2E75B6"
    return "#666666"


def _render_hero(report: dict, intel: dict) -> str:
    threat = report.get("threat_level", "UNKNOWN")
    gradient = THREAT_GRADIENT.get(threat.upper(), THREAT_GRADIENT["INFO"])
    colour = _sev_colour(threat)
    danger = intel.get("danger_score", 0.0)
    score_colour = _score_colour(danger)
    findings = report.get("findings_count", 0)
    confirmed = report.get("confirmed_attacks", 0)
    events = report.get("events_analyzed", 0)
    elapsed = report.get("analysis_time_seconds", 0)
    imsi_ratio = intel.get("imsi_exposure_ratio", 0.0)
    imsi_label = intel.get("imsi_exposure_ratio_label", "")
    db = report.get("db_stats", {})

    ratio_pct = min(float(imsi_ratio) * 100, 100) if imsi_ratio else 0.0
    tucker_pct = 28.6
    commercial_pct = 3.0

    return f"""
    <div class="hero" style="--threat-gradient: {gradient};">
      <div class="hero-inner">
        <div class="threat-badge" style="color:{colour}; border-color:{colour};">
          THREAT LEVEL: {_e(threat)}
        </div>
        <h1>Rayhunter Threat Analyzer
          <span class="threat-word" style="color:{colour};">{_e(threat)}</span>
        </h1>
        <p class="subtitle">Cellular Surveillance Detection &mdash; Cranbourne East VIC &mdash; ACMA ENQ-1851DVJH04</p>

        <div class="stat-row">
          <div class="stat-card" style="--accent-line:{score_colour};">
            <div class="label">Danger Score</div>
            <div class="value" style="color:{score_colour};">{danger:.1f}</div>
            <div class="unit">/ 10.0</div>
          </div>
          <div class="stat-card" style="--accent-line:{colour};">
            <div class="label">Confirmed Attacks</div>
            <div class="value" style="color:{colour};">{confirmed}</div>
            <div class="unit">of {findings} findings</div>
          </div>
          <div class="stat-card" style="--accent-line:#C8102E;">
            <div class="label">IMSI Exposure Ratio</div>
            <div class="value" style="color:#C8102E;">{ratio_pct:.1f}<span style="font-size:16px;">%</span></div>
            <div class="unit">{_e(imsi_label)}</div>
          </div>
          <div class="stat-card">
            <div class="label">Events Analyzed</div>
            <div class="value">{int(events):,}</div>
            <div class="unit">in {elapsed:.0f}s</div>
          </div>
          <div class="stat-card">
            <div class="label">Intelligence DB</div>
            <div class="value">{db.get("attacks_loaded", 0)}</div>
            <div class="unit">attacks &middot; {db.get("devices_loaded", 0)} devices</div>
          </div>
        </div>
      </div>
    </div>
    """


def _render_operator_assessment(intel: dict) -> str:
    if not intel:
        return ""

    danger = float(intel.get("danger_score", 0.0))
    score_colour = _score_colour(danger)
    bar_pct = min(danger * 10, 100)
    devices = intel.get("likely_devices", [])
    imsi_ratio = intel.get("imsi_exposure_ratio", 0.0)
    ratio_pct = min(float(imsi_ratio) * 100, 100) if imsi_ratio else 0.0
    tucker_pct = 28.6
    commercial_pct = 3.0

    devices_html = "".join(
        f'<span class="tag" style="color:#E05C00;border-color:rgba(224,92,0,0.4);">{_e(d)}</span>'
        for d in (devices or [])[:4]
    )

    ratio_colour = "#C8102E" if ratio_pct > tucker_pct else ("#E05C00" if ratio_pct > 10 else "#2E75B6")

    return f"""
    <div class="section">
      <div class="section-title">Operator Assessment &mdash; IntelligenceDB v2.0</div>
      <div class="assessment-grid">

        <div class="assessment-card">
          <div class="card-header">Attribution</div>
          <div class="card-body">
            <table class="kv-table">
              <tr><td>Matched Profile</td><td>{_e(intel.get("matched_profile") or "No direct match")}</td></tr>
              <tr><td>Likely Actor</td><td>{_e(intel.get("likely_actor", "—"))}</td></tr>
              <tr><td>Skill Level</td><td>{_e(intel.get("skill_level", "—"))}</td></tr>
              <tr><td>Sophistication</td><td>{_e(intel.get("sophistication_level", "—"))}</td></tr>
              <tr><td>Automation</td><td>{_e(intel.get("automation_level", "—"))}</td></tr>
              <tr><td>Persistence</td><td>{_e(intel.get("persistence_level", "—"))}</td></tr>
              <tr><td>Confidence</td><td>{_e(intel.get("confidence", "—"))}</td></tr>
            </table>
          </div>
        </div>

        <div class="assessment-card">
          <div class="card-header">Risk Metrics</div>
          <div class="card-body">
            <table class="kv-table">
              <tr>
                <td>Danger Score</td>
                <td>
                  <span style="font-size:20px;font-weight:700;color:{score_colour};">{danger:.1f}/10</span>
                  <div class="danger-meter">
                    <div class="bar-bg">
                      <div class="bar-fill" style="width:0%;background:{score_colour};"
                           data-width="{bar_pct:.0f}%"></div>
                    </div>
                  </div>
                </td>
              </tr>
              <tr>
                <td>Evidence Items</td>
                <td>{intel.get("evidence_count", intel.get("citations_count", "—"))}</td>
              </tr>
              <tr>
                <td>IMSI Exp. Ratio</td>
                <td>
                  <span style="color:{ratio_colour};font-weight:700;">{ratio_pct:.1f}%</span>
                  <div style="margin-top:6px;">
                    <div style="font-size:10px;font-family:var(--mono);color:var(--text-dim);margin-bottom:6px;">
                      vs. Tucker et al. 2025 baselines:
                    </div>
                    <div class="ratio-track">
                      <div class="ratio-fill" style="width:0%;" data-width="{ratio_pct:.1f}%"></div>
                      <div class="ratio-marker" style="left:{commercial_pct:.1f}%;"></div>
                      <div class="ratio-label" style="left:{commercial_pct:.1f}%;">3% commercial</div>
                      <div class="ratio-marker" style="left:{tucker_pct:.1f}%;"></div>
                      <div class="ratio-label" style="left:{tucker_pct:.1f}%;">28.6% court CSS</div>
                      <div class="ratio-value">{ratio_pct:.1f}%</div>
                    </div>
                  </div>
                </td>
              </tr>
            </table>
          </div>
        </div>

        <div class="assessment-card" style="grid-column: 1 / -1;">
          <div class="card-header">Likely Hardware</div>
          <div class="card-body">
            {devices_html if devices_html else '<span style="color:var(--text-dim);font-size:13px;">No hardware candidates identified</span>'}
          </div>
        </div>

      </div>
    </div>
    """


def _render_hardware_candidates(hardware: list) -> str:
    if not hardware:
        return ""

    cards = ""
    for hw in hardware[:8]:
        name = hw.get("name", "Unknown")
        score = hw.get("score", 0)
        tier = hw.get("tier", "")
        desc = hw.get("description", "")
        score_colour = _score_colour(score / 2)  # scores are 0-20 range
        tier_colour = _hw_tier_colour(tier)
        tier_label = str(tier).replace("_", " ")

        cards += f"""
        <div class="hw-card">
          <div class="hw-score" style="color:{score_colour};">{score}</div>
          <div class="hw-name">{_e(name)}</div>
          <div class="hw-type">
            <span class="tag" style="color:{tier_colour};border-color:{tier_colour}40;">{_e(tier_label)}</span>
          </div>
          <div class="hw-desc">{_e(desc[:180])}{"..." if len(str(desc)) > 180 else ""}</div>
        </div>
        """

    return f"""
    <div class="section">
      <div class="section-title">Hardware Candidates</div>
      <div class="hw-grid">{cards}</div>
    </div>
    """


def _render_findings(findings: list) -> str:
    if not findings:
        return ""

    items = ""
    for i, f in enumerate(findings):
        sev = f.get("severity", "INFO")
        confirmed = f.get("confirmed", False)
        title = f.get("title", "Unknown Finding")
        desc = f.get("description", "")
        technique = f.get("technique", "")
        spec = f.get("spec_reference", "")
        evidence = f.get("evidence", [])
        action = f.get("action", "")
        colour = _sev_colour(sev)

        conf_badge = ""
        if confirmed:
            conf_badge = f' <span class="tag" style="color:#1A5C2A;border-color:#1A5C2A;">&#10003; CONFIRMED</span>'

        ev_items = ""
        for ev in evidence[:8]:
            ts = _e(ev.get("timestamp", ""))
            msg = _e(ev.get("message", str(ev)))
            ev_items += f'<div class="evidence-item"><span class="ts">[{ts}]</span> {msg}</div>'

        action_html = ""
        if action:
            action_html = f"""
            <div class="action-block">
              <div class="ac-label">&#9654; Recommended Action</div>
              <div class="ac-text">{_e(action)}</div>
            </div>"""

        spec_html = f'<div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-top:6px;">Spec: {_e(spec)}</div>' if spec else ""

        items += f"""
        <div class="finding" style="--sev-colour:{colour};">
          <div class="finding-header">
            <div class="finding-sev" style="color:{colour};">{_e(sev)}</div>
            <div class="finding-meta">
              <div class="finding-title">[{i+1}] {_e(title)}{conf_badge}</div>
              <div class="finding-technique">{_e(technique)}</div>
            </div>
            <div class="finding-toggle">&#8964;</div>
          </div>
          <div class="finding-body">
            <p class="finding-desc">{_e(desc)}</p>
            {spec_html}
            {"<div class='evidence-block'><div class='ev-label'>Evidence</div>" + ev_items + "</div>" if ev_items else ""}
            {action_html}
          </div>
        </div>
        """

    return f"""
    <div class="section">
      <div class="section-title">Detailed Findings</div>
      {items}
    </div>
    """


def _render_cell_table(findings: list) -> str:
    # Find the cell summary finding
    cell_finding = None
    for f in findings:
        if "Cell ID" in f.get("title", "") or "cell_ids" in f:
            cell_finding = f
            break
        if "cells" in f:
            cell_finding = f
            break

    cells = []
    if cell_finding:
        for ev in cell_finding.get("evidence", []):
            msg = str(ev.get("message", ""))
            if "CID=" in msg:
                cells.append(msg)

    if not cells:
        return ""

    KNOWN_ROGUE = {
        "137713195", "137713175", "137713155", "8409387", "8409357"
    }
    max_obs = 1

    parsed = []
    for line in cells:
        parts = {}
        for token in line.split():
            if "=" in token:
                k, v = token.split("=", 1)
                parts[k] = v
        if "CID" in parts:
            obs = int(parts.get("observations", 0))
            max_obs = max(max_obs, obs)
            parsed.append(parts)

    rows = ""
    for p in sorted(parsed, key=lambda x: int(x.get("observations", 0)), reverse=True):
        cid = p.get("CID", "")
        tac = p.get("TAC", "")
        mcc = p.get("MCC", "")
        mnc = p.get("MNC", "")
        obs = int(p.get("observations", 0))
        bar_w = int(obs / max_obs * 100)
        rogue_flag = f'<span class="rogue-flag">ROGUE</span>' if cid in KNOWN_ROGUE else ""

        rows += f"""
        <tr>
          <td><code>{_e(cid)}</code>{rogue_flag}</td>
          <td><code>{_e(tac)}</code></td>
          <td>{_e(mcc)}/{_e(mnc)}</td>
          <td>
            <div class="obs-bar-wrap">
              <div style="font-family:var(--mono);font-size:12px;margin-bottom:4px;">{obs:,}</div>
              <div class="obs-bar-bg">
                <div class="obs-bar-fill" style="width:0%;" data-width="{bar_w}%"></div>
              </div>
            </div>
          </td>
        </tr>"""

    if not rows:
        return ""

    return f"""
    <div class="section">
      <div class="section-title">Cell ID Inventory &mdash; {len(parsed)} Unique Cells</div>
      <div style="overflow-x:auto;">
        <table class="cell-table">
          <thead>
            <tr>
              <th>Cell ID</th><th>TAC</th><th>MCC/MNC</th><th>Observations</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """


def _render_citations(citations: list) -> str:
    if not citations:
        return ""

    items = ""
    for i, cite in enumerate(citations, 1):
        if isinstance(cite, dict):
            title = cite.get("title", str(cite))
            url = cite.get("url", "")
        else:
            title = str(cite)
            url = ""

        url_html = f'<div class="cite-url">{_e(url)}</div>' if url else ""
        items += f"""
        <li class="cite-item">
          <div class="cite-num">[{i}]</div>
          <div class="cite-body">
            <div class="cite-title">{_e(title)}</div>
            {url_html}
          </div>
        </li>"""

    return f"""
    <div class="section">
      <div class="section-title">Forensic Citation Registry</div>
      <ul class="cite-list">{items}</ul>
    </div>
    """


def generate_v2_html_report(
    full_report: Dict[str, Any],
    output_dir: str = "reports",
    filename: Optional[str] = None,
) -> Path:
    """
    Generate a standalone v2.0 HTML report from the full_report dict
    produced by _build_full_report() in main.py.

    Returns the Path to the generated file.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not filename:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        filename = f"rayhunter_report_{ts}.html"

    out_path = out_dir / filename

    intel = full_report.get("intelligence_v2", {}) or {}
    findings = full_report.get("findings", []) or []
    hardware = full_report.get("hardware_candidates", []) or []
    citations = full_report.get("citations", []) or []
    generated = full_report.get("generated", datetime.now(timezone.utc).isoformat())
    threat = full_report.get("threat_level", "UNKNOWN")
    threat_colour = _sev_colour(threat)

    # Build HTML
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rayhunter Threat Report &mdash; {_e(threat)}</title>
<style>{_css()}</style>
</head>
<body>

<header class="site-header">
  <div class="brand">
    <span>&#9670;</span> RAYHUNTER THREAT ANALYZER v2.0
  </div>
  <div class="run-meta">
    Generated: {_e(generated[:19].replace("T", " "))} UTC<br>
    ACMA ENQ-1851DVJH04
  </div>
</header>

{_render_hero(full_report, intel)}

<div class="page-body">
  {_render_operator_assessment(intel)}
  {_render_hardware_candidates(hardware)}
  {_render_findings(findings)}
  {_render_cell_table(findings)}
  {_render_citations(citations)}
</div>

<footer class="footer">
  <div>Rayhunter Threat Analyzer v2.0 &mdash; Cranbourne East VIC &mdash; Julian Burns</div>
  <div class="hash">Report: {_e(filename)}</div>
</footer>

<script>{_js()}</script>
</body>
</html>"""

    out_path.write_text(doc, encoding="utf-8")
    return out_path
