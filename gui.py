#!/usr/bin/env python3
"""
Rayhunter Threat Analyzer — PyQt6 GUI
======================================
Launch from the analyzer root directory:

    python gui.py
    python gui.py --config my_config.yaml

Requires:
    pip install PyQt6
    (all other deps same as main.py)
"""

import sys
import os
import json
import time
import traceback
import argparse
from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout
from typing import Optional

# ── PyQt6 imports ────────────────────────────────────────────────────────────
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QPushButton, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QTextEdit, QFileDialog, QFrame, QGroupBox, QGridLayout,
    QMessageBox, QStatusBar, QProgressBar, QSizePolicy, QScrollArea,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QSize, QTimer
from PyQt6.QtGui import QFont, QColor, QAction, QTextCursor, QPalette

# ── Analyzer imports (graceful fallback if running outside repo) ──────────────
try:
    import config_loader
    from main import collect_files, run_analysis, _build_full_report
    try:
        from html_reporter_v2 import generate_v2_html_report as _gen_html
        _HTML_AVAILABLE = True
    except ImportError:
        _HTML_AVAILABLE = False
    from reporter import ThreatReporter
    _ANALYZER_AVAILABLE = True
except ImportError as _import_err:
    _ANALYZER_AVAILABLE = False
    _IMPORT_ERROR = str(_import_err)


# =============================================================================
# COLOUR PALETTE
# =============================================================================

class C:
    BG          = "#0d0d1a"
    PANEL       = "#12122a"
    PANEL_ALT   = "#1a1a35"
    BORDER      = "#2a2a55"
    ACCENT      = "#3a3a80"
    ACCENT_HOVER= "#5050aa"
    TEXT        = "#d8d8f0"
    TEXT_DIM    = "#7070a0"
    TEXT_BRIGHT = "#ffffff"

    CRITICAL    = "#ff3333"
    HIGH        = "#ff8800"
    MEDIUM      = "#ffd700"
    LOW         = "#44cc44"
    MINIMAL     = "#4488ff"
    UNKNOWN     = "#888888"

    FINDING_CRIT= "#3a0a0a"
    FINDING_HIGH= "#2a1800"
    FINDING_MED = "#2a2000"
    FINDING_LOW = "#0a2a0a"

    BTN_PRIMARY = "#1e3a8a"
    BTN_SCAN    = "#7c2020"
    BTN_SCAN_H  = "#aa3030"
    BTN_EXPORT  = "#1a4a1a"
    BTN_EXPORT_H= "#2a6a2a"
    BTN_STOP    = "#555580"

DANGER_COLOUR = {
    "CRITICAL": C.CRITICAL,
    "HIGH":     C.HIGH,
    "MEDIUM":   C.MEDIUM,
    "LOW":      C.LOW,
    "MINIMAL":  C.MINIMAL,
}


# =============================================================================
# STYLESHEET
# =============================================================================

QSS = f"""
QMainWindow, QWidget {{
    background-color: {C.BG};
    color: {C.TEXT};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}}
QSplitter::handle {{
    background: {C.BORDER};
    width: 2px;
    height: 2px;
}}
QGroupBox {{
    border: 1px solid {C.BORDER};
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 6px;
    font-weight: bold;
    color: {C.TEXT_DIM};
    font-size: 11px;
    letter-spacing: 1px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
}}
QLineEdit {{
    background: {C.PANEL};
    border: 1px solid {C.BORDER};
    border-radius: 3px;
    color: {C.TEXT};
    padding: 4px 6px;
}}
QLineEdit:focus {{
    border: 1px solid {C.ACCENT_HOVER};
}}
QTextEdit {{
    background: {C.PANEL};
    border: 1px solid {C.BORDER};
    border-radius: 3px;
    color: {C.TEXT};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    selection-background-color: {C.ACCENT};
}}
QListWidget {{
    background: {C.PANEL};
    border: 1px solid {C.BORDER};
    border-radius: 3px;
    color: {C.TEXT};
    outline: none;
}}
QListWidget::item {{
    padding: 5px 8px;
    border-bottom: 1px solid {C.PANEL_ALT};
}}
QListWidget::item:selected {{
    background: {C.ACCENT};
    color: {C.TEXT_BRIGHT};
}}
QListWidget::item:hover {{
    background: {C.PANEL_ALT};
}}
QPushButton {{
    background: {C.ACCENT};
    border: none;
    border-radius: 3px;
    color: {C.TEXT_BRIGHT};
    padding: 5px 14px;
    font-weight: bold;
    font-size: 11px;
}}
QPushButton:hover {{
    background: {C.ACCENT_HOVER};
}}
QPushButton:disabled {{
    background: #2a2a40;
    color: {C.TEXT_DIM};
}}
QPushButton#scan_btn {{
    background: {C.BTN_SCAN};
    font-size: 13px;
    padding: 7px 22px;
    letter-spacing: 1px;
}}
QPushButton#scan_btn:hover {{
    background: {C.BTN_SCAN_H};
}}
QPushButton#scan_btn:disabled {{
    background: #3a2020;
    color: #884444;
}}
QPushButton#export_btn {{
    background: {C.BTN_EXPORT};
}}
QPushButton#export_btn:hover {{
    background: {C.BTN_EXPORT_H};
}}
QPushButton#stop_btn {{
    background: {C.BTN_STOP};
}}
QStatusBar {{
    background: {C.PANEL};
    color: {C.TEXT_DIM};
    border-top: 1px solid {C.BORDER};
    font-size: 11px;
}}
QProgressBar {{
    background: {C.PANEL};
    border: 1px solid {C.BORDER};
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {C.CRITICAL};
    border-radius: 3px;
}}
QScrollBar:vertical {{
    background: {C.PANEL};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {C.BORDER};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QMenuBar {{
    background: {C.PANEL};
    color: {C.TEXT};
    border-bottom: 1px solid {C.BORDER};
}}
QMenuBar::item:selected {{
    background: {C.ACCENT};
}}
QMenu {{
    background: {C.PANEL_ALT};
    border: 1px solid {C.BORDER};
    color: {C.TEXT};
}}
QMenu::item:selected {{
    background: {C.ACCENT};
}}
QLabel#danger_score {{
    font-size: 52px;
    font-weight: bold;
    font-family: 'Consolas', monospace;
}}
QLabel#danger_rating {{
    font-size: 16px;
    font-weight: bold;
    letter-spacing: 3px;
}}
QLabel#section_header {{
    color: {C.TEXT_DIM};
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: bold;
}}
"""


# =============================================================================
# STDOUT CAPTURE — feeds live output to the log panel
# =============================================================================

class LogEmitter(QObject):
    line_ready = pyqtSignal(str)

    def write(self, text):
        if text.strip():
            self.line_ready.emit(text.rstrip())

    def flush(self):
        pass


# =============================================================================
# ANALYSIS WORKER — runs in QThread so UI stays responsive
# =============================================================================

class AnalysisWorker(QObject):
    log         = pyqtSignal(str)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)
    progress    = pyqtSignal(int)   # 0-100

    def __init__(self, files: dict, cfg: dict, verbose: bool):
        super().__init__()
        self._files   = files
        self._cfg     = cfg
        self._verbose = verbose
        self._abort   = False

    def abort(self):
        self._abort = True

    def run(self):
        emitter = LogEmitter()
        emitter.line_ready.connect(self.log)

        old_stdout = sys.stdout
        sys.stdout = emitter

        try:
            self.log.emit("─" * 60)
            self.log.emit("  RAYHUNTER THREAT ANALYZER  v2.0")
            self.log.emit("─" * 60)

            total = sum(len(v) for v in self._files.values())
            self.log.emit(f"[+] Files queued: {total}  "
                          f"({len(self._files['ndjson'])} NDJSON · "
                          f"{len(self._files['pcap'])} PCAP · "
                          f"{len(self._files['qmdl'])} QMDL)")
            self.progress.emit(10)

            if not _ANALYZER_AVAILABLE:
                raise RuntimeError(
                    f"Analyzer modules not importable:\n{_IMPORT_ERROR}\n\n"
                    "Run gui.py from the rayhunter-threat-analyzer root directory."
                )

            t0 = time.time()
            results = run_analysis(self._files, self._cfg, verbose=self._verbose)
            elapsed = time.time() - t0
            self.progress.emit(80)

            reporter = ThreatReporter(self._cfg)
            report   = reporter.build_report(results, elapsed=elapsed)
            # v2.0 -- wire in intelligence layer
            # _build_full_report_called
            try:
                full_report = _build_full_report(report, results)
                self._full_report = full_report
            except Exception:
                full_report = report
                self._full_report = report
            self.progress.emit(95)

            self.log.emit(f"\n[✓] Analysis complete in {elapsed:.2f}s")
            n_findings = len(results.get("findings", []))
            self.log.emit(f"[✓] {n_findings} finding(s) detected")

            fp = results.get("fingerprinter")
            if fp and fp.attacker_assessment:
                a = fp.attacker_assessment
                self.log.emit(f"[✓] Profile: {a.matched_profile.name if a.matched_profile else 'No match'}")
                self.log.emit(f"[✓] Danger:  {a.danger_score}/10  —  {a.danger_rating}")

            self.progress.emit(100)
            self.finished.emit({"results": results, "report": report, "elapsed": elapsed})

        except Exception as exc:
            self.error.emit(f"[ERROR] {exc}\n\n{traceback.format_exc()}")
        finally:
            sys.stdout = old_stdout


# =============================================================================
# THREAT ASSESSMENT CARD
# =============================================================================

class ThreatCard(QFrame):
    """Displays the danger score, profile match, and key operator attributes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(f"background: {C.PANEL_ALT}; border: 1px solid {C.BORDER}; border-radius: 4px;")
        self._build()
        self.clear()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 14, 14)
        outer.setSpacing(6)

        # Header
        hdr = QLabel("OPERATOR ASSESSMENT")
        hdr.setObjectName("section_header")
        outer.addWidget(hdr)

        # Score row
        score_row = QHBoxLayout()
        score_row.setSpacing(12)
        self._score_lbl = QLabel("—")
        self._score_lbl.setObjectName("danger_score")
        self._score_lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        score_row.addWidget(self._score_lbl)

        right_col = QVBoxLayout()
        right_col.setSpacing(2)
        self._rating_lbl = QLabel("NO DATA")
        self._rating_lbl.setObjectName("danger_rating")
        right_col.addWidget(self._rating_lbl)
        self._profile_lbl = QLabel("—")
        self._profile_lbl.setWordWrap(True)
        self._profile_lbl.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 11px;")
        right_col.addWidget(self._profile_lbl)
        score_row.addLayout(right_col)
        outer.addLayout(score_row)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color: {C.BORDER};")
        outer.addWidget(div)

        # Attributes grid
        self._grid = QGridLayout()
        self._grid.setSpacing(4)
        self._grid.setColumnMinimumWidth(0, 110)
        outer.addLayout(self._grid)
        self._rows = {}
        for i, key in enumerate([
            "Confidence", "Skill Level", "Automation",
            "Sophistication", "Persistence",
            "Likely Actor", "Hardware",
            "IMSI Exposure",
        ]):
            lbl_key = QLabel(key)
            lbl_key.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 11px;")
            lbl_val = QLabel("—")
            lbl_val.setWordWrap(True)
            lbl_val.setStyleSheet(f"color: {C.TEXT}; font-size: 11px;")
            self._grid.addWidget(lbl_key, i, 0, Qt.AlignmentFlag.AlignTop)
            self._grid.addWidget(lbl_val, i, 1, Qt.AlignmentFlag.AlignTop)
            self._rows[key] = lbl_val

    def clear(self):
        self._score_lbl.setText("—")
        self._score_lbl.setStyleSheet(f"font-size: 52px; font-weight: bold; color: {C.TEXT_DIM};")
        self._rating_lbl.setText("NO DATA")
        self._rating_lbl.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {C.TEXT_DIM};")
        self._profile_lbl.setText("Run a scan to populate this panel")
        for v in self._rows.values():
            v.setText("—")
            v.setStyleSheet(f"color: {C.TEXT}; font-size: 11px;")

    def populate(self, fingerprinter):
        a = fingerprinter.attacker_assessment
        if not a:
            self.clear()
            return

        score = a.danger_score
        rating = getattr(a, "danger_rating", "UNKNOWN")
        colour = DANGER_COLOUR.get(rating, C.UNKNOWN)

        self._score_lbl.setText(f"{score:.1f}")
        self._score_lbl.setStyleSheet(
            f"font-size: 52px; font-weight: bold; color: {colour}; font-family: Consolas;"
        )
        self._rating_lbl.setText(rating)
        self._rating_lbl.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {colour}; letter-spacing: 3px;"
        )
        profile_name = a.matched_profile.name if a.matched_profile else "No direct match"
        self._profile_lbl.setText(profile_name)

        def _set(key, val, colour=C.TEXT):
            lbl = self._rows.get(key)
            if lbl:
                lbl.setText(str(val) if val else "—")
                lbl.setStyleSheet(f"color: {colour}; font-size: 11px;")

        _set("Confidence",     getattr(a, "confidence", "—"))
        _set("Skill Level",    getattr(a, "skill_level", "—"))
        _set("Automation",     getattr(a, "automation_level", "—"))
        _set("Sophistication", getattr(a, "sophistication_level", "—"))
        _set("Persistence",    getattr(a, "persistence_level", "—"))
        _set("Likely Actor",   getattr(a, "likely_actor", "—"))

        devs = getattr(a, "likely_devices", [])
        _set("Hardware", ", ".join(devs[:3]) if devs else "—")

        ratio = getattr(fingerprinter, "get_imsi_exposure_ratio_label", lambda: None)()
        _set("IMSI Exposure", ratio or "—",
             colour=C.CRITICAL if ratio and "HIGH" in str(ratio).upper() else C.TEXT)


# =============================================================================
# FINDING DETAIL PANEL
# =============================================================================

class FindingDetail(QTextEdit):
    """Read-only panel that shows enriched details for a selected finding."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setPlaceholderText("Select a finding from the list to see detail…")

    def show_finding(self, enriched_finding: dict):
        """Render an enriched finding dict as formatted text."""
        ef = enriched_finding
        lines = []
        title = ef.get("finding_title", "Unknown Finding")
        lines.append(f"{'─'*50}")
        lines.append(f"  {title.upper()}")
        lines.append(f"{'─'*50}")

        card = ef.get("rating_card", {})
        if card:
            lines.append(f"\n  Severity    : {card.get('severity', '—')}")
            lines.append(f"  Confidence  : {card.get('confidence', '—')}")
            lines.append(f"  Attack IDs  : {', '.join(ef.get('matched_attack_ids', [])) or '—'}")
            lines.append(f"  Top Device  : {ef.get('top_device', '—')}")

        cites = ef.get("citations", [])
        if cites:
            lines.append(f"\n  CITATIONS ({len(cites)}):")
            for c in cites[:5]:
                lines.append(f"    • {c}")

        desc = card.get("description", "")
        if desc:
            lines.append(f"\n  DESCRIPTION:")
            for chunk in [desc[i:i+70] for i in range(0, len(desc), 70)]:
                lines.append(f"    {chunk}")

        self.setPlainText("\n".join(lines))

    def show_raw(self, finding: dict):
        """Fall back to showing raw finding dict when no enriched form available."""
        lines = [f"{'─'*50}"]
        for k, v in finding.items():
            lines.append(f"  {k:<18}: {v}")
        self.setPlainText("\n".join(lines))


# =============================================================================
# MAIN WINDOW
# =============================================================================

class MainWindow(QMainWindow):

    def __init__(self, cfg: dict):
        super().__init__()
        self._cfg             = cfg
        self._worker          = None
        self._thread          = None
        self._results         = None
        self._enriched        = []
        self._full_report     = {}   # v2.0 full intelligence report
        self._raw_findings    = []
        self._selected_files  = []
        self._selected_dir    = None

        self.setWindowTitle("Rayhunter Threat Analyzer  v2.0")
        self.resize(1280, 820)
        self.setMinimumSize(900, 600)

        self._build_menu()
        self._build_ui()
        self._build_status()

        if not _ANALYZER_AVAILABLE:
            self._log(f"⚠  Analyzer modules not found: {_IMPORT_ERROR}")
            self._log("   Run gui.py from the rayhunter-threat-analyzer root directory.")

    # ─────────────────────────────────────────────────────────────────────────
    # MENU BAR
    # ─────────────────────────────────────────────────────────────────────────

    def _build_menu(self):
        mb = self.menuBar()

        # File
        fm = mb.addMenu("File")
        act_files = QAction("Add Files…", self)
        act_files.setShortcut("Ctrl+O")
        act_files.triggered.connect(self._browse_files)
        fm.addAction(act_files)

        act_dir = QAction("Set Directory…", self)
        act_dir.setShortcut("Ctrl+D")
        act_dir.triggered.connect(self._browse_dir)
        fm.addAction(act_dir)

        fm.addSeparator()
        act_clear = QAction("Clear Selection", self)
        act_clear.triggered.connect(self._clear_selection)
        fm.addAction(act_clear)

        fm.addSeparator()
        act_quit = QAction("Exit", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        fm.addAction(act_quit)

        # Analysis
        am = mb.addMenu("Analysis")
        act_scan = QAction("Run Scan", self)
        act_scan.setShortcut("Ctrl+R")
        act_scan.triggered.connect(self._start_scan)
        am.addAction(act_scan)

        act_stop = QAction("Stop Scan", self)
        act_stop.triggered.connect(self._stop_scan)
        am.addAction(act_stop)

        am.addSeparator()
        act_verbose = QAction("Verbose Output", self, checkable=True)
        act_verbose.setChecked(False)
        self._verbose_action = act_verbose
        am.addAction(act_verbose)

        # Export
        em = mb.addMenu("Export")
        act_json = QAction("Export JSON Report…", self)
        act_json.setShortcut("Ctrl+E")
        act_json.triggered.connect(self._export_json)
        em.addAction(act_json)

        act_log = QAction("Export Scan Log…", self)
        act_log.triggered.connect(self._export_log)
        em.addAction(act_log)

        # Help
        hm = mb.addMenu("Help")
        act_about = QAction("About", self)
        act_about.triggered.connect(self._show_about)
        hm.addAction(act_about)

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN UI
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 6, 8, 6)
        root.setSpacing(6)

        # ── TOP TOOLBAR ──────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self._file_btn = QPushButton("＋ Files")
        self._file_btn.setToolTip("Add NDJSON / PCAP / QMDL files")
        self._file_btn.clicked.connect(self._browse_files)
        toolbar.addWidget(self._file_btn)

        self._dir_btn = QPushButton("📁 Directory")
        self._dir_btn.setToolTip("Set a directory to scan recursively")
        self._dir_btn.clicked.connect(self._browse_dir)
        toolbar.addWidget(self._dir_btn)

        self._selection_lbl = QLabel("No files selected")
        self._selection_lbl.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 11px;")
        toolbar.addWidget(self._selection_lbl, stretch=1)

        mcc_lbl = QLabel("MCC")
        mcc_lbl.setStyleSheet(f"color: {C.TEXT_DIM};")
        toolbar.addWidget(mcc_lbl)
        self._mcc_box = QLineEdit()
        self._mcc_box.setPlaceholderText("505")
        self._mcc_box.setFixedWidth(46)
        mcc_val = self._cfg.get("home_network", {}).get("mcc", "")
        self._mcc_box.setText(str(mcc_val))
        toolbar.addWidget(self._mcc_box)

        mnc_lbl = QLabel("MNC")
        mnc_lbl.setStyleSheet(f"color: {C.TEXT_DIM};")
        toolbar.addWidget(mnc_lbl)
        self._mnc_box = QLineEdit()
        self._mnc_box.setPlaceholderText("01")
        self._mnc_box.setFixedWidth(40)
        mnc_val = self._cfg.get("home_network", {}).get("mnc", "")
        self._mnc_box.setText(str(mnc_val))
        toolbar.addWidget(self._mnc_box)

        self._scan_btn = QPushButton("▶  SCAN")
        self._scan_btn.setObjectName("scan_btn")
        self._scan_btn.setToolTip("Run threat analysis (Ctrl+R)")
        self._scan_btn.clicked.connect(self._start_scan)
        toolbar.addWidget(self._scan_btn)

        self._stop_btn = QPushButton("■ Stop")
        self._stop_btn.setObjectName("stop_btn")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)
        toolbar.addWidget(self._stop_btn)

        root.addLayout(toolbar)

        # ── PROGRESS BAR ────────────────────────────────────────────────────
        self._progress = QProgressBar()
        self._progress.setValue(0)
        self._progress.setFixedHeight(5)
        self._progress.setTextVisible(False)
        root.addWidget(self._progress)

        # ── MAIN SPLITTER (horizontal: findings list | right panel) ─────────
        h_split = QSplitter(Qt.Orientation.Horizontal)
        h_split.setChildrenCollapsible(False)

        # Left: findings list
        left = QGroupBox("FINDINGS")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(4, 8, 4, 4)
        self._findings_list = QListWidget()
        self._findings_list.currentRowChanged.connect(self._on_finding_selected)
        left_layout.addWidget(self._findings_list)
        self._findings_count = QLabel("0 findings")
        self._findings_count.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 10px;")
        left_layout.addWidget(self._findings_count)
        h_split.addWidget(left)

        # Right: vertical splitter (threat card top | detail bottom)
        v_split = QSplitter(Qt.Orientation.Vertical)
        v_split.setChildrenCollapsible(False)

        # Right-top: threat card
        card_group = QGroupBox("THREAT ASSESSMENT")
        card_layout = QVBoxLayout(card_group)
        card_layout.setContentsMargins(4, 8, 4, 4)
        self._threat_card = ThreatCard()
        card_layout.addWidget(self._threat_card)
        v_split.addWidget(card_group)

        # Right-bottom: finding detail
        detail_group = QGroupBox("FINDING DETAIL")
        detail_layout = QVBoxLayout(detail_group)
        detail_layout.setContentsMargins(4, 8, 4, 4)
        self._finding_detail = FindingDetail()
        detail_layout.addWidget(self._finding_detail)

        export_row = QHBoxLayout()
        export_row.setSpacing(6)
        self._export_json_btn = QPushButton("Export JSON")
        self._export_json_btn.setObjectName("export_btn")
        self._export_json_btn.clicked.connect(self._export_json)
        export_row.addWidget(self._export_json_btn)
        self._export_log_btn = QPushButton("Export Log")
        self._export_log_btn.setObjectName("export_btn")
        self._export_log_btn.clicked.connect(self._export_log)
        export_row.addWidget(self._export_log_btn)
        export_row.addStretch()
        detail_layout.addLayout(export_row)
        v_split.addWidget(detail_group)

        v_split.setSizes([320, 320])
        h_split.addWidget(v_split)
        h_split.setSizes([340, 820])

        root.addWidget(h_split, stretch=1)

        # ── LOG PANEL ────────────────────────────────────────────────────────
        log_group = QGroupBox("SCAN LOG")
        log_layout = QVBoxLayout(log_group)
        log_layout.setContentsMargins(4, 8, 4, 4)
        log_layout.setSpacing(4)

        log_btns = QHBoxLayout()
        clr_btn = QPushButton("Clear")
        clr_btn.setFixedWidth(60)
        clr_btn.clicked.connect(self._clear_log)
        log_btns.addStretch()
        log_btns.addWidget(clr_btn)
        log_layout.addLayout(log_btns)

        self._log_panel = QTextEdit()
        self._log_panel.setReadOnly(True)
        self._log_panel.setFixedHeight(150)
        self._log_panel.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self._log_panel)
        root.addWidget(log_group)

    # ─────────────────────────────────────────────────────────────────────────
    # STATUS BAR
    # ─────────────────────────────────────────────────────────────────────────

    def _build_status(self):
        sb = self.statusBar()
        self._status_lbl = QLabel("Ready")
        sb.addWidget(self._status_lbl)
        db_info = "Analyzer: " + ("OK" if _ANALYZER_AVAILABLE else "NOT FOUND — run from repo root")
        sb.addPermanentWidget(QLabel(db_info))

    # ─────────────────────────────────────────────────────────────────────────
    # FILE SELECTION
    # ─────────────────────────────────────────────────────────────────────────

    def _browse_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Capture Files", "",
            "Capture files (*.ndjson *.pcap *.pcapng *.qmdl *.bin);;All files (*)"
        )
        if paths:
            self._selected_files.extend(paths)
            self._selected_dir = None
            self._update_selection_label()

    def _browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Capture Directory")
        if d:
            self._selected_dir = d
            self._selected_files = []
            self._update_selection_label()

    def _clear_selection(self):
        self._selected_files = []
        self._selected_dir = None
        self._update_selection_label()

    def _update_selection_label(self):
        if self._selected_dir:
            self._selection_lbl.setText(f"Dir: {self._selected_dir}")
            self._selection_lbl.setStyleSheet(f"color: {C.MEDIUM}; font-size: 11px;")
        elif self._selected_files:
            n = len(self._selected_files)
            self._selection_lbl.setText(f"{n} file{'s' if n != 1 else ''} selected")
            self._selection_lbl.setStyleSheet(f"color: {C.LOW}; font-size: 11px;")
        else:
            self._selection_lbl.setText("No files selected")
            self._selection_lbl.setStyleSheet(f"color: {C.TEXT_DIM}; font-size: 11px;")

    # ─────────────────────────────────────────────────────────────────────────
    # SCAN CONTROL
    # ─────────────────────────────────────────────────────────────────────────

    def _start_scan(self):
        if not _ANALYZER_AVAILABLE:
            QMessageBox.critical(self, "Analyzer Not Found",
                f"Analyzer modules could not be imported:\n\n{_IMPORT_ERROR}\n\n"
                "Run gui.py from the rayhunter-threat-analyzer root directory.")
            return

        if not self._selected_files and not self._selected_dir:
            QMessageBox.warning(self, "No Input",
                "Select files or a directory before scanning.")
            return

        # Apply MCC/MNC overrides
        cfg = dict(self._cfg)
        mcc = self._mcc_box.text().strip()
        mnc = self._mnc_box.text().strip()
        if mcc:
            cfg.setdefault("home_network", {})["mcc"] = mcc
        if mnc:
            cfg.setdefault("home_network", {})["mnc"] = mnc

        files = collect_files(
            self._selected_files if self._selected_files else [],
            self._selected_dir
        )
        total = sum(len(v) for v in files.values())
        if total == 0:
            QMessageBox.warning(self, "No Files", "No supported files found in selection.")
            return

        # Reset UI
        self._findings_list.clear()
        self._findings_count.setText("0 findings")
        self._threat_card.clear()
        self._finding_detail.clear()
        self._results = None
        self._enriched = []
        self._raw_findings = []
        self._progress.setValue(0)
        self._log(f"\n[SCAN START]  {total} file(s)")

        # Launch worker
        verbose = self._verbose_action.isChecked()
        self._thread = QThread()
        self._worker = AnalysisWorker(files, cfg, verbose)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self._log)
        self._worker.progress.connect(self._progress.setValue)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.error.connect(self._on_scan_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._on_thread_done)

        self._scan_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._status_lbl.setText("Scanning…")
        self._thread.start()

    def _stop_scan(self):
        if self._worker:
            self._worker.abort()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(3000)
        self._log("[!] Scan stopped by user.")
        self._on_thread_done()

    def _on_thread_done(self):
        self._scan_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Ready")

    # ─────────────────────────────────────────────────────────────────────────
    # SCAN RESULTS
    # ─────────────────────────────────────────────────────────────────────────

    def _on_scan_finished(self, payload: dict):
        self._results = payload
        results  = payload["results"]
        elapsed  = payload["elapsed"]

        self._raw_findings   = results.get("findings", [])
        self._enriched       = results.get("enriched_findings", [])
        fingerprinter        = results.get("fingerprinter")

        # Populate threat card
        if fingerprinter:
            self._threat_card.populate(fingerprinter)

        # Populate findings list
        self._findings_list.clear()
        display_list = self._enriched if self._enriched else self._raw_findings

        for i, item in enumerate(display_list):
            if self._enriched:
                title    = item.get("finding_title", f"Finding {i+1}")
                card     = item.get("rating_card", {})
                severity = card.get("severity", "UNKNOWN")
            else:
                title    = item.get("title", f"Finding {i+1}")
                severity = item.get("severity", "UNKNOWN")

            list_item = QListWidgetItem(f"  {severity:<10}  {title}")
            bg_col = {
                "CRITICAL": C.FINDING_CRIT,
                "HIGH":     C.FINDING_HIGH,
                "MEDIUM":   C.FINDING_MED,
                "LOW":      C.FINDING_LOW,
            }.get(severity, C.PANEL)
            text_col = DANGER_COLOUR.get(severity, C.TEXT)
            list_item.setBackground(QColor(bg_col))
            list_item.setForeground(QColor(text_col))
            self._findings_list.addItem(list_item)

        count = len(display_list)
        self._findings_count.setText(f"{count} finding{'s' if count != 1 else ''}")

        self._status_lbl.setText(
            f"Done — {count} finding(s)  |  {elapsed:.2f}s"
        )

    def _on_scan_error(self, msg: str):
        self._log(msg)
        self._status_lbl.setText("Error — see log")
        QMessageBox.critical(self, "Analysis Error", msg[:600])

    # ─────────────────────────────────────────────────────────────────────────
    # FINDING SELECTION
    # ─────────────────────────────────────────────────────────────────────────

    def _on_finding_selected(self, row: int):
        if row < 0:
            return
        if self._enriched and row < len(self._enriched):
            self._finding_detail.show_finding(self._enriched[row])
        elif self._raw_findings and row < len(self._raw_findings):
            self._finding_detail.show_raw(self._raw_findings[row])

    # ─────────────────────────────────────────────────────────────────────────
    # LOG
    # ─────────────────────────────────────────────────────────────────────────

    def _log(self, text: str):
        self._log_panel.moveCursor(QTextCursor.MoveOperation.End)
        self._log_panel.insertPlainText(text + "\n")
        self._log_panel.moveCursor(QTextCursor.MoveOperation.End)

    def _clear_log(self):
        self._log_panel.clear()

    # ─────────────────────────────────────────────────────────────────────────
    # EXPORT
    # ─────────────────────────────────────────────────────────────────────────

    def _export_json(self):
        if not self._results:
            QMessageBox.information(self, "No Data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON Report", "rayhunter_report.json",
            "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        try:
            reporter = ThreatReporter(self._cfg)
            report = reporter.build_report(
                self._results["results"],
                elapsed=self._results["elapsed"]
            )
            full = _build_full_report(report, self._results["results"])
            with open(path, "w") as f:
                json.dump(full, f, indent=2, default=str)
            self._status_lbl.setText(f"Exported: {path}")
            self._log(f"[✓] JSON exported to: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Scan Log", "rayhunter_scan.log",
            "Log files (*.log *.txt);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write(self._log_panel.toPlainText())
            self._log(f"[✓] Log exported to: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ─────────────────────────────────────────────────────────────────────────
    # ABOUT
    # ─────────────────────────────────────────────────────────────────────────

    def _show_about(self):
        QMessageBox.about(self, "About",
            "Rayhunter Threat Analyzer  v2.0\n"
            "Cellular Surveillance Detection & Forensic Analysis\n\n"
            "Targets: NDJSON · PCAP · QMDL\n"
            "Intelligence DB: attacks · devices · attacker profiles\n\n"
            "GitHub: JulianBurns85/rayhunter-threat-analyzer"
        )


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Rayhunter Threat Analyzer — GUI")
    parser.add_argument("--config", default="config.yaml",
                        help="Config file (default: config.yaml)")
    args = parser.parse_args()

    # Load config (fall back to empty dict if not found)
    cfg = {}
    if _ANALYZER_AVAILABLE:
        try:
            cfg = config_loader.load(args.config)
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("Rayhunter Threat Analyzer")
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)

    # Dark palette base (QSS handles most — this covers native widget edges)
    pal = app.palette()
    pal.setColor(QPalette.ColorRole.Window,        QColor(C.BG))
    pal.setColor(QPalette.ColorRole.WindowText,    QColor(C.TEXT))
    pal.setColor(QPalette.ColorRole.Base,          QColor(C.PANEL))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(C.PANEL_ALT))
    pal.setColor(QPalette.ColorRole.Text,          QColor(C.TEXT))
    pal.setColor(QPalette.ColorRole.Button,        QColor(C.ACCENT))
    pal.setColor(QPalette.ColorRole.ButtonText,    QColor(C.TEXT_BRIGHT))
    pal.setColor(QPalette.ColorRole.Highlight,     QColor(C.ACCENT_HOVER))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(C.TEXT_BRIGHT))
    app.setPalette(pal)

    window = MainWindow(cfg)
    window.show()
    sys.exit(app.exec())


    def _open_html_report(self):
        """Generate HTML report and open in default browser. v2.0"""
        import webbrowser
        import os
        try:
            if not getattr(self, "_full_report", None):
                self._log("No report available yet. Run a scan first.")
                return
            if not _HTML_AVAILABLE:
                self._log("html_reporter_v2 not found — cannot generate HTML report.")
                return
            html_path = _gen_html(self._full_report, output_dir="reports")
            self._log(f"HTML report saved: {html_path}")
            webbrowser.open(html_path.resolve().as_uri())
        except Exception as e:
            self._log(f"HTML report error: {e}")

    def _enable_html_button(self):
        """Enable the HTML button after a successful scan."""
        if hasattr(self, "_btn_html"):
            self._btn_html.setEnabled(True)

if __name__ == "__main__":
    main()
