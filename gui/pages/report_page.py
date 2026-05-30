"""Report page — in-app HTML viewer with report switcher and AI refinement panel."""

from __future__ import annotations

import webbrowser
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


def _webengine_available() -> bool:
    try:
        from PySide6.QtWebEngineWidgets import QWebEngineView
        return True
    except ImportError:
        return False


_BTN_STYLE = """
    QPushButton { background:#21262d;color:#c9d1d9;border:1px solid #30363d;
                  border-radius:4px;font-size:11px;padding:0 14px;font-weight:500; }
    QPushButton:hover { background:#30363d;color:#e6edf3;border-color:#484f58; }
    QPushButton:checked { background:#1c4980;color:#ffffff;
                          border-color:#388bfd;font-weight:700; }
    QPushButton:checked:hover { background:#235ba0; }
    QPushButton:disabled { color:#484f58;border-color:#21262d;background:#161b22; }
"""

_ACTION_BTN_STYLE = """
    QPushButton { background:#21262d;color:#79c0ff;border:1px solid #388bfd;
                  border-radius:4px;font-size:11px;padding:0 14px;font-weight:600; }
    QPushButton:hover { background:#1c2a3a;color:#a5d6ff; }
    QPushButton:disabled { color:#484f58;border-color:#21262d;background:#161b22; }
"""


class ReportPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._report_path: Path | None = None
        self._investigation_path: Path | None = None
        self._quick_report_path: Path | None = None
        self._formal_report_path: Path | None = None
        self._comprehensive_report_path: Path | None = None
        self._refinement_ctx = None
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────────
        toolbar = QFrame()
        toolbar.setFixedHeight(48)
        toolbar.setStyleSheet("background:#161b22;border-bottom:1px solid #30363d;")
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(12, 8, 12, 8)
        tb.setSpacing(8)

        self._path_label = QLabel("No report yet — run the pipeline first.")
        self._path_label.setStyleSheet("color:#8b949e;font-size:11px;")
        tb.addWidget(self._path_label, stretch=1)

        # Report switcher buttons — Comprehensive is the default landing report
        self._comp_btn = QPushButton("Comprehensive")
        self._formal_btn = QPushButton("Formal (Pure-Auto)")
        self._raw_btn = QPushButton("Raw Evidence")
        self._tech_btn = QPushButton("AI Technical")
        self._inv_btn = QPushButton("AI Investigation")
        for btn in (self._comp_btn, self._formal_btn, self._raw_btn,
                    self._tech_btn, self._inv_btn):
            btn.setFixedHeight(30)
            btn.setCheckable(True)
            btn.setEnabled(False)
            btn.setStyleSheet(_BTN_STYLE)
        self._comp_btn.setChecked(True)  # Comprehensive is the default

        self._comp_btn.clicked.connect(self._show_comprehensive)
        self._formal_btn.clicked.connect(self._show_formal)
        self._raw_btn.clicked.connect(self._show_raw)
        self._tech_btn.clicked.connect(self._show_technical)
        self._inv_btn.clicked.connect(self._show_investigation)
        tb.addWidget(self._comp_btn)
        tb.addWidget(self._formal_btn)
        tb.addWidget(self._raw_btn)
        tb.addWidget(self._tech_btn)
        tb.addWidget(self._inv_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet("color:#30363d;")
        tb.addWidget(sep)

        self._open_btn = QPushButton("Open in Browser")
        self._pdf_btn = QPushButton("Export PDF")
        for btn in (self._open_btn, self._pdf_btn):
            btn.setFixedHeight(30)
            btn.setEnabled(False)
            btn.setStyleSheet(_ACTION_BTN_STYLE)
        self._open_btn.clicked.connect(self._open_browser)
        self._pdf_btn.clicked.connect(self._export_pdf)
        tb.addWidget(self._open_btn)
        tb.addWidget(self._pdf_btn)
        outer.addWidget(toolbar)

        # ── Main area: viewer + refinement panel ─────────────────────────
        self._splitter = QSplitter(Qt.Orientation.Vertical)
        outer.addWidget(self._splitter, stretch=1)

        # Report viewer
        if _webengine_available():
            from PySide6.QtWebEngineWidgets import QWebEngineView
            self._view = QWebEngineView()
            self._view.setStyleSheet("background:#0d1117;")
            self._has_webengine = True
        else:
            self._view = QLabel(
                "QWebEngineView not available.\n"
                "Install PySide6-Addons or open the report in your browser."
            )
            self._view.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._view.setStyleSheet("color:#8b949e;font-size:13px;")
            self._has_webengine = False
        self._splitter.addWidget(self._view)

        # ── Refinement panel (hidden until report ready) ──────────────────
        self._refine_panel = QFrame()
        self._refine_panel.setStyleSheet("background:#161b22;border-top:1px solid #30363d;")
        self._refine_panel.setVisible(False)
        refine_layout = QVBoxLayout(self._refine_panel)
        refine_layout.setContentsMargins(12, 10, 12, 10)
        refine_layout.setSpacing(8)

        # Header
        hdr = QLabel("AI Report Refinement")
        hdr.setStyleSheet("color:#58a6ff;font-weight:700;font-size:12px;")
        hint = QLabel(
            "Ask the AI to re-examine specific aspects — e.g. 'Analyse USB connections in detail' "
            "or 'Rewrite the persistence section focusing on scheduled tasks'."
        )
        hint.setStyleSheet("color:#8b949e;font-size:10px;")
        hint.setWordWrap(True)
        refine_layout.addWidget(hdr)
        refine_layout.addWidget(hint)

        # Input row
        input_row = QHBoxLayout()
        self._refine_input = QLineEdit()
        self._refine_input.setPlaceholderText("Type your refinement request and press Enter…")
        self._refine_input.setStyleSheet(
            "background:#0d1117;color:#e6edf3;border:1px solid #30363d;"
            "border-radius:4px;padding:6px 10px;font-size:12px;"
        )
        self._refine_input.returnPressed.connect(self._on_refine)

        self._refine_btn = QPushButton("Analyse")
        self._refine_btn.setFixedHeight(34)
        self._refine_btn.setFixedWidth(80)
        self._refine_btn.setStyleSheet(
            "QPushButton{background:#1f6feb;color:#fff;border:none;border-radius:4px;font-weight:700;font-size:11px;}"
            "QPushButton:hover{background:#388bfd;}"
            "QPushButton:disabled{background:#30363d;color:#8b949e;}"
        )
        self._refine_btn.clicked.connect(self._on_refine)

        input_row.addWidget(self._refine_input)
        input_row.addWidget(self._refine_btn)
        refine_layout.addLayout(input_row)

        # Response area
        self._refine_output = QTextEdit()
        self._refine_output.setReadOnly(True)
        self._refine_output.setFixedHeight(180)
        self._refine_output.setStyleSheet(
            "background:#0d1117;color:#e6edf3;border:1px solid #30363d;"
            "border-radius:4px;padding:8px;font-size:12px;font-family:'Segoe UI';"
        )
        self._refine_output.setPlaceholderText("AI analysis will appear here…")
        refine_layout.addWidget(self._refine_output)

        self._splitter.addWidget(self._refine_panel)
        self._splitter.setSizes([700, 320])

    # ── Public API ────────────────────────────────────────────────────────

    def load_report(self, path: str, investigation_path: str | None = None,
                    refinement_ctx=None, quick_report_path: str | None = None,
                    formal_report_path: str | None = None,
                    comprehensive_report_path: str | None = None):
        self._report_path = Path(path)
        self._refinement_ctx = refinement_ctx

        if investigation_path:
            self._investigation_path = Path(investigation_path)
        if quick_report_path:
            self._quick_report_path = Path(quick_report_path)
        if formal_report_path:
            self._formal_report_path = Path(formal_report_path)
        if comprehensive_report_path:
            self._comprehensive_report_path = Path(comprehensive_report_path)

        self._open_btn.setEnabled(True)
        self._pdf_btn.setEnabled(self._has_webengine)
        # AI buttons only enable if AI reports exist
        if self._report_path and self._report_path.exists() and \
           self._report_path.name == "final_forensic_report.html":
            self._tech_btn.setEnabled(True)
        if investigation_path and Path(investigation_path).exists():
            self._inv_btn.setEnabled(True)
        if quick_report_path and Path(quick_report_path).exists():
            self._raw_btn.setEnabled(True)
        if formal_report_path and Path(formal_report_path).exists():
            self._formal_btn.setEnabled(True)
        if comprehensive_report_path and Path(comprehensive_report_path).exists():
            self._comp_btn.setEnabled(True)

        # Default: open the Comprehensive evidence report (everything in one place,
        # browser-searchable). Falls back to Formal then Technical if Comprehensive
        # isn't available for some reason.
        for btn in (self._comp_btn, self._formal_btn, self._raw_btn,
                    self._tech_btn, self._inv_btn):
            btn.setChecked(False)
        if self._comprehensive_report_path and self._comprehensive_report_path.exists():
            self._comp_btn.setChecked(True)
            self._path_label.setText(f"Report: {self._comprehensive_report_path.name}")
            self._load_url(self._comprehensive_report_path)
        elif self._formal_report_path and self._formal_report_path.exists():
            self._formal_btn.setChecked(True)
            self._path_label.setText(f"Report: {self._formal_report_path.name}")
            self._load_url(self._formal_report_path)
        else:
            self._tech_btn.setChecked(True)
            self._path_label.setText(f"Report: {self._report_path.name}")
            self._load_url(self._report_path)

        # Show refinement panel if LLM is available
        if refinement_ctx and getattr(refinement_ctx, 'all_findings', []):
            self._refine_panel.setVisible(True)
            self._refine_btn.setEnabled(True)
            self._splitter.setSizes([700, 320])

    def _load_url(self, path: Path):
        if self._has_webengine and path and path.exists():
            self._view.setUrl(QUrl.fromLocalFile(str(path)))

    def _set_active(self, active_btn):
        for btn in (self._raw_btn, self._formal_btn, self._comp_btn,
                    self._tech_btn, self._inv_btn):
            btn.setChecked(btn is active_btn)

    def _show_raw(self):
        self._set_active(self._raw_btn)
        if self._quick_report_path and self._quick_report_path.exists():
            self._path_label.setText(f"Report: {self._quick_report_path.name}")
            self._load_url(self._quick_report_path)

    def _show_formal(self):
        self._set_active(self._formal_btn)
        if self._formal_report_path and self._formal_report_path.exists():
            self._path_label.setText(f"Report: {self._formal_report_path.name}")
            self._load_url(self._formal_report_path)

    def _show_comprehensive(self):
        self._set_active(self._comp_btn)
        if self._comprehensive_report_path and self._comprehensive_report_path.exists():
            self._path_label.setText(f"Report: {self._comprehensive_report_path.name}")
            self._load_url(self._comprehensive_report_path)

    def _show_technical(self):
        self._set_active(self._tech_btn)
        if self._report_path:
            self._path_label.setText(f"Report: {self._report_path.name}")
            self._load_url(self._report_path)

    def _show_investigation(self):
        self._set_active(self._inv_btn)
        if self._investigation_path and self._investigation_path.exists():
            self._path_label.setText(f"Report: {self._investigation_path.name}")
            self._load_url(self._investigation_path)

    def _current_report_path(self) -> Path | None:
        if self._formal_btn.isChecked():    return self._formal_report_path
        if self._comp_btn.isChecked():      return self._comprehensive_report_path
        if self._inv_btn.isChecked():       return self._investigation_path
        if self._raw_btn.isChecked():       return self._quick_report_path
        return self._report_path

    def _open_browser(self):
        current = self._current_report_path()
        if current and current.exists():
            webbrowser.open(str(current))

    def _export_pdf(self):
        if not self._has_webengine:
            return
        from PySide6.QtWidgets import QFileDialog
        current = self._current_report_path()
        if not current:
            return
        out, _ = QFileDialog.getSaveFileName(
            self, "Export PDF", str(current.with_suffix(".pdf")), "PDF Files (*.pdf)"
        )
        if out:
            self._view.page().printToPdf(out)

    # ── Refinement ────────────────────────────────────────────────────────

    def _on_refine(self):
        request = self._refine_input.text().strip()
        if not request or not self._refinement_ctx:
            return
        self._refine_btn.setEnabled(False)
        self._refine_input.setEnabled(False)
        self._refine_output.setPlainText("Analysing… this may take a minute.")

        class _RefineThread(QThread):
            done = Signal(str)
            error = Signal(str)
            def __init__(self, ctx, req, parent=None):
                super().__init__(parent)
                self._ctx = ctx
                self._req = req
            def run(self):
                from core.progress_bus import ProgressBus
                try:
                    resp = self._ctx.refine(self._req, ProgressBus())
                    self.done.emit(resp)
                except Exception as e:
                    self.error.emit(str(e))

        self._refine_thread = _RefineThread(self._refinement_ctx, request, self)
        self._refine_thread.done.connect(self._on_refine_done)
        self._refine_thread.error.connect(self._on_refine_error)
        self._refine_thread.start()

    def _on_refine_done(self, response: str):
        self._refine_output.setPlainText(response)
        self._refine_btn.setEnabled(True)
        self._refine_input.setEnabled(True)
        self._refine_input.clear()
        # Rebuild investigation report with this refinement appended
        if self._refinement_ctx and self._refinement_ctx.investigation_report:
            try:
                from core.report.final_report import build_investigation_report
                build_investigation_report(
                    self._refinement_ctx.ctx,
                    self._refinement_ctx.all_findings,
                    "",
                    conclusion=response,
                    system_info=self._refinement_ctx.system_info,
                )
                # Reload the investigation report view if it's currently displayed
                if self._inv_btn.isChecked() and self._investigation_path:
                    self._load_url(self._investigation_path)
            except Exception:
                pass

    def _on_refine_error(self, err: str):
        self._refine_output.setPlainText(f"Error: {err}")
        self._refine_btn.setEnabled(True)
        self._refine_input.setEnabled(True)
