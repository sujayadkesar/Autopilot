"""
MainWindow — primary application window.

Layout:
  Left  | Tab bar (Setup / Run / Logs / Report)
  Right | Page content
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSizePolicy,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.agent_registry import list_agents
from core.case_context import CaseContext

from .pages.log_page import LogPage
from .pages.progress_page import ProgressPage
from .pages.report_page import ReportPage
from .pages.run_page import RunPage
from .pages.setup_page import SetupPage
from .workers.orchestrator_worker import OrchestratorWorker

_PAGES = ["Setup", "Run", "Progress", "Logs", "Report"]


class SidebarButton(QToolButton):
    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setText(text)
        self.setCheckable(True)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(44)
        self._set_style(False)

    def setChecked(self, checked: bool):
        super().setChecked(checked)
        self._set_style(checked)

    def _set_style(self, active: bool):
        if active:
            style = """
                QToolButton {
                    background:#1f2937;color:#e6edf3;
                    border-left:3px solid #58a6ff;border-right:none;
                    border-top:none;border-bottom:none;
                    text-align:left;padding-left:18px;
                    font-weight:600;font-size:13px;
                }
            """
        else:
            style = """
                QToolButton {
                    background:transparent;color:#8b949e;
                    border-left:3px solid transparent;border-right:none;
                    border-top:none;border-bottom:none;
                    text-align:left;padding-left:18px;
                    font-size:13px;
                }
                QToolButton:hover { color:#c9d1d9; background:#161b22; }
            """
        self.setStyleSheet(style)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DFIR Automation")
        self.setMinimumSize(1100, 720)
        self._worker: Optional[OrchestratorWorker] = None
        self._agents_manifest = list_agents()
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("QFrame{background:#161b22;border-right:1px solid #30363d;}")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(0)

        # Logo / title
        title_frame = QFrame()
        title_frame.setFixedHeight(64)
        title_frame.setStyleSheet("background:linear-gradient(135deg,#0d1b2a,#1a1f35);border-bottom:1px solid #30363d;")
        tl = QVBoxLayout(title_frame)
        tl.setContentsMargins(16, 10, 16, 10)
        title_lbl = QLabel("DFIR")
        title_lbl.setStyleSheet("color:#58a6ff;font-size:20px;font-weight:900;letter-spacing:4px;")
        sub_lbl = QLabel("Forensic Automation")
        sub_lbl.setStyleSheet("color:#8b949e;font-size:9px;letter-spacing:2px;text-transform:uppercase;")
        tl.addWidget(title_lbl)
        tl.addWidget(sub_lbl)
        sb_layout.addWidget(title_frame)

        # Nav buttons
        self._nav_btns: dict[str, SidebarButton] = {}
        for page_name in _PAGES:
            btn = SidebarButton(page_name)
            btn.clicked.connect(lambda checked, n=page_name: self._switch_page(n))
            self._nav_btns[page_name] = btn
            sb_layout.addWidget(btn)

        # Agent list in sidebar
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#30363d;")
        sb_layout.addWidget(sep)
        agents_title = QLabel("  Agents")
        agents_title.setStyleSheet("color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:2px;padding:8px 16px 4px;")
        sb_layout.addWidget(agents_title)

        for agent in self._agents_manifest:
            lbl = QLabel(f"  · {agent['display_name']}")
            lbl.setStyleSheet("color:#8b949e;font-size:11px;padding:3px 16px;")
            sb_layout.addWidget(lbl)

        sb_layout.addStretch()

        # Version footer
        ver_lbl = QLabel("v1.0.0")
        ver_lbl.setStyleSheet("color:#30363d;font-size:9px;padding:8px 16px;")
        sb_layout.addWidget(ver_lbl)

        root.addWidget(sidebar)

        # ── Page stack ─────────────────────────────────────────────────
        self._stack = QStackedWidget()
        root.addWidget(self._stack, stretch=1)

        self._setup_page = SetupPage(self._agents_manifest)
        self._run_page = RunPage()
        self._progress_page = ProgressPage()
        self._log_page = LogPage()
        self._report_page = ReportPage()

        for page in (self._setup_page, self._run_page, self._progress_page,
                     self._log_page, self._report_page):
            self._stack.addWidget(page)

        # Connections
        self._setup_page.run_requested.connect(self._on_run_requested)
        self._run_page.cancel_requested.connect(self._on_cancel)

        self._switch_page("Setup")

    def _switch_page(self, name: str):
        idx = _PAGES.index(name)
        self._stack.setCurrentIndex(idx)
        for page_name, btn in self._nav_btns.items():
            btn.setChecked(page_name == name)

    # ── Pipeline wiring ───────────────────────────────────────────────────

    def _on_run_requested(self, config: dict):
        skip_llm = config.pop("_skip_llm", False)
        ctx = CaseContext(**config)
        agent_info = [(a["name"], a["display_name"]) for a in self._agents_manifest if a["name"] in config["enabled_agents"]]

        self._run_page.prepare_run(agent_info)
        self._progress_page.prepare_run(agent_info)
        self._switch_page("Run")

        self._worker = OrchestratorWorker(ctx, skip_llm=skip_llm)
        sig = self._worker.signals

        # Wire signals to Run page (agent cards)
        sig.stage_started.connect(self._run_page.on_stage_started)
        sig.stage_progress.connect(self._run_page.on_stage_progress)
        sig.stage_done.connect(self._run_page.on_stage_done)
        sig.stage_error.connect(self._run_page.on_stage_error)
        sig.finding_added.connect(self._run_page.on_finding_added)
        # Wire signals to Progress page (structured timeline)
        sig.stage_started.connect(self._progress_page.on_stage_started)
        sig.stage_progress.connect(self._progress_page.on_stage_progress)
        sig.stage_done.connect(self._progress_page.on_stage_done)
        sig.stage_error.connect(self._progress_page.on_stage_error)
        sig.finding_added.connect(self._progress_page.on_finding_added)

        sig.log_line.connect(lambda level, agent, msg: self._log_page.append(level, agent, msg))

        sig.global_done.connect(self._on_pipeline_done)  # (report_path, quick_report_path)
        sig.pipeline_error.connect(self._on_pipeline_error)

        self._setup_page.set_running(True)
        self._worker.start()

    def _on_cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
            self._run_page.on_pipeline_error("Cancelled by user")
            self._setup_page.set_running(False)

    def _on_pipeline_done(self, report_path: str, quick_report_path: str,
                          formal_report_path: str, comprehensive_report_path: str):
        self._run_page.on_global_done(report_path)
        self._progress_page.on_global_done(report_path)
        self._setup_page.set_running(False)

        refinement_ctx = None
        inv_path = None
        if self._worker and self._worker._result is not None:
            result = self._worker._result
            refinement_ctx = getattr(result, '_refinement_ctx', None)
            if refinement_ctx and refinement_ctx.investigation_report:
                inv_path = str(refinement_ctx.investigation_report)

        self._report_page.load_report(
            report_path,
            investigation_path=inv_path,
            refinement_ctx=refinement_ctx,
            quick_report_path=quick_report_path or None,
            formal_report_path=formal_report_path or None,
            comprehensive_report_path=comprehensive_report_path or None,
        )
        QTimer.singleShot(500, lambda: self._switch_page("Report"))

    def _on_pipeline_error(self, error_msg: str):
        self._run_page.on_pipeline_error(error_msg)
        self._progress_page.on_pipeline_error(error_msg)
        self._setup_page.set_running(False)
        QMessageBox.critical(self, "Pipeline Error", error_msg[:800])

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(2000)
        super().closeEvent(event)
