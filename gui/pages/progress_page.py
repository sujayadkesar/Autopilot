"""
Progress page — structured per-agent stage tracker.

Shows a live table: Agent | Stage | Status | Duration
plus a global elapsed timer and completion checklist.
"""

from __future__ import annotations

import time
from typing import Dict, Tuple

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

STAGES = ["extract", "parse", "analyze", "report"]

_STATUS_STYLE = {
    "idle":    ("—",        "#444d56"),
    "running": ("⏳ Running", "#f0883e"),
    "done":    ("✓ Done",   "#3fb950"),
    "error":   ("✗ Error",  "#ff4444"),
    "skipped": ("⊘ Skip",   "#8b949e"),
}


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 0:
        return "—"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


class StageRow(QWidget):
    """One row in the agent's stage table."""
    def __init__(self, stage: str, parent=None):
        super().__init__(parent)
        self.stage = stage
        self._start: float = -1
        self._elapsed: float = -1
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 2, 0, 2)
        row.setSpacing(0)

        self._stage_lbl = QLabel(stage.capitalize())
        self._stage_lbl.setFixedWidth(80)
        self._stage_lbl.setStyleSheet("color:#8b949e;font-size:11px;padding-left:8px;")

        self._status_lbl = QLabel("—")
        self._status_lbl.setFixedWidth(120)
        self._status_lbl.setStyleSheet("color:#444d56;font-size:11px;")

        self._elapsed_lbl = QLabel("—")
        self._elapsed_lbl.setFixedWidth(70)
        self._elapsed_lbl.setStyleSheet("color:#8b949e;font-size:11px;")
        self._elapsed_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        self._msg_lbl = QLabel("")
        self._msg_lbl.setStyleSheet("color:#444d56;font-size:10px;padding-left:8px;")
        self._msg_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        row.addWidget(self._stage_lbl)
        row.addWidget(self._status_lbl)
        row.addWidget(self._elapsed_lbl)
        row.addWidget(self._msg_lbl)

    def set_status(self, key: str, msg: str = "", elapsed: float = -1):
        label, color = _STATUS_STYLE.get(key, ("—", "#444d56"))
        self._status_lbl.setText(label)
        self._status_lbl.setStyleSheet(f"color:{color};font-size:11px;font-weight:600;")
        if elapsed >= 0:
            self._elapsed = elapsed
            self._elapsed_lbl.setText(_fmt_elapsed(elapsed))
        if msg:
            short = msg[:60] + "…" if len(msg) > 60 else msg
            self._msg_lbl.setText(short)
            self._msg_lbl.setStyleSheet("color:#8b949e;font-size:10px;padding-left:8px;")

    def start(self):
        self._start = time.monotonic()
        self.set_status("running")

    def tick(self):
        if self._start > 0 and self._elapsed < 0:
            elapsed = time.monotonic() - self._start
            self._elapsed_lbl.setText(_fmt_elapsed(elapsed))


class AgentProgressCard(QWidget):
    """Card showing all 4 stage rows for one agent."""
    def __init__(self, agent_name: str, display_name: str, parent=None):
        super().__init__(parent)
        self.agent_name = agent_name
        self._stages: Dict[str, StageRow] = {}
        self._finding_count = 0
        self._start = time.monotonic()
        self._done = False
        self._build(display_name)

    def _build(self, display_name: str):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Header
        header = QFrame()
        header.setStyleSheet("background:#1c2128;border-radius:6px 6px 0 0;")
        hdr_layout = QHBoxLayout(header)
        hdr_layout.setContentsMargins(12, 8, 12, 8)

        name_lbl = QLabel(display_name)
        name_lbl.setStyleSheet("color:#c9d1d9;font-size:12px;font-weight:700;")
        hdr_layout.addWidget(name_lbl, stretch=1)

        self._finding_lbl = QLabel("0 findings")
        self._finding_lbl.setStyleSheet("color:#8b949e;font-size:10px;")
        hdr_layout.addWidget(self._finding_lbl)

        self._total_lbl = QLabel("")
        self._total_lbl.setStyleSheet("color:#3fb950;font-size:10px;font-weight:600;")
        hdr_layout.addWidget(self._total_lbl)
        outer.addWidget(header)

        # Stage rows
        body = QFrame()
        body.setStyleSheet(
            "background:#161b22;border:1px solid #30363d;"
            "border-top:none;border-radius:0 0 6px 6px;"
        )
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(4, 4, 4, 4)
        body_layout.setSpacing(0)

        # Column header
        col_header = QWidget()
        col_row = QHBoxLayout(col_header)
        col_row.setContentsMargins(0, 0, 0, 4)
        col_row.setSpacing(0)
        for txt, w in [("Stage", 80), ("Status", 120), ("Time", 70)]:
            lbl = QLabel(txt)
            lbl.setFixedWidth(w)
            lbl.setStyleSheet("color:#444d56;font-size:9px;text-transform:uppercase;"
                              "letter-spacing:1px;padding-left:8px;")
            col_row.addWidget(lbl)
        detail_lbl = QLabel("Detail")
        detail_lbl.setStyleSheet("color:#444d56;font-size:9px;text-transform:uppercase;"
                                 "letter-spacing:1px;padding-left:8px;")
        col_row.addWidget(detail_lbl, stretch=1)
        body_layout.addWidget(col_header)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#21262d;")
        body_layout.addWidget(sep)

        for stage in STAGES:
            row = StageRow(stage)
            self._stages[stage] = row
            body_layout.addWidget(row)

        outer.addWidget(body)

    def on_started(self, stage: str):
        if stage in self._stages:
            self._stages[stage].start()

    def on_progress(self, stage: str, pct: float, msg: str):
        if stage in self._stages:
            self._stages[stage].set_status("running", msg)

    def on_done(self, stage: str, elapsed: float):
        if stage in self._stages:
            self._stages[stage].set_status("done", elapsed=elapsed)
        if stage == "report":
            self._done = True
            total = time.monotonic() - self._start
            self._total_lbl.setText(f"✓ {_fmt_elapsed(total)}")

    def on_error(self, stage: str, msg: str):
        if stage in self._stages:
            self._stages[stage].set_status("error", msg)

    def on_finding(self, count: int, severity: str):
        self._finding_count = count
        sev_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                     "MEDIUM": "#ffcc00"}.get(severity, "#8b949e")
        self._finding_lbl.setText(
            f"{count} finding{'s' if count != 1 else ''} "
            f"<span style='color:{sev_color}'>({severity})</span>"
        )
        self._finding_lbl.setTextFormat(Qt.TextFormat.RichText)

    def tick(self):
        for row in self._stages.values():
            row.tick()


class ProgressPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: Dict[str, AgentProgressCard] = {}
        self._pipeline_start: float = -1
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Top bar
        top = QFrame()
        top.setFixedHeight(52)
        top.setStyleSheet("background:#161b22;border-bottom:1px solid #30363d;")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(24, 8, 24, 8)

        self._status_lbl = QLabel("Waiting for pipeline…")
        self._status_lbl.setStyleSheet("color:#8b949e;font-size:12px;")
        top_layout.addWidget(self._status_lbl, stretch=1)

        self._elapsed_lbl = QLabel("")
        self._elapsed_lbl.setStyleSheet("color:#8b949e;font-size:11px;")
        top_layout.addWidget(self._elapsed_lbl)

        outer.addWidget(top)

        # Global progress bar
        self._global_bar = QProgressBar()
        self._global_bar.setRange(0, 0)
        self._global_bar.setFixedHeight(4)
        self._global_bar.setVisible(False)
        self._global_bar.setTextVisible(False)
        self._global_bar.setStyleSheet("""
            QProgressBar { background:#21262d; border:none; }
            QProgressBar::chunk { background:#58a6ff; }
        """)
        outer.addWidget(self._global_bar)

        # Scrollable cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background:#0d1117;border:none;")

        self._cards_widget = QWidget()
        self._cards_widget.setStyleSheet("background:#0d1117;")
        self._cards_layout = QVBoxLayout(self._cards_widget)
        self._cards_layout.setContentsMargins(24, 20, 24, 20)
        self._cards_layout.setSpacing(12)
        self._cards_layout.addStretch()

        scroll.setWidget(self._cards_widget)
        outer.addWidget(scroll, stretch=1)

    def prepare_run(self, agent_info: list[tuple[str, str]]):
        """Called before pipeline starts. agent_info = [(name, display_name), ...]"""
        for card in self._cards.values():
            self._cards_layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

        stretch = self._cards_layout.takeAt(self._cards_layout.count() - 1)
        for name, display in agent_info:
            card = AgentProgressCard(name, display)
            self._cards[name] = card
            self._cards_layout.addWidget(card)
        self._cards_layout.addStretch()

        self._pipeline_start = time.monotonic()
        if not self._timer.isActive():
            self._timer.start()
        self._global_bar.setVisible(True)
        self._status_lbl.setStyleSheet("color:#f0883e;font-size:12px;font-weight:600;")
        self._status_lbl.setText("Pipeline running…")

    def on_global_done(self, report_path: str):
        self._global_bar.setVisible(False)
        self._status_lbl.setStyleSheet("color:#3fb950;font-size:12px;font-weight:600;")
        # Freeze the elapsed timer at completion
        if self._pipeline_start > 0:
            final = time.monotonic() - self._pipeline_start
            self._elapsed_lbl.setText(f"Total: {_fmt_elapsed(final)}")
            self._pipeline_start = -1  # stops _tick from updating
        self._timer.stop()
        self._status_lbl.setText("✓ Pipeline complete")

    def on_pipeline_error(self, err: str):
        self._global_bar.setVisible(False)
        if self._pipeline_start > 0:
            final = time.monotonic() - self._pipeline_start
            self._elapsed_lbl.setText(f"Stopped at: {_fmt_elapsed(final)}")
            self._pipeline_start = -1
        self._timer.stop()
        self._status_lbl.setStyleSheet("color:#ff4444;font-size:12px;font-weight:600;")
        self._status_lbl.setText(f"✗ Error: {err[:80]}")

    # Signal handlers (wired by main_window)
    def on_stage_started(self, agent: str, stage: str):
        if agent in self._cards:
            self._cards[agent].on_started(stage)

    def on_stage_progress(self, agent: str, stage: str, pct: float, msg: str):
        if agent in self._cards:
            self._cards[agent].on_progress(stage, pct, msg)

    def on_stage_done(self, agent: str, stage: str, elapsed: float):
        if agent in self._cards:
            self._cards[agent].on_done(stage, elapsed)

    def on_stage_error(self, agent: str, stage: str, error_msg: str):
        if agent in self._cards:
            self._cards[agent].on_error(stage, error_msg)

    def on_finding_added(self, agent: str, count: int, severity: str):
        if agent in self._cards:
            self._cards[agent].on_finding(count, severity)

    def _tick(self):
        if self._pipeline_start > 0:
            elapsed = time.monotonic() - self._pipeline_start
            self._elapsed_lbl.setText(f"Elapsed: {_fmt_elapsed(elapsed)}")
        for card in self._cards.values():
            card.tick()
