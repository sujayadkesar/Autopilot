"""Run page — agent cards + global progress while pipeline executes."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..widgets.agent_card import AgentCard


class RunPage(QWidget):
    cancel_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: dict[str, AgentCard] = {}
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Global progress bar
        top_bar = QFrame()
        top_bar.setStyleSheet("background:#161b22;border-bottom:1px solid #30363d;")
        top_bar.setFixedHeight(52)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(24, 8, 24, 8)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color:#8b949e;font-size:12px;")
        self._global_bar = QProgressBar()
        self._global_bar.setRange(0, 0)  # indeterminate until we can count stages
        self._global_bar.setFixedHeight(6)
        self._global_bar.setVisible(False)
        self._global_bar.setStyleSheet("""
            QProgressBar { background:#30363d; border:none; border-radius:3px; }
            QProgressBar::chunk { background:#58a6ff; border-radius:3px; }
        """)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setFixedSize(80, 28)
        self._cancel_btn.setVisible(False)
        self._cancel_btn.setStyleSheet("""
            QPushButton { background:#2d1b1b;color:#ff4444;border:1px solid #ff4444;
                          border-radius:4px;font-size:11px; }
            QPushButton:hover { background:#3d1b1b; }
        """)
        self._cancel_btn.clicked.connect(self.cancel_requested)

        top_layout.addWidget(self._status_label)
        top_layout.addWidget(self._global_bar, stretch=1)
        top_layout.addWidget(self._cancel_btn)
        outer.addWidget(top_bar)

        # Scrollable card area
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

    def prepare_run(self, agent_names: list[tuple[str, str]]):
        """Called before pipeline starts. agent_names = [(name, display_name), ...]"""
        # Clear old cards
        for card in self._cards.values():
            self._cards_layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

        # Add new cards
        stretch_item = self._cards_layout.takeAt(self._cards_layout.count() - 1)
        for name, display in agent_names:
            card = AgentCard(name, display)
            self._cards[name] = card
            self._cards_layout.addWidget(card)
        self._cards_layout.addStretch()

        self._global_bar.setRange(0, 0)
        self._global_bar.setVisible(True)
        self._cancel_btn.setVisible(True)
        self._status_label.setText("Pipeline running…")

    def on_global_done(self, report_path: str):
        self._global_bar.setVisible(False)
        self._global_bar.setRange(0, 1)
        self._global_bar.setValue(1)
        self._cancel_btn.setVisible(False)
        self._status_label.setStyleSheet("color:#3fb950;font-size:12px;font-weight:600;")
        self._status_label.setText(f"✓ Complete — {report_path}")

    def on_pipeline_error(self, error: str):
        self._global_bar.setVisible(False)
        self._cancel_btn.setVisible(False)
        self._status_label.setStyleSheet("color:#ff4444;font-size:12px;font-weight:600;")
        self._status_label.setText(f"✗ Error: {error[:80]}")

    # ── wiring helpers (called by main_window) ────────────────────────────

    def on_stage_started(self, agent: str, stage: str):
        if agent in self._cards:
            self._cards[agent].on_stage_started(stage)

    def on_stage_progress(self, agent: str, stage: str, pct: float, msg: str):
        if agent in self._cards:
            self._cards[agent].on_stage_progress(stage, pct, msg)
        if msg:
            self._status_label.setText(f"[{agent}] {stage} — {msg}")

    def on_stage_done(self, agent: str, stage: str, elapsed: float):
        if agent in self._cards:
            self._cards[agent].on_stage_done(stage, elapsed)

    def on_stage_error(self, agent: str, stage: str, error_msg: str):
        if agent in self._cards:
            self._cards[agent].on_stage_error(stage, error_msg)

    def on_finding_added(self, agent: str, count: int, severity: str):
        if agent in self._cards:
            self._cards[agent].on_finding_added(count, severity)
