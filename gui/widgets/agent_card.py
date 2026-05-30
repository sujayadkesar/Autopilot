"""
AgentCard — shows extract/parse/analyze/report stage progress for one agent.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

STAGE_NAMES = ["extract", "parse", "analyze", "report"]

SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#33cc66",
    "INFO":     "#4488ff",
}

STAGE_STATES = {
    "idle":    ("#30363d", "#30363d"),
    "running": ("#1f6feb", "#58a6ff"),
    "done":    ("#196c2e", "#3fb950"),
    "error":   ("#6e1313", "#ff4444"),
}


class StagePill(QLabel):
    def __init__(self, stage_name: str, parent=None):
        super().__init__(parent)
        self._stage = stage_name
        self._state = "idle"
        self._pct = 0.0
        self._elapsed = 0.0
        self._redraw()

    def set_state(self, state: str, pct: float = 0.0, elapsed: float = 0.0):
        self._state = state
        self._pct = pct
        self._elapsed = elapsed
        self._redraw()

    def _redraw(self):
        bg, fg = STAGE_STATES.get(self._state, STAGE_STATES["idle"])
        label = self._stage.capitalize()
        if self._state == "running":
            label += f" {self._pct:.0f}%"
        elif self._state == "done":
            label += f" ✓ {self._elapsed:.1f}s"
        elif self._state == "error":
            label += " ✗"
        self.setText(label)
        self.setStyleSheet(f"""
            QLabel {{
                background: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 4px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 600;
            }}
        """)


class AgentCard(QFrame):
    def __init__(self, agent_name: str, display_name: str, parent=None):
        super().__init__(parent)
        self.agent_name = agent_name
        self._findings = 0
        self._risk_score = 0
        self._latest_finding = ""

        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            AgentCard {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(8)

        # Header row
        header = QHBoxLayout()
        self._title = QLabel(display_name)
        self._title.setStyleSheet("color:#58a6ff;font-weight:700;font-size:13px;")
        header.addWidget(self._title)
        header.addStretch()
        self._findings_label = QLabel("0 findings")
        self._findings_label.setStyleSheet("color:#8b949e;font-size:11px;")
        header.addWidget(self._findings_label)
        self._risk_label = QLabel("")
        self._risk_label.setStyleSheet("font-weight:700;font-size:11px;")
        header.addWidget(self._risk_label)
        root.addLayout(header)

        # Stage pills
        pills_row = QHBoxLayout()
        pills_row.setSpacing(8)
        self._pills: dict[str, StagePill] = {}
        for stage in STAGE_NAMES:
            pill = StagePill(stage)
            self._pills[stage] = pill
            pills_row.addWidget(pill)
        pills_row.addStretch()
        root.addLayout(pills_row)

        # Latest finding
        self._latest_label = QLabel("")
        self._latest_label.setStyleSheet("color:#8b949e;font-size:10px;font-style:italic;")
        self._latest_label.setWordWrap(True)
        root.addWidget(self._latest_label)

    # ── slots (called from main thread via signal connections) ────────────

    def on_stage_started(self, stage: str):
        if stage in self._pills:
            self._pills[stage].set_state("running")

    def on_stage_progress(self, stage: str, pct: float, msg: str):
        if stage in self._pills:
            self._pills[stage].set_state("running", pct=pct)
        if msg:
            self._latest_label.setText(f"→ {msg}")

    def on_stage_done(self, stage: str, elapsed: float):
        if stage in self._pills:
            self._pills[stage].set_state("done", elapsed=elapsed)

    def on_stage_error(self, stage: str, error_msg: str):
        if stage in self._pills:
            self._pills[stage].set_state("error")
        self._latest_label.setText(f"✗ {error_msg[:120]}")
        self._latest_label.setStyleSheet("color:#ff4444;font-size:10px;")

    def on_finding_added(self, count: int, severity: str):
        self._findings = count
        self._findings_label.setText(f"{count} finding{'s' if count != 1 else ''}")
        color = SEV_COLORS.get(severity, "#8b949e")
        if severity in ("CRITICAL", "HIGH"):
            self._latest_label.setStyleSheet(f"color:{color};font-size:10px;font-weight:600;")
