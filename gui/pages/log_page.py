"""Log page — streaming pipeline log with working level filter."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..widgets.log_view import LogView

LEVEL_RANK = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}


class LogPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_entries: list[tuple[str, str, str]] = []  # (level, agent, message)
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Toolbar
        toolbar = QFrame()
        toolbar.setFixedHeight(44)
        toolbar.setStyleSheet("background:#161b22;border-bottom:1px solid #30363d;")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(16, 6, 16, 6)
        tb_layout.setSpacing(12)

        lbl = QLabel("Filter level:")
        lbl.setStyleSheet("color:#8b949e;font-size:11px;")
        tb_layout.addWidget(lbl)

        self._level_combo = QComboBox()
        self._level_combo.addItems(["ALL", "INFO", "WARNING", "ERROR"])
        self._level_combo.setFixedWidth(110)
        self._level_combo.setStyleSheet("""
            QComboBox { background:#1f2937;color:#e6edf3;border:1px solid #30363d;
                        border-radius:4px;padding:2px 8px;font-size:11px; }
            QComboBox QAbstractItemView { background:#161b22;color:#e6edf3;border:1px solid #30363d; }
        """)
        # Re-render existing lines when filter changes
        self._level_combo.currentIndexChanged.connect(self._on_filter_changed)
        tb_layout.addWidget(self._level_combo)

        tb_layout.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedSize(60, 26)
        clear_btn.setStyleSheet("""
            QPushButton { background:#1f2937;color:#8b949e;border:1px solid #30363d;
                          border-radius:4px;font-size:10px; }
            QPushButton:hover { color:#e6edf3; }
        """)
        clear_btn.clicked.connect(self._clear)
        tb_layout.addWidget(clear_btn)

        self._count_label = QLabel("0 lines")
        self._count_label.setStyleSheet("color:#8b949e;font-size:10px;")
        tb_layout.addWidget(self._count_label)

        outer.addWidget(toolbar)

        # Log view
        self._log = LogView()
        outer.addWidget(self._log, stretch=1)

    def append(self, level: str, agent: str, message: str):
        """Thread-safe — called from any thread via signal."""
        self._all_entries.append((level, agent, message))
        self._count_label.setText(f"{len(self._all_entries):,} lines")
        if self._passes_filter(level):
            self._log.append_log(level, agent, message)

    def _passes_filter(self, level: str) -> bool:
        selected = self._level_combo.currentText()
        if selected == "ALL":
            return True
        return LEVEL_RANK.get(level, 0) >= LEVEL_RANK.get(selected, 0)

    def _on_filter_changed(self):
        """Re-render all stored entries through the new filter."""
        self._log.clear_log()
        for level, agent, message in self._all_entries:
            if self._passes_filter(level):
                self._log.append_log(level, agent, message)

    def _clear(self):
        self._all_entries.clear()
        self._log.clear_log()
        self._count_label.setText("0 lines")
