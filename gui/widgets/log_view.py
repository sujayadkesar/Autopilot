"""
LogView — performant QPlainTextEdit with:
  - Max 50k lines (Qt ring buffer via setMaximumBlockCount)
  - Severity-coloured text
  - Tail-follow toggle
  - Batch appends via QTimer to avoid per-line repaint
"""

from __future__ import annotations

import queue
import threading
from typing import Optional

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit, QWidget

LEVEL_COLORS = {
    "ERROR":   "#ff4444",
    "WARNING": "#ffaa00",
    "INFO":    "#8b949e",
    "DEBUG":   "#444d56",
}
AGENT_COLORS = {
    "registry":              "#58a6ff",
    "prefetch_amcache_mft":  "#3fb950",
    "usn_lnk_mru":           "#d2a8ff",
    "event_logs":            "#ffa657",
    "orchestrator":          "#f0883e",
}


class LogView(QPlainTextEdit):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(50_000)
        self.setFont(QFont("Consolas", 9))
        self.setStyleSheet("""
            QPlainTextEdit {
                background: #0d1117;
                color: #8b949e;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        self._tail = True
        self._queue: queue.Queue = queue.Queue()
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    def append_log(self, level: str, agent: str, message: str):
        """Thread-safe: called from any thread."""
        self._queue.put((level, agent, message))

    def clear_log(self):
        """Clear the view and drain any pending queue entries."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except Exception:
                break
        self.clear()

    def set_tail(self, enabled: bool):
        self._tail = enabled

    def _drain(self):
        """Drain ≤200 lines per timer tick (100ms) for smooth UI."""
        if self._queue.empty():
            return
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        count = 0
        while not self._queue.empty() and count < 200:
            level, agent, message = self._queue.get_nowait()
            fmt = QTextCharFormat()
            color = LEVEL_COLORS.get(level, "#8b949e")
            fmt.setForeground(QColor(color))
            cursor.insertText(f"[{level:<8}] ", fmt)
            agent_fmt = QTextCharFormat()
            agent_fmt.setForeground(QColor(AGENT_COLORS.get(agent, "#58a6ff")))
            cursor.insertText(f"[{agent}] ", agent_fmt)
            msg_fmt = QTextCharFormat()
            msg_fmt.setForeground(QColor(LEVEL_COLORS.get(level, "#c9d1d9")))
            cursor.insertText(message + "\n", msg_fmt)
            count += 1
        if self._tail:
            self.moveCursor(QTextCursor.MoveOperation.End)
