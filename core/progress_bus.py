"""
ProgressBus — thread-safe event bus for pipeline progress.

Designed to work with or without PySide6:
  - With Qt: subclass QtProgressBus (in gui/workers/signals.py) which wraps
    this with Qt signals so GUI slots receive updates on the main thread.
  - Without Qt (CLI): subscribe plain Python callables.

Events emitted:
  stage_started(agent, stage)          stage ∈ extract|parse|analyze|report|final
  stage_progress(agent, stage, pct, msg)
  stage_done(agent, stage, elapsed_s)
  stage_error(agent, stage, error_msg)
  finding_added(agent, count_so_far, severity)
  log_line(level, agent, message)      level ∈ DEBUG|INFO|WARNING|ERROR
  global_done(report_path)
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional


class ProgressBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: List[Callable[..., None]] = []
        self._stage_starts: Dict[str, float] = {}

    # ── subscription ──────────────────────────────────────────────────────

    def subscribe(self, fn: Callable[..., None]) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def _emit(self, event: str, **kwargs: Any) -> None:
        kwargs["event"] = event
        with self._lock:
            subscribers = list(self._subscribers)
        for fn in subscribers:
            try:
                fn(**kwargs)
            except Exception:
                pass

    # ── high-level helpers (called by agents / orchestrator) ───────────────

    def stage_started(self, agent: str, stage: str) -> None:
        key = f"{agent}:{stage}"
        self._stage_starts[key] = time.time()
        self._emit("stage_started", agent=agent, stage=stage)
        self.log("INFO", agent, f"[{stage.upper()}] started")

    def stage_progress(self, agent: str, stage: str, pct: float, msg: str = "") -> None:
        self._emit("stage_progress", agent=agent, stage=stage, pct=pct, msg=msg)

    def stage_done(self, agent: str, stage: str) -> None:
        key = f"{agent}:{stage}"
        elapsed = time.time() - self._stage_starts.get(key, time.time())
        self._emit("stage_done", agent=agent, stage=stage, elapsed=round(elapsed, 1))
        self.log("INFO", agent, f"[{stage.upper()}] done in {elapsed:.1f}s")

    def stage_error(self, agent: str, stage: str, error_msg: str) -> None:
        self._emit("stage_error", agent=agent, stage=stage, error_msg=error_msg)
        self.log("ERROR", agent, f"[{stage.upper()}] ERROR: {error_msg}")

    def finding_added(self, agent: str, count: int, severity: str) -> None:
        self._emit("finding_added", agent=agent, count=count, severity=severity)

    def log(self, level: str, agent: str, message: str) -> None:
        self._emit("log_line", level=level, agent=agent, message=message)

    def global_done(self, report_path: str) -> None:
        self._emit("global_done", report_path=report_path)
        self.log("INFO", "orchestrator", f"Pipeline complete → {report_path}")

    def global_start(self) -> None:
        self._emit("global_start")
        self.log("INFO", "orchestrator", "Pipeline starting")
