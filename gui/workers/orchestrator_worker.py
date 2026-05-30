"""
OrchestratorWorker — runs the pipeline on a QThread.
Bridges ProgressBus events to Qt signals (main thread safe).
"""

from __future__ import annotations

from PySide6.QtCore import QThread

from core.case_context import CaseContext
from core.progress_bus import ProgressBus

from .signals import PipelineSignals


class OrchestratorWorker(QThread):
    def __init__(self, ctx: CaseContext, skip_llm: bool = False, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.skip_llm = skip_llm
        self.signals = PipelineSignals()
        self._progress = self._make_progress_bus()
        self._cancelled = False
        self._result = None

    def _make_progress_bus(self) -> ProgressBus:
        bus = ProgressBus()
        sig = self.signals

        def on_event(**kwargs):
            if self._cancelled:
                return
            event = kwargs.get("event")
            try:
                if event == "stage_started":
                    sig.stage_started.emit(kwargs["agent"], kwargs["stage"])
                elif event == "stage_progress":
                    sig.stage_progress.emit(kwargs["agent"], kwargs["stage"], float(kwargs.get("pct", 0)), str(kwargs.get("msg", "")))
                elif event == "stage_done":
                    sig.stage_done.emit(kwargs["agent"], kwargs["stage"], float(kwargs.get("elapsed", 0)))
                elif event == "stage_error":
                    sig.stage_error.emit(kwargs["agent"], kwargs["stage"], str(kwargs.get("error_msg", "")))
                elif event == "finding_added":
                    sig.finding_added.emit(kwargs["agent"], int(kwargs.get("count", 0)), str(kwargs.get("severity", "")))
                elif event == "log_line":
                    sig.log_line.emit(str(kwargs.get("level", "INFO")), str(kwargs.get("agent", "")), str(kwargs.get("message", "")))
                elif event == "global_start":
                    sig.global_start.emit()
                elif event == "global_done":
                    rp = str(kwargs.get("report_path", ""))
                    qp = str(getattr(self._result, "quick_report_path", "") or "")
                    fp = str(getattr(self._result, "formal_report_path", "") or "")
                    cp = str(getattr(self._result, "comprehensive_report_path", "") or "")
                    sig.global_done.emit(rp, qp, fp, cp)
            except RuntimeError:
                pass  # Qt object already deleted

        bus.subscribe(on_event)
        return bus

    def cancel(self):
        self._cancelled = True

    def run(self):
        from orchestrator import OllamaUnavailable, run_pipeline
        from core.fsutil import MountUnavailableError
        try:
            self._result = run_pipeline(self.ctx, self._progress, skip_llm=self.skip_llm)
        except MountUnavailableError as e:
            # The mount pre-flight failed — show a focused error, no traceback
            try:
                self.signals.pipeline_error.emit(f"Forensic image not accessible.\n\n{e}")
            except RuntimeError:
                pass
        except OllamaUnavailable as e:
            try:
                self.signals.pipeline_error.emit(str(e))
            except RuntimeError:
                pass
        except Exception as e:
            import traceback
            try:
                self.signals.pipeline_error.emit(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")
            except RuntimeError:
                pass
