"""
Qt signals for the pipeline worker.
All heavy work happens on QThread — UI is updated via these signals on the main thread.
"""

from PySide6.QtCore import QObject, Signal


class PipelineSignals(QObject):
    # stage events
    stage_started = Signal(str, str)          # agent, stage
    stage_progress = Signal(str, str, float, str)  # agent, stage, pct, msg
    stage_done = Signal(str, str, float)      # agent, stage, elapsed_s
    stage_error = Signal(str, str, str)       # agent, stage, error_msg

    # finding
    finding_added = Signal(str, int, str)     # agent, count, severity

    # log
    log_line = Signal(str, str, str)          # level, agent, message

    # pipeline lifecycle
    global_start = Signal()
    global_done = Signal(str, str, str, str)  # report_path, quick, formal, comprehensive
    pipeline_error = Signal(str)              # fatal error message
