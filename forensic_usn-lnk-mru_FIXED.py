#!/usr/bin/env python3
"""
forensic_pipeline.py
Windows forensic artifact discovery and parsing pipeline.
Orchestrates EZ Tools (RECmd, MFTECmd, LECmd) + Hindsight
to validate artifact presence and produce parsed outputs.

Author  : DFIR Automation Framework
Version : 2.1.0
Python  : 3.9+
"""

# ─────────────────────────────────────────────
#  STANDARD LIBRARY
# ─────────────────────────────────────────────
import argparse
import glob
import logging
import os
import platform
import queue
import shutil
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ─────────────────────────────────────────────
#  THIRD-PARTY (Rich)
# ─────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskID,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("[FATAL] 'rich' library not found. Install via: pip install rich")
    sys.exit(1)

# ═══════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════

TOOL_NAMES = {
    "recmd":      "RECmd.exe",
    "mftecmd":    "MFTECmd.exe",
    "lecmd":      "LECmd.exe",
    "hindsight":  "hindsight.exe",
}

# EZ Tools batch file for MRU/Registry parsing (ships with RegistryExplorer)
# Place this .reb file in your tools directory.
BATCH_FILE_NAME = "RECmd_Batch_MC.reb"

# Browser profile relative paths for auto-discovery
BROWSER_PROFILES = {
    "Chrome": r"AppData\Local\Google\Chrome\User Data",
    "Edge":   r"AppData\Local\Microsoft\Edge\User Data",
    # Firefox handled separately (different profile structure)
}

# Retry config
MAX_RETRIES     = 3
RETRY_DELAY_SEC = 2.0

RETRY_ABORT_MARKERS = (
    "access denied",
    "file not found",
    "invalid choice",
    "not found. exiting",
    "unrecognized arguments",
    "unicodeencodeerror",
)

RECMD_BATCH_CANDIDATES = (
    "DFIRBatch.reb",
    BATCH_FILE_NAME,
)

BROWSER_OUTPUT_FORMATS: Tuple[Tuple[str, str], ...] = (
    ("xlsx", "xlsx"),
    ("jsonl", "jsonl"),
)

USN_J_CANDIDATES = (
    Path(r"$Extend\$UsnJrnl:$J:$DATA"),
    Path(r"$Extend\$J"),
)

USN_MFT_CANDIDATES = (
    Path(r"$MFT"),
)

# Pipeline phases
PHASE_EXTRACTION = "Extraction"
PHASE_PARSING    = "Parsing"

# ═══════════════════════════════════════════════════════
#  ENUMS & DATA CLASSES
# ═══════════════════════════════════════════════════════

class ArtifactStatus(Enum):
    PENDING  = auto()
    RUNNING  = auto()
    DONE     = auto()
    EMPTY    = auto()
    FAILED   = auto()
    SKIPPED  = auto()


@dataclass
class ArtifactResult:
    """
    Immutable status record for a single artifact task.
    Thread-safe writes are ensured by the caller holding _table_lock.
    """
    key:         str
    name:        str
    phase:       str
    status:      ArtifactStatus = ArtifactStatus.PENDING
    start_time:  Optional[float] = None
    end_time:    Optional[float] = None
    returncode:  Optional[int]  = None
    stdout:      str            = ""
    stderr:      str            = ""
    error_msg:   str            = ""
    cmd:         str            = ""   # full command string for audit trail

    @property
    def elapsed(self) -> str:
        if self.start_time and self.end_time:
            return f"{self.end_time - self.start_time:.1f}s"
        return "-"

    @property
    def status_rich(self) -> Text:
        """Returns a Rich Text object with colour-coded status."""
        colours = {
            ArtifactStatus.PENDING:  "yellow",
            ArtifactStatus.RUNNING:  "cyan",
            ArtifactStatus.DONE:     "green",
            ArtifactStatus.EMPTY:    "yellow",
            ArtifactStatus.FAILED:   "red",
            ArtifactStatus.SKIPPED:  "dim",
        }
        labels = {
            ArtifactStatus.PENDING:  "PENDING",
            ArtifactStatus.RUNNING:  "RUNNING",
            ArtifactStatus.DONE:     "DONE",
            ArtifactStatus.EMPTY:    "EMPTY",
            ArtifactStatus.FAILED:   "FAILED",
            ArtifactStatus.SKIPPED:  "SKIPPED",
        }
        return Text(labels[self.status], style=colours[self.status])


@dataclass(frozen=True)
class PipelineConfig:
    recmd_batch: Optional[Path] = None
    usn_j_path: Optional[Path] = None
    usn_mft_path: Optional[Path] = None


# ═══════════════════════════════════════════════════════
#  CUSTOM EXCEPTIONS
# ═══════════════════════════════════════════════════════

class ForensicBaseError(Exception):
    """Base class for all pipeline exceptions."""

class ToolNotFoundError(ForensicBaseError):
    """Raised when a required executable cannot be located."""

class ArtifactNotFoundError(ForensicBaseError):
    """Raised when a forensic artifact path does not exist on the target."""

class ArtifactEmptyError(ForensicBaseError):
    """Raised when an artifact category is genuinely absent on the source."""

class ArtifactAccessDeniedError(ForensicBaseError):
    """Raised when a required artifact exists but cannot be accessed."""

class ExecutionError(ForensicBaseError):
    """Raised when execution or output validation fails after retries."""

    def __init__(
        self,
        message: str,
        *,
        returncode: Optional[int] = None,
        stdout: str = "",
        stderr: str = "",
    ):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ═══════════════════════════════════════════════════════
#  LOGGING SETUP
# ═══════════════════════════════════════════════════════

_console = Console()

def setup_logging(log_dir: Path) -> logging.Logger:
    """
    Configure dual-sink logging:
      • Rich console handler (INFO+)
      • Rotating file handler  (DEBUG+) → logs/pipeline.log
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "pipeline.log"

    logger = logging.getLogger("ForensicPipeline")
    logger.setLevel(logging.DEBUG)

    # Console sink – INFO only (Rich prettifies output)
    rich_handler = RichHandler(
        console=_console,
        rich_tracebacks=True,
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(logging.INFO)

    # File sink – DEBUG (full audit trail)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(threadName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(rich_handler)
    logger.addHandler(file_handler)
    return logger


# ═══════════════════════════════════════════════════════
#  TOOL RUNNER
# ═══════════════════════════════════════════════════════

class ToolRunner:
    """
    Centralised subprocess executor.

    Features:
      • Captures stdout, stderr, and return code
      • Configurable retry with exponential back-off
      • Writes per-tool debug output to the audit log
      • Never silently swallows failures
    """

    def __init__(self, logger: logging.Logger, retries: int = MAX_RETRIES):
        self._log     = logger
        self._retries = retries

    @staticmethod
    def _contains_marker(text: str, markers: Sequence[str]) -> bool:
        lowered = text.lower()
        return any(marker.lower() in lowered for marker in markers)

    @staticmethod
    def _snapshot_outputs(paths: Sequence[Path]) -> Dict[Path, Tuple[bool, Optional[int], Optional[int]]]:
        snapshots: Dict[Path, Tuple[bool, Optional[int], Optional[int]]] = {}
        for path in paths:
            try:
                stat = path.stat()
            except FileNotFoundError:
                snapshots[path] = (False, None, None)
            else:
                snapshots[path] = (True, stat.st_mtime_ns, stat.st_size)
        return snapshots

    @staticmethod
    def _validate_outputs(
        paths: Sequence[Path],
        snapshots: Dict[Path, Tuple[bool, Optional[int], Optional[int]]],
    ) -> Optional[str]:
        if not paths:
            return None

        missing: List[str] = []
        stale: List[str] = []
        for path in paths:
            try:
                stat = path.stat()
            except FileNotFoundError:
                missing.append(str(path))
                continue

            existed, mtime_ns, size = snapshots.get(path, (False, None, None))
            if existed and stat.st_mtime_ns == mtime_ns and stat.st_size == size:
                stale.append(str(path))

        if missing:
            return "Expected output file(s) missing: " + ", ".join(missing)
        if stale:
            return "Expected output file(s) were not updated: " + ", ".join(stale)
        return None

    def run(
        self,
        cmd: List[str],
        artifact_name: str,
        timeout: int = 600,
        expected_outputs: Optional[Sequence[Path]] = None,
        env_overrides: Optional[Dict[str, str]] = None,
        failure_markers: Optional[Sequence[str]] = None,
        no_retry_markers: Sequence[str] = RETRY_ABORT_MARKERS,
        retries: Optional[int] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute *cmd* up to the configured retry limit.

        Returns (returncode, stdout, stderr).
        Raises ExecutionError if all attempts fail.
        """
        cmd_str = " ".join(f'"{c}"' if " " in str(c) else str(c) for c in cmd)
        self._log.debug("[%s] CMD → %s", artifact_name, cmd_str)

        output_paths = [Path(path) for path in (expected_outputs or [])]
        output_snapshots = self._snapshot_outputs(output_paths)
        effective_retries = max(1, retries if retries is not None else self._retries)
        extra_env = None
        if env_overrides:
            extra_env = os.environ.copy()
            extra_env.update(env_overrides)

        last_exc: Optional[ExecutionError] = None
        for attempt in range(1, effective_retries + 1):
            retryable = True
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=extra_env,
                    # Windows: hide console window for sub-processes
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if platform.system() == "Windows"
                        else 0
                    ),
                )
                self._log.debug(
                    "[%s] Attempt %d/%d → RC=%d",
                    artifact_name, attempt, effective_retries, proc.returncode,
                )
                if proc.stdout:
                    self._log.debug("[%s] STDOUT: %s", artifact_name, proc.stdout[:2000])
                if proc.stderr:
                    self._log.debug("[%s] STDERR: %s", artifact_name, proc.stderr[:2000])

                combined_output = "\n".join(part for part in (proc.stdout, proc.stderr) if part)

                if proc.returncode == 0:
                    if failure_markers and self._contains_marker(combined_output, failure_markers):
                        last_exc = ExecutionError(
                            f"[{artifact_name}] Process reported a failure marker despite RC=0.",
                            returncode=proc.returncode,
                            stdout=proc.stdout,
                            stderr=proc.stderr,
                        )
                        self._log.warning(str(last_exc))
                    else:
                        output_issue = self._validate_outputs(output_paths, output_snapshots)
                        if output_issue is None:
                            return proc.returncode, proc.stdout, proc.stderr
                        last_exc = ExecutionError(
                            f"[{artifact_name}] {output_issue}",
                            returncode=proc.returncode,
                            stdout=proc.stdout,
                            stderr=proc.stderr,
                        )
                        self._log.warning(str(last_exc))

                    retryable = not self._contains_marker(combined_output, no_retry_markers)
                    if not retryable:
                        break
                    if attempt < effective_retries:
                        delay = RETRY_DELAY_SEC * attempt
                        self._log.info("[%s] Retrying in %.1fs …", artifact_name, delay)
                        time.sleep(delay)
                    continue

                last_exc = ExecutionError(
                    f"[{artifact_name}] RC={proc.returncode} on attempt {attempt}. "
                    f"STDERR: {proc.stderr[:500]}",
                    returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                )
                self._log.warning(str(last_exc))
                retryable = not self._contains_marker(combined_output, no_retry_markers)
                # FIX 3: retryable was computed but never acted upon for the
                # non-zero RC branch — the loop kept retrying even for terminal
                # errors (e.g. UnicodeEncodeError which is in RETRY_ABORT_MARKERS).
                # This caused Browser/hindsight to exhaust all 3 attempts uselessly.
                if not retryable:
                    break

            except subprocess.TimeoutExpired as exc:
                last_exc = ExecutionError(
                    f"[{artifact_name}] Timed out after {timeout}s on attempt {attempt}",
                    stdout=exc.stdout or "",
                    stderr=exc.stderr or "",
                )
                self._log.warning(
                    "[%s] Timeout on attempt %d/%d", artifact_name, attempt, effective_retries
                )
            except FileNotFoundError as exc:
                raise ToolNotFoundError(
                    f"Executable not found: {cmd[0]}"
                ) from exc
            except Exception as exc:
                last_exc = ExecutionError(
                    f"[{artifact_name}] Unexpected error on attempt {attempt}: {exc}"
                )
                self._log.warning(
                    "[%s] Unexpected error on attempt %d/%d: %s",
                    artifact_name, attempt, effective_retries, exc,
                )

            if attempt < effective_retries and retryable:
                delay = RETRY_DELAY_SEC * attempt
                self._log.info("[%s] Retrying in %.1fs …", artifact_name, delay)
                time.sleep(delay)

        raise ExecutionError(
            f"[{artifact_name}] All {effective_retries} attempt(s) failed. "
            f"Last error: {last_exc}",
            returncode=last_exc.returncode if last_exc else None,
            stdout=last_exc.stdout if last_exc else "",
            stderr=last_exc.stderr if last_exc else "",
        ) from last_exc


# ═══════════════════════════════════════════════════════
#  PATH DISCOVERY HELPERS
# ═══════════════════════════════════════════════════════

class PathCache:
    """
    Thread-safe in-memory cache for discovered filesystem paths.
    Prevents redundant disk scans across concurrent workers.
    """

    def __init__(self):
        self._lock  = threading.Lock()
        self._store: Dict[str, List[Path]] = {}

    def get(self, key: str) -> Optional[List[Path]]:
        with self._lock:
            return self._store.get(key)

    def set(self, key: str, paths: List[Path]) -> None:
        with self._lock:
            self._store[key] = paths


_path_cache = PathCache()


def discover_paths(
    base: Path,
    pattern: str,
    cache_key: Optional[str] = None,
) -> List[Path]:
    """
    Glob *pattern* under *base*.  Results are cached by *cache_key*.
    Returns an empty list (never raises) if nothing found.
    """
    key = cache_key or f"{base}::{pattern}"
    cached = _path_cache.get(key)
    if cached is not None:
        return cached

    results = [Path(p) for p in glob.glob(str(base / pattern), recursive=True)]
    _path_cache.set(key, results)
    return results


def ensure_dir(path: Path) -> Path:
    """Create directory tree safely; return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def require_tool(tools_dir: Path, tool_key: str) -> Path:
    """
    Resolve an EZ Tool executable.  Raises ToolNotFoundError if absent.
    """
    name = TOOL_NAMES[tool_key]
    exe  = tools_dir / name
    if not exe.is_file():
        raise ToolNotFoundError(
            f"Required tool '{name}' not found in tools directory: {tools_dir}\n"
            f"  → Expected path: {exe}"
        )
    return exe


def resolve_optional_path(path: Optional[Path], base_dir: Path) -> Optional[Path]:
    if path is None:
        return None
    return path if path.is_absolute() else base_dir / path


def probe_path(path: Path) -> Tuple[str, Optional[str]]:
    try:
        path.stat()
    except PermissionError:
        return "access_denied", None
    except FileNotFoundError:
        return "missing", None
    except OSError as exc:
        return "error", str(exc)
    return "exists", None


def resolve_recmd_batch(tools_dir: Path, explicit_batch: Optional[Path] = None) -> Path:
    candidates: List[Path] = []
    explicit_candidate = resolve_optional_path(explicit_batch, tools_dir)
    if explicit_candidate is not None:
        candidates.append(explicit_candidate)
    else:
        for parent in (tools_dir, tools_dir / "BatchExamples"):
            for batch_name in RECMD_BATCH_CANDIDATES:
                candidates.append(parent / batch_name)

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    searched = "\n".join(f"  - {candidate}" for candidate in candidates)
    raise ToolNotFoundError(
        "RECmd batch file not found.\n"
        f"Searched:\n{searched}\n"
        "  → Supply --recmd-batch to override the lookup path."
    )


# ═══════════════════════════════════════════════════════
#  ARTIFACT HANDLERS
# ═══════════════════════════════════════════════════════

class ArtifactHandler:
    """
    Base class for per-artifact logic.
    Each subclass implements:
      • extract() → copies/extracts raw artifacts from the target
      • parse()   → runs an EZ Tool / Hindsight against the raw artifact
    """

    NAME: str = "BaseArtifact"

    def __init__(
        self,
        drive: Path,
        output_root: Path,
        tools_dir: Path,
        config: PipelineConfig,
        runner: ToolRunner,
        logger: logging.Logger,
    ):
        self._drive      = drive
        self._output     = output_root
        self._tools      = tools_dir
        self._config     = config
        self._runner     = runner
        self._log        = logger

    def extract(self) -> None:
        raise NotImplementedError

    def parse(self) -> None:
        raise NotImplementedError

    def _out_dir(self, subdir: str) -> Path:
        return ensure_dir(self._output / "parsed_artifact" / subdir)


# ──────────────────────────────────────────────────────
#  MRU  (RECmd – NTUSER.DAT + UsrClass.dat)
# ──────────────────────────────────────────────────────

class MRUHandler(ArtifactHandler):
    """
    Parses OpenSaveMRU and RecentDocs from all user registry hives
    using RECmd.exe with a batch file.

    Command pattern:
        RECmd.exe -f <hive> --bn <batch.reb> --nl true
                  --csv <outdir> --csvf <filename> -q
    """

    NAME = "MRU"

    # Hive filenames to target
    HIVE_PATTERNS = [
        r"Users\*\NTUSER.DAT",
        r"Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat",
    ]

    def _discover_hives(self) -> List[Path]:
        hives: List[Path] = []
        for pat in self.HIVE_PATTERNS:
            hits = discover_paths(self._drive, pat, cache_key=f"MRU::{pat}")
            if hits:
                self._log.debug("[MRU] Found %d hive(s) matching '%s'", len(hits), pat)
                hives.extend(hits)
        return hives

    def extract(self) -> None:
        self._hives = self._discover_hives()
        self._batch_file = resolve_recmd_batch(self._tools, self._config.recmd_batch)
        if not self._hives:
            raise ArtifactEmptyError(
                f"[MRU] No registry hives found under {self._drive}"
            )
        self._log.debug("[MRU] Using RECmd batch file: %s", self._batch_file)

    def parse(self) -> None:
        exe = require_tool(self._tools, "recmd")
        out_dir = self._out_dir("MRU")
        batch_file = getattr(self, "_batch_file", None) or resolve_recmd_batch(
            self._tools, self._config.recmd_batch
        )
        all_hives = getattr(self, "_hives", None) or self._discover_hives()

        if not all_hives:
            raise ArtifactEmptyError("[MRU] No registry hives available for parsing.")

        failures: List[str] = []
        for idx, hive in enumerate(all_hives):
            # Derive a unique output filename per hive (user account name)
            # e.g. NTUSER_jdoe.csv  or  UsrClass_jdoe.csv
            parts = hive.parts
            try:
                # Extract the username directory component
                users_idx = next(
                    i for i, p in enumerate(parts)
                    if p.lower() == "users"
                )
                username = parts[users_idx + 1]
            except (StopIteration, IndexError):
                username = f"user{idx}"

            stem     = hive.stem          # NTUSER or UsrClass
            csv_name = f"MRU_{stem}_{username}.csv"
            output_csv = out_dir / csv_name

            cmd = [
                str(exe),
                "-f", str(hive),
                "--bn", str(batch_file),
                "--nl", "true",           # do not load linked hives (forensic image)
                "--csv", str(out_dir),
                "--csvf", csv_name,
                # FIX 1: REMOVED "-q" — RECmd v2.1.0 does NOT support this flag.
                # Passing -q causes RECmd to print help/usage (RC=0) and exit
                # WITHOUT processing the hive, so no CSV is ever produced.
                # LECmd supports -q; RECmd does not. Do not confuse the two.
            ]
            try:
                self._runner.run(
                    cmd,
                    artifact_name=f"MRU-{username}-{stem}",
                    expected_outputs=[output_csv],
                )
                self._log.info("[MRU] Parsed hive → %s/%s", out_dir.name, csv_name)
            except ExecutionError as exc:
                failures.append(f"{hive}: {exc}")

        if failures:
            raise ExecutionError(
                "[MRU] One or more hives failed to parse:\n  - "
                + "\n  - ".join(failures)
            )


# ──────────────────────────────────────────────────────
#  USN Journal  (MFTECmd – $J + $MFT)
# ──────────────────────────────────────────────────────

class USNJournalHandler(ArtifactHandler):
    """
    Parses $UsnJrnl:$J using MFTECmd with $MFT for filename resolution.

    Command pattern:
        MFTECmd.exe -f <$J path> -m <$MFT path>
                    --csv <outdir> --csvf usnjrnl.csv
    """

    NAME = "USN_Journal"

    def _resolve_required_path(
        self,
        label: str,
        explicit_path: Optional[Path],
        defaults: Sequence[Path],
    ) -> Path:
        candidates = []
        explicit_candidate = resolve_optional_path(explicit_path, self._drive)
        if explicit_candidate is not None:
            candidates.append(explicit_candidate)
        else:
            candidates.extend(self._drive / candidate for candidate in defaults)

        access_denied: List[str] = []
        errors: List[str] = []
        for candidate in candidates:
            state, detail = probe_path(candidate)
            if state == "exists":
                return candidate
            if state == "access_denied":
                access_denied.append(str(candidate))
            elif state == "error":
                errors.append(f"{candidate} ({detail})")

        if access_denied:
            raise ArtifactAccessDeniedError(
                f"[USN] Access denied while probing {label}: " + ", ".join(access_denied)
            )

        details = ""
        if errors:
            details = "\n  Additional probe errors:\n  - " + "\n  - ".join(errors)
        raise ArtifactNotFoundError(
            f"[USN] Required {label} artifact not found.\n"
            + "\n".join(f"  - {candidate}" for candidate in candidates)
            + details
        )

    def _resolve_optional_path(
        self,
        label: str,
        explicit_path: Optional[Path],
        defaults: Sequence[Path],
    ) -> Optional[Path]:
        candidates = []
        explicit_candidate = resolve_optional_path(explicit_path, self._drive)
        if explicit_candidate is not None:
            candidates.append(explicit_candidate)
        else:
            candidates.extend(self._drive / candidate for candidate in defaults)

        access_denied: List[str] = []
        errors: List[str] = []
        for candidate in candidates:
            state, detail = probe_path(candidate)
            if state == "exists":
                return candidate
            if state == "access_denied":
                access_denied.append(str(candidate))
            elif state == "error":
                errors.append(f"{candidate} ({detail})")

        if explicit_candidate is not None:
            if access_denied:
                raise ArtifactAccessDeniedError(
                    f"[USN] Access denied while probing {label}: " + ", ".join(access_denied)
                )
            raise ArtifactNotFoundError(
                f"[USN] Explicit {label} path was not found: {explicit_candidate}"
            )

        if access_denied:
            self._log.warning(
                "[USN] %s exists but is not accessible; continuing without it: %s",
                label,
                ", ".join(access_denied),
            )
        if errors:
            self._log.warning(
                "[USN] Encountered probe errors while looking for %s: %s",
                label,
                "; ".join(errors),
            )
        return None

    def extract(self) -> None:
        self._resolved_j_path = self._resolve_required_path(
            "$UsnJrnl:$J",
            self._config.usn_j_path,
            USN_J_CANDIDATES,
        )
        self._resolved_mft_path = self._resolve_optional_path(
            "$MFT",
            self._config.usn_mft_path,
            USN_MFT_CANDIDATES,
        )
        self._log.debug("[USN] Located $J → %s", self._resolved_j_path)
        if self._resolved_mft_path is not None:
            self._log.debug("[USN] Located $MFT → %s", self._resolved_mft_path)
        else:
            self._log.warning(
                "[USN] $MFT not available; MFTECmd will parse $J without filename enrichment."
            )

    def parse(self) -> None:
        exe = require_tool(self._tools, "mftecmd")
        j_path = getattr(self, "_resolved_j_path", None) or self._resolve_required_path(
            "$UsnJrnl:$J",
            self._config.usn_j_path,
            USN_J_CANDIDATES,
        )
        mft_path = getattr(self, "_resolved_mft_path", None)
        if mft_path is None:
            mft_path = self._resolve_optional_path(
                "$MFT",
                self._config.usn_mft_path,
                USN_MFT_CANDIDATES,
            )
        out_dir = self._out_dir("USN_Journal")
        output_csv = out_dir / "usnjrnl.csv"

        cmd = [
            str(exe),
            "-f", str(j_path),           # -f = target file ($J ADS)
            "--csv", str(out_dir),
            "--csvf", "usnjrnl.csv",
        ]
        if mft_path is not None:
            cmd[3:3] = ["-m", str(mft_path)]
        self._runner.run(
            cmd,
            artifact_name="USN_Journal",
            expected_outputs=[output_csv],
            failure_markers=("not found. exiting",),
        )
        self._log.info("[USN] USN Journal parsed → %s/usnjrnl.csv", out_dir.name)


# ──────────────────────────────────────────────────────
#  LNK Files  (LECmd)
# ──────────────────────────────────────────────────────

class LNKHandler(ArtifactHandler):
    """
    Recursively parses all .lnk files under user Recent folders using LECmd.

    Command pattern:
        LECmd.exe -d <recent_dir> --csv <outdir> --csvf lnk_<user>.csv -q
    """

    NAME = "LNK_Files"

    RECENT_PATTERN = r"Users\*\AppData\Roaming\Microsoft\Windows\Recent"

    def _discover_recent_dirs(self) -> List[Path]:
        return discover_paths(
            self._drive, self.RECENT_PATTERN, cache_key="LNK::recent"
        )

    def extract(self) -> None:
        self._recent_dirs = self._discover_recent_dirs()
        if not self._recent_dirs:
            raise ArtifactEmptyError(
                f"[LNK] No Recent folders found under {self._drive}\\"
                r"Users\*\AppData\Roaming\Microsoft\Windows\Recent"
            )
        self._log.debug("[LNK] Found %d Recent folder(s)", len(self._recent_dirs))

    def parse(self) -> None:
        exe     = require_tool(self._tools, "lecmd")
        out_dir = self._out_dir("LNK_Files")
        paths   = getattr(self, "_recent_dirs", None) or self._discover_recent_dirs()

        if not paths:
            raise ArtifactEmptyError("[LNK] No Recent folders to parse.")

        failures: List[str] = []
        for recent_dir in paths:
            # Extract username for namespacing the output file
            parts = recent_dir.parts
            try:
                users_idx = next(
                    i for i, p in enumerate(parts)
                    if p.lower() == "users"
                )
                username = parts[users_idx + 1]
            except (StopIteration, IndexError):
                username = recent_dir.parent.parent.parent.name

            csv_name = f"lnk_{username}.csv"
            output_csv = out_dir / csv_name

            cmd = [
                str(exe),
                "-d", str(recent_dir),   # recursive directory mode
                "--csv", str(out_dir),
                "--csvf", csv_name,
                "-q",                    # suppress per-file console output
            ]
            try:
                self._runner.run(
                    cmd,
                    artifact_name=f"LNK-{username}",
                    expected_outputs=[output_csv],
                )
                self._log.info("[LNK] Parsed → %s/%s", out_dir.name, csv_name)
            except ExecutionError as exc:
                # FIX 2: LECmd exits RC=0 with "Found 0 files" when a
                # Recent folder is legitimately empty (e.g. Default user).
                # That is a valid empty-state — skip it, do not mark as FAILED.
                _combined = (exc.stdout or "") + (exc.stderr or "")
                if "found 0 files" in _combined.lower():
                    self._log.info(
                        "[LNK] No .lnk files in %s — empty folder, skipping", recent_dir
                    )
                    continue
                failures.append(f"{recent_dir}: {exc}")

        if failures:
            raise ExecutionError(
                "[LNK] One or more Recent folders failed to parse:\n  - "
                + "\n  - ".join(failures)
            )


# ──────────────────────────────────────────────────────
#  Browser Artifacts  (hindsight.exe)
# ──────────────────────────────────────────────────────

class BrowserHandler(ArtifactHandler):
    """
    Auto-discovers Chrome and Edge profiles and runs hindsight.exe
    against each Default profile directory.

    Hindsight command pattern:
        hindsight.exe -i <profile_default_dir>
                      -o <output_stem>
                      -f xlsx
                      -l <logfile>

    The current CLI documents XLSX as the default output, with JSONL and
    SQLite as supported alternatives. This handler attempts XLSX first,
    then falls back to JSONL if needed.
    """

    NAME = "Browsers"

    def _find_browser_profiles(self) -> List[Tuple[str, str, Path]]:
        """
        Returns list of (browser_name, username, profile_path).
        """
        if hasattr(self, "_profiles") and self._profiles is not None:
            return self._profiles

        profiles: List[Tuple[str, str, Path]] = []

        for browser, rel_path in BROWSER_PROFILES.items():
            pattern = rf"Users\*\{rel_path}"
            user_data_dirs = discover_paths(
                self._drive, pattern, cache_key=f"BROWSER::{browser}"
            )
            for udd in user_data_dirs:
                # Extract username
                parts = udd.parts
                try:
                    users_idx = next(
                        i for i, p in enumerate(parts)
                        if p.lower() == "users"
                    )
                    username = parts[users_idx + 1]
                except (StopIteration, IndexError):
                    username = "unknown"

                # Hindsight targets the 'Default' profile subdirectory
                default_profile = udd / "Default"
                if default_profile.is_dir():
                    profiles.append((browser, username, default_profile))
                else:
                    # Enumerate all profile dirs (Profile 1, Profile 2, …)
                    for entry in udd.iterdir():
                        if entry.is_dir() and (
                            entry.name.lower() == "default"
                            or entry.name.lower().startswith("profile")
                        ):
                            profiles.append((browser, username, entry))

        self._profiles = profiles
        return self._profiles

    def extract(self) -> None:
        self._profiles = self._find_browser_profiles()
        if not self._profiles:
            raise ArtifactEmptyError(
                f"[Browsers] No Chrome/Edge profiles found under {self._drive}\\Users\\"
            )
        self._log.debug("[Browsers] Discovered %d profile(s)", len(self._profiles))

    def parse(self) -> None:
        exe     = require_tool(self._tools, "hindsight")
        out_dir = self._out_dir("Browsers")
        log_dir = ensure_dir(self._output / "logs")
        profiles = getattr(self, "_profiles", None) or self._find_browser_profiles()

        if not profiles:
            raise ArtifactEmptyError("[Browsers] No browser profiles to parse.")

        # FIX 4d: On Windows, set the console output code page to UTF-8 (65001)
        # so that hindsight's internal Rich Win32 renderer encodes characters
        # correctly. Child processes inherit the parent's console code page.
        if platform.system() == "Windows":
            try:
                import ctypes as _ctypes
                _ctypes.windll.kernel32.SetConsoleOutputCP(65001)
                _ctypes.windll.kernel32.SetConsoleCP(65001)
                self._log.debug("[Browsers] Console code page set to UTF-8 (65001)")
            except Exception as _cp_exc:
                self._log.debug("[Browsers] Could not set console code page: %s", _cp_exc)

        failures: List[str] = []
        for browser, username, profile_path in profiles:
            # Build a filesystem-safe stem for output files
            safe_name = f"{browser}_{username}_{profile_path.name}".replace(" ", "_")
            output_stem = out_dir / safe_name
            hs_log = log_dir / f"hindsight_{safe_name}.log"
            profile_errors: List[str] = []
            profile_success = False

            for fmt, suffix in BROWSER_OUTPUT_FORMATS:
                expected_output = out_dir / f"{safe_name}.{suffix}"
                cmd = [
                    str(exe),
                    "-i", str(profile_path),
                    "-o", str(output_stem),
                    "-f", fmt,
                    "-l", str(hs_log),
                ]
                try:
                    self._runner.run(
                        cmd,
                        artifact_name=f"Browser-{browser}-{username}-{profile_path.name}-{fmt}",
                        expected_outputs=[expected_output],
                        env_overrides={
                            "NO_COLOR": "1",
                            # FIX 4b: belt-and-suspenders — prevent Rich from
                            # activating any coloured / special-char output.
                            "FORCE_COLOR": "0",
                            # FIX 4a: replace unmappable chars (e.g. U+25BC ▼)
                            # instead of raising UnicodeEncodeError and crashing.
                            "PYTHONIOENCODING": "utf-8:replace",
                            "PYTHONUTF8": "1",
                            # FIX 4c: keep UTF-8 I/O path in PyInstaller frozen bins.
                            "PYTHONLEGACYWINDOWSSTDIO": "0",
                            "TERM": "dumb",
                        },
                        failure_markers=("unicodeencodeerror",),
                    )
                    self._log.info(
                        "[Browsers] %s profile '%s' (%s) → %s",
                        browser, username, profile_path.name, expected_output.name,
                    )
                    profile_success = True
                    break
                except ExecutionError as exc:
                    profile_errors.append(f"{fmt}: {exc}")
                    self._log.warning(
                        "[Browsers] %s format failed for %s/%s (%s): %s",
                        fmt, browser, username, profile_path.name, exc,
                    )

            if not profile_success:
                failures.append(
                    f"{browser}/{username}/{profile_path.name}: " + " | ".join(profile_errors)
                )

        if failures:
            raise ExecutionError(
                "[Browsers] One or more browser profiles failed to parse:\n  - "
                + "\n  - ".join(failures)
            )


# ═══════════════════════════════════════════════════════
#  RICH UI MANAGER
# ═══════════════════════════════════════════════════════

class UIManager:
    """
    Manages a Rich Live display consisting of:
      • A status table (artifact name | phase | status | elapsed)
      • A dual progress bar (Extraction phase | Parsing phase)
    All mutations are guarded by a threading.Lock.
    """

    def __init__(self, artifact_count: int):
        self._lock         = threading.Lock()
        self._results: Dict[str, ArtifactResult] = {}
        self._completed_keys: set[str] = set()
        self._live: Optional[Live] = None

        # Two phase progress bars
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=_console,
        )
        self._task_extract = self._progress.add_task(
            f"[cyan]{PHASE_EXTRACTION}", total=artifact_count
        )
        self._task_parse = self._progress.add_task(
            f"[magenta]{PHASE_PARSING}", total=artifact_count
        )

    # ── Public API ───────────────────────────────────────

    def register(self, result: ArtifactResult) -> None:
        with self._lock:
            self._results[result.key] = result

    def update(self, key: str, **kwargs) -> None:
        """Update fields on an existing ArtifactResult and advance progress."""
        with self._lock:
            r = self._results.get(key)
            if r is None:
                return

            old_status = r.status
            new_status = kwargs.get("status", r.status)
            for k, v in kwargs.items():
                object.__setattr__(r, k, v)  # dataclass – bypass frozen check if needed

            # Advance the correct progress bar when a task completes or fails
            if (
                old_status not in (ArtifactStatus.DONE, ArtifactStatus.EMPTY,
                                   ArtifactStatus.FAILED, ArtifactStatus.SKIPPED)
                and new_status in (ArtifactStatus.DONE, ArtifactStatus.EMPTY,
                                   ArtifactStatus.FAILED, ArtifactStatus.SKIPPED)
                and key not in self._completed_keys
            ):
                self._completed_keys.add(key)
                if r.phase == PHASE_EXTRACTION:
                    self._progress.advance(self._task_extract)
                else:
                    self._progress.advance(self._task_parse)

    def build_table(self) -> Table:
        """Construct the status table from current result snapshot."""
        table = Table(
            title="[bold]Forensic Pipeline — Artifact Status",
            box=box.ROUNDED,
            border_style="bright_blue",
            show_lines=True,
            expand=True,
        )
        table.add_column("Artifact",  style="bold white",  min_width=18)
        table.add_column("Phase",     style="dim",          min_width=12)
        table.add_column("Status",    min_width=14)
        table.add_column("Elapsed",   justify="right",      min_width=8)
        table.add_column("RC",        justify="center",     min_width=4)

        with self._lock:
            for r in sorted(self._results.values(), key=lambda item: (item.name, item.phase)):
                rc_str = str(r.returncode) if r.returncode is not None else "-"
                table.add_row(
                    r.name,
                    r.phase,
                    r.status_rich,
                    r.elapsed,
                    rc_str,
                )
        return table

    def get_renderable(self):
        """Return a composite renderable (table + progress bars) for Live."""
        from rich.console import Group
        return Group(self.build_table(), self._progress)

    def start(self):
        self._live = Live(
            self.get_renderable(),
            console=_console,
            refresh_per_second=8,
            transient=False,
        )
        self._live.start()

    def stop(self):
        if self._live:
            self._live.stop()

    def refresh(self):
        if self._live:
            self._live.update(self.get_renderable())


# ═══════════════════════════════════════════════════════
#  FORENSIC PIPELINE  (Main Orchestrator)
# ═══════════════════════════════════════════════════════

class ForensicPipeline:
    """
    Top-level orchestrator.

    Lifecycle:
        1. validate()    – pre-flight checks (tools, drive, directories)
        2. run()         – parallel extraction phase then parallel parsing phase
        3. report()      – write summary to pipeline.log

    Thread model:
        ThreadPoolExecutor with configurable workers.
        Extraction tasks and parsing tasks are queued separately;
        parsing begins only after extraction completes.
    """

    def __init__(
        self,
        drive: Path,
        output: Path,
        tools_dir: Path,
        config: PipelineConfig,
        workers: int = 4,
    ):
        self._drive     = drive
        self._output    = output
        self._tools     = tools_dir
        self._config    = config
        self._workers   = workers

        # Set up logging first
        self._log = setup_logging(output / "logs")
        self._log.info("═" * 60)
        self._log.info("  Forensic Pipeline v2.1.0  –  %s",
                       datetime.now().isoformat(timespec="seconds"))
        self._log.info("  Drive   : %s", drive)
        self._log.info("  Output  : %s", output)
        self._log.info("  RECmd Batch Override : %s", config.recmd_batch or "auto")
        self._log.info("  USN $J Override      : %s", config.usn_j_path or "auto")
        self._log.info("  USN $MFT Override    : %s", config.usn_mft_path or "auto")
        self._log.info("  Workers : %d", workers)
        self._log.info("═" * 60)

        self._runner = ToolRunner(self._log)

        # Instantiate all artifact handlers
        handler_classes = [MRUHandler, USNJournalHandler, LNKHandler, BrowserHandler]
        self._handlers: List[ArtifactHandler] = [
            cls(drive, output, tools_dir, config, self._runner, self._log)
            for cls in handler_classes
        ]

        # Two ArtifactResult records per handler (extract + parse phases)
        self._results: Dict[str, ArtifactResult] = {}
        for h in self._handlers:
            for phase in (PHASE_EXTRACTION, PHASE_PARSING):
                key = f"{h.NAME}::{phase}"
                self._results[key] = ArtifactResult(
                    key=key, name=h.NAME, phase=phase
                )

        self._ui = UIManager(artifact_count=len(self._handlers))

    # ── Validation ───────────────────────────────────────

    def validate(self) -> None:
        """
        Pre-flight checks.  Raises on any critical failure so the
        pipeline aborts before any I/O is attempted.
        """
        self._log.info("[Validate] Starting pre-flight checks …")

        # 1. Drive must be accessible
        if not self._drive.exists():
            raise ArtifactNotFoundError(
                f"Forensic drive not accessible: {self._drive}"
            )

        # 2. Tools directory must exist
        if not self._tools.is_dir():
            raise ToolNotFoundError(
                f"Tools directory not found: {self._tools}"
            )

        # 3. Each required executable must be present
        for key, name in TOOL_NAMES.items():
            exe = self._tools / name
            if not exe.is_file():
                self._log.warning(
                    "[Validate] ⚠  Tool missing: %s  (path: %s)", name, exe
                )
            else:
                self._log.info("[Validate] ✔  Found: %s", name)

        # 4. Batch file for RECmd
        try:
            batch = resolve_recmd_batch(self._tools, self._config.recmd_batch)
        except ToolNotFoundError as exc:
            if self._config.recmd_batch is not None:
                raise
            self._log.warning(
                "[Validate] ⚠  %s", exc
            )
        else:
            self._log.info("[Validate] ✔  Using RECmd batch file: %s", batch)

        # 5. Ensure output skeleton exists
        for subdir in ("parsed_artifact/MRU", "parsed_artifact/USN_Journal",
                       "parsed_artifact/LNK_Files", "parsed_artifact/Browsers",
                       "logs"):
            ensure_dir(self._output / subdir)

        self._log.info("[Validate] Pre-flight checks complete.")

    # ── Execution Helpers ─────────────────────────────────

    def _run_phase(
        self,
        phase: str,
        method: str,
        handlers: Optional[Sequence[ArtifactHandler]] = None,
    ) -> Dict[str, ArtifactStatus]:
        """
        Execute all handlers concurrently for *phase* using the method name
        'extract' or 'parse'. Returns {handler.NAME: terminal_status}.
        """
        active_handlers = list(self._handlers if handlers is None else handlers)
        results: Dict[str, ArtifactStatus] = {}
        lock = threading.Lock()

        def _task(handler: ArtifactHandler) -> Tuple[str, ArtifactStatus]:
            key = f"{handler.NAME}::{phase}"
            r   = self._results[key]
            start_time = time.monotonic()
            self._ui.update(
                key,
                status=ArtifactStatus.RUNNING,
                start_time=start_time,
                end_time=None,
                returncode=None,
                error_msg="",
            )
            self._ui.refresh()

            try:
                fn = getattr(handler, method)
                fn()
                self._ui.update(
                    key,
                    status=ArtifactStatus.DONE,
                    end_time=time.monotonic(),
                    returncode=0,
                )
                self._log.info(
                    "[%s] %s phase → DONE",
                    handler.NAME, phase,
                )
                return handler.NAME, ArtifactStatus.DONE

            except ArtifactEmptyError as exc:
                self._ui.update(
                    key,
                    status=ArtifactStatus.EMPTY,
                    end_time=time.monotonic(),
                    error_msg=str(exc),
                )
                self._log.warning(
                    "[%s] %s phase → EMPTY: %s", handler.NAME, phase, exc
                )
                return handler.NAME, ArtifactStatus.EMPTY

            except (ToolNotFoundError, ArtifactAccessDeniedError,
                    ArtifactNotFoundError, ExecutionError) as exc:
                self._ui.update(
                    key,
                    status=ArtifactStatus.FAILED,
                    end_time=time.monotonic(),
                    error_msg=str(exc),
                    returncode=exc.returncode if isinstance(exc, ExecutionError) else None,
                )
                self._log.error(
                    "[%s] %s phase → FAILED: %s", handler.NAME, phase, exc
                )
                return handler.NAME, ArtifactStatus.FAILED

            except Exception as exc:
                self._ui.update(
                    key,
                    status=ArtifactStatus.FAILED,
                    end_time=time.monotonic(),
                    error_msg=traceback.format_exc(),
                )
                self._log.error(
                    "[%s] %s phase → UNEXPECTED: %s",
                    handler.NAME, phase, traceback.format_exc(),
                )
                return handler.NAME, ArtifactStatus.FAILED

            finally:
                self._ui.refresh()

        with ThreadPoolExecutor(
            max_workers=self._workers,
            thread_name_prefix=f"dfir-{phase[:3].lower()}",
        ) as executor:
            futures: Dict[Future, ArtifactHandler] = {
                executor.submit(_task, h): h for h in active_handlers
            }
            for future in as_completed(futures):
                name, status = future.result()
                with lock:
                    results[name] = status

        return results

    # ── Main Entry Point ─────────────────────────────────

    def run(self) -> int:
        """
        Execute pipeline. Returns 0 when no handler failed, else 1.
        """
        # Register all results for the UI before starting Live display
        for r in self._results.values():
            self._ui.register(r)

        self._ui.start()
        t_start = time.monotonic()

        try:
            # ── Phase 1: Extraction ──────────────────────
            self._log.info("[Pipeline] ─── PHASE 1: %s ───", PHASE_EXTRACTION)
            extract_results = self._run_phase(PHASE_EXTRACTION, "extract")

            # ── Phase 2: Parsing ─────────────────────────
            parse_handlers = []
            skipped_parse: List[str] = []
            for handler in self._handlers:
                status = extract_results.get(handler.NAME)
                if status == ArtifactStatus.DONE:
                    parse_handlers.append(handler)
                    continue

                parse_key = f"{handler.NAME}::{PHASE_PARSING}"
                if status in (ArtifactStatus.FAILED, ArtifactStatus.EMPTY, ArtifactStatus.SKIPPED):
                    skipped_parse.append(f"{handler.NAME} ({status.name})")
                    self._ui.update(
                        parse_key,
                        status=ArtifactStatus.SKIPPED,
                        error_msg=f"Skipped because extraction ended in {status.name}",
                        end_time=time.monotonic(),
                    )

            if skipped_parse:
                self._log.warning(
                    "[Pipeline] Skipping parse for non-ready extractions: %s",
                    ", ".join(skipped_parse),
                )

            self._log.info("[Pipeline] ─── PHASE 2: %s ───", PHASE_PARSING)
            parse_results = self._run_phase(PHASE_PARSING, "parse", handlers=parse_handlers)
            for handler in self._handlers:
                parse_results.setdefault(
                    handler.NAME,
                    self._results[f"{handler.NAME}::{PHASE_PARSING}"].status,
                )

        finally:
            self._ui.stop()

        elapsed = time.monotonic() - t_start
        return self.report(extract_results, parse_results, elapsed)

    # ── Summary Report ────────────────────────────────────

    @staticmethod
    def _status_cell(status: ArtifactStatus) -> str:
        if status == ArtifactStatus.DONE:
            return "[green]DONE[/]"
        if status == ArtifactStatus.EMPTY:
            return "[yellow]EMPTY[/]"
        if status == ArtifactStatus.SKIPPED:
            return "[dim]SKIPPED[/]"
        if status == ArtifactStatus.FAILED:
            return "[red]FAILED[/]"
        if status == ArtifactStatus.RUNNING:
            return "[cyan]RUNNING[/]"
        return "[yellow]PENDING[/]"

    def report(
        self,
        extract: Dict[str, ArtifactStatus],
        parse: Dict[str, ArtifactStatus],
        elapsed: float,
    ) -> int:
        """
        Print and log a final summary. Returns 1 only when a handler failed.
        """
        failed = any(
            status == ArtifactStatus.FAILED
            for status in list(extract.values()) + list(parse.values())
        )
        gaps = any(
            status in (ArtifactStatus.EMPTY, ArtifactStatus.SKIPPED)
            for status in list(extract.values()) + list(parse.values())
        )
        if failed:
            status_str = "[bold red]PARTIAL FAILURE[/]"
            border_style = "red"
        elif gaps:
            status_str = "[bold yellow]COMPLETED WITH GAPS[/]"
            border_style = "yellow"
        else:
            status_str = "[bold green]ALL PASSED[/]"
            border_style = "green"

        summary = Table(
            title=f"Pipeline Complete — {status_str}  ({elapsed:.1f}s total)",
            box=box.DOUBLE_EDGE,
            border_style=border_style,
        )
        summary.add_column("Artifact",    style="bold")
        summary.add_column("Extract",     justify="center")
        summary.add_column("Parse",       justify="center")

        for name in sorted(set(list(extract.keys()) + list(parse.keys()))):
            e_status = extract.get(name, ArtifactStatus.PENDING)
            p_status = parse.get(name, ArtifactStatus.PENDING)
            summary.add_row(
                name,
                self._status_cell(e_status),
                self._status_cell(p_status),
            )

        _console.print(summary)

        # Log path of output
        _console.print(
            Panel(
                f"[bold]Output directory:[/]  {self._output}\n"
                f"[bold]Audit log:[/]         {self._output / 'logs' / 'pipeline.log'}",
                title="📁 Output Locations",
                border_style="blue",
            )
        )

        self._log.info(
            "[Pipeline] Finished in %.1fs — %s",
            elapsed,
            "PARTIAL FAILURE" if failed else ("COMPLETED WITH GAPS" if gaps else "ALL PASSED"),
        )
        return 1 if failed else 0


# ═══════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic_pipeline",
        description=(
            "Windows DFIR artifact discovery and parsing pipeline\n"
            "Parses: MRU, USN Journal, LNK Files, Browser Artifacts\n"
            "Tools:  RECmd | MFTECmd | LECmd | Hindsight"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  forensic_pipeline.py -d E:\\ -o C:\\Cases\\Case001 "
            "--tools-dir C:\\EZTools\n"
            "  forensic_pipeline.py -d F:\\ -o D:\\Output "
            "--tools-dir D:\\Tools --workers 8\n"
            "  forensic_pipeline.py -d F:\\ -o D:\\Output --tools-dir D:\\Tools "
            "--recmd-batch D:\\Tools\\BatchExamples\\DFIRBatch.reb "
            "--usn-j-path D:\\Exports\\$J --usn-mft-path D:\\Exports\\$MFT\n"
        ),
    )
    parser.add_argument(
        "-d", "--drive",
        required=True,
        metavar="DRIVE",
        help="Mounted forensic drive letter or path  (e.g. E:\\ or /mnt/evidence)",
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        metavar="OUTPUT_DIR",
        help="Root output directory for all parsed artifacts and logs",
    )
    parser.add_argument(
        "--tools-dir",
        required=True,
        metavar="TOOLS_DIR",
        help="Directory containing EZ Tools executables and batch files",
    )
    parser.add_argument(
        "--recmd-batch",
        metavar="BATCH_FILE",
        help="Optional explicit RECmd batch file path. Relative paths are resolved under --tools-dir.",
    )
    parser.add_argument(
        "--usn-j-path",
        metavar="J_PATH",
        help="Optional explicit $J path or extracted $J file. Relative paths are resolved under --drive.",
    )
    parser.add_argument(
        "--usn-mft-path",
        metavar="MFT_PATH",
        help="Optional explicit $MFT path or extracted $MFT file. Relative paths are resolved under --drive.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="ThreadPoolExecutor worker count  (default: 4)",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip pre-flight validation (use with caution)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.1.0",
    )
    return parser


# ═══════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    drive     = Path(args.drive)
    output    = Path(args.output)
    tools_dir = Path(args.tools_dir)
    config    = PipelineConfig(
        recmd_batch=Path(args.recmd_batch) if args.recmd_batch else None,
        usn_j_path=Path(args.usn_j_path) if args.usn_j_path else None,
        usn_mft_path=Path(args.usn_mft_path) if args.usn_mft_path else None,
    )
    workers   = max(1, args.workers)

    _console.print(
        Panel(
            "[bold cyan]Windows Forensic Automation Pipeline[/]\n"
            f"[dim]Drive:[/] {drive}   "
            f"[dim]Output:[/] {output}   "
            f"[dim]Tools:[/] {tools_dir}   "
            f"[dim]Workers:[/] {workers}",
            title="🔍  DFIR Pipeline v2.1.0",
            border_style="bright_cyan",
        )
    )

    try:
        pipeline = ForensicPipeline(
            drive=drive,
            output=output,
            tools_dir=tools_dir,
            config=config,
            workers=workers,
        )

        if not args.no_validate:
            pipeline.validate()

        return pipeline.run()

    except (ToolNotFoundError, ArtifactAccessDeniedError, ArtifactNotFoundError) as exc:
        _console.print(f"[bold red][FATAL] {exc}[/]")
        return 2
    except KeyboardInterrupt:
        _console.print("\n[yellow][!] Pipeline interrupted by user.[/]")
        return 130
    except Exception as exc:
        _console.print(f"[bold red][FATAL] Unexpected error: {exc}[/]")
        _console.print_exception()
        return 1


if __name__ == "__main__":
    sys.exit(main())
