"""
forensic_parser.py — Forensic Artifact Parser Agent v1.0

Single-file Python CLI agent that extracts and parses key Windows forensic
artifacts from a mounted forensic image using Eric Zimmerman's (EZ) tools.

Targets: $MFT, Amcache.hve, Prefetch (.pf), SRUDB.dat
Tools:   MFTECmd, AmcacheParser, PECmd, SrumECmd

Usage:
    python forensic_parser.py -d E -o C:\\Cases\\Case001\\output
    python forensic_parser.py -d F -o D:\\Output --tools-dir D:\\EZTools
    python forensic_parser.py -d E -o .\\output --timeout 600 --workers 2

Requirements:
    pip install rich
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich import box
except ImportError:
    print("ERROR: 'rich' library is required. Install it with: pip install rich")
    sys.exit(2)


# ─── Constants ─────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
BANNER = r"""
  ┌─────────────────────────────────────────────────────┐
  │  🔍  Forensic Artifact Parser Agent  v{version}        │
  │      Multi-threaded • EZ Tools • CSV Output         │
  └─────────────────────────────────────────────────────┘
""".format(version=VERSION)

DEFAULT_TIMEOUT = 600   # seconds per EZ tool invocation
DEFAULT_WORKERS = 4

# Artifact source paths relative to the mounted drive root
ARTIFACT_PATHS = {
    "MFT": {
        "files": [{"relative": "$MFT", "required": True}],
    },
    "Amcache": {
        "files": [
            {"relative": os.path.join("Windows", "AppCompat", "Programs", "Amcache.hve"), "required": True},
            {"relative": os.path.join("Windows", "AppCompat", "Programs", "Amcache.hve.LOG1"), "required": False},
            {"relative": os.path.join("Windows", "AppCompat", "Programs", "Amcache.hve.LOG2"), "required": False},
        ],
    },
    "Prefetch": {
        "directory": os.path.join("Windows", "Prefetch"),
        "extension": ".pf",
    },
    "SRUMDB": {
        "files": [
            {"relative": os.path.join("Windows", "System32", "sru", "SRUDB.dat"), "required": True},
            {"relative": os.path.join("Windows", "System32", "config", "SOFTWARE"), "required": False},
        ],
    },
}

# EZ Tool binary names
EZ_TOOLS = {
    "MFT":      "MFTECmd.exe",
    "Amcache":  "AmcacheParser.exe",
    "Prefetch": "PECmd.exe",
    "SRUMDB":   "SrumECmd.exe",
}


# ─── Enums ─────────────────────────────────────────────────────────────────────
class ArtifactStatus(Enum):
    """Lifecycle states for each artifact processing task."""
    PENDING         = "⏳ Pending"
    EXTRACTING      = "📦 Extracting"
    EXTRACTED       = "✅ Extracted"
    EXTRACT_FAILED  = "❌ Extract Failed"
    PARSING         = "🔬 Parsing"
    COMPLETE        = "✅ Complete"
    PARSE_FAILED    = "❌ Parse Failed"
    SKIPPED         = "⏭️  Skipped"


# ─── Data Classes ──────────────────────────────────────────────────────────────
@dataclass
class ArtifactResult:
    """Tracks the outcome of processing a single artifact category."""
    name: str
    status: ArtifactStatus = ArtifactStatus.PENDING
    extraction_time: float = 0.0
    parsing_time: float = 0.0
    files_extracted: int = 0
    csvs_generated: int = 0
    error_message: Optional[str] = None

    @property
    def total_time(self) -> float:
        return self.extraction_time + self.parsing_time

    @property
    def extraction_ok(self) -> bool:
        return self.status not in (
            ArtifactStatus.EXTRACT_FAILED,
            ArtifactStatus.SKIPPED,
            ArtifactStatus.PENDING,
        )

    @property
    def extraction_status_text(self) -> str:
        if self.status == ArtifactStatus.SKIPPED:
            return "[dim]Skipped[/dim]"
        if self.status == ArtifactStatus.EXTRACT_FAILED:
            return f"[red]Failed[/red]"
        if self.status in (ArtifactStatus.EXTRACTED, ArtifactStatus.PARSING,
                           ArtifactStatus.COMPLETE, ArtifactStatus.PARSE_FAILED):
            return "[green]Success[/green]"
        return "[dim]—[/dim]"

    @property
    def parsing_status_text(self) -> str:
        if self.status == ArtifactStatus.COMPLETE:
            return "[green]Success[/green]"
        if self.status == ArtifactStatus.PARSE_FAILED:
            return "[yellow]Failed[/yellow]"
        if self.status in (ArtifactStatus.SKIPPED, ArtifactStatus.EXTRACT_FAILED):
            return "[dim]Skipped[/dim]"
        return "[dim]—[/dim]"


# ─── Custom Exceptions ────────────────────────────────────────────────────────
class ArtifactNotFoundError(Exception):
    """Raised when a required artifact file is missing on the mounted image."""


class ParseError(Exception):
    """Raised when an EZ Tool returns a non-zero exit code."""


class ToolNotFoundError(Exception):
    """Raised when an EZ Tool binary cannot be located."""


# ─── Logging Setup ─────────────────────────────────────────────────────────────
def setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    """
    Configure dual logging: file (DEBUG) + console (WARNING+).

    Args:
        output_dir: Directory to write the log file into.
        verbose: If True, lower the console log level to INFO.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("forensic_parser")
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers on re-init
    logger.handlers.clear()

    # File handler — comprehensive audit trail
    log_path = os.path.join(output_dir, "forensic_parser.log")
    fh = logging.FileHandler(log_path, encoding="utf-8", mode="w")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(threadName)-16s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # Console handler — minimal noise (warnings only unless verbose)
    ch = RichHandler(
        level=logging.INFO if verbose else logging.WARNING,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    logger.addHandler(ch)

    return logger


# ─── Progress Manager ──────────────────────────────────────────────────────────
class ProgressManager:
    """
    Thread-safe progress tracking using the rich library.

    Manages two progress groups (extraction and parsing) and provides
    methods to update each from concurrent worker threads.
    """

    def __init__(self, console: Console) -> None:
        self.console = console
        self._lock = threading.Lock()

        # Extraction progress — shows file counts
        self.extraction_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

        # Parsing progress — indeterminate spinner with status text
        self.parsing_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("{task.fields[status]}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

        self._extraction_tasks: dict[str, int] = {}
        self._parsing_tasks: dict[str, int] = {}

    # ── Extraction methods ──────────────────────────────────────────────

    def add_extraction_task(self, name: str, total: int) -> None:
        """Register a new extraction task with a known file count."""
        with self._lock:
            tid = self.extraction_progress.add_task(
                f"[cyan]{name:12s}", total=total
            )
            self._extraction_tasks[name] = tid

    def advance_extraction(self, name: str, advance: int = 1) -> None:
        """Advance an extraction task's completed file count."""
        with self._lock:
            self.extraction_progress.advance(self._extraction_tasks[name], advance)

    def complete_extraction(self, name: str) -> None:
        """Mark an extraction task as finished."""
        with self._lock:
            tid = self._extraction_tasks[name]
            task = self.extraction_progress.tasks[tid]
            self.extraction_progress.update(
                tid, completed=task.total,
                description=f"[green]{'✅ ' + name:14s}"
            )

    def fail_extraction(self, name: str, reason: str) -> None:
        """Mark an extraction task as failed."""
        with self._lock:
            tid = self._extraction_tasks[name]
            self.extraction_progress.update(
                tid,
                description=f"[red]{'❌ ' + name:14s}",
            )

    # ── Parsing methods ─────────────────────────────────────────────────

    def add_parsing_task(self, name: str) -> None:
        """Register a new parsing task (indeterminate progress)."""
        with self._lock:
            tid = self.parsing_progress.add_task(
                f"[yellow]{name:12s}", total=100, status="Waiting…"
            )
            self._parsing_tasks[name] = tid

    def start_parsing(self, name: str) -> None:
        """Signal that parsing has begun for an artifact."""
        with self._lock:
            self.parsing_progress.update(
                self._parsing_tasks[name], status="[bold]Running…"
            )

    def update_parsing_status(self, name: str, status: str) -> None:
        """Update the inline status text for a parsing task."""
        with self._lock:
            truncated = status[:55] + "…" if len(status) > 55 else status
            self.parsing_progress.update(
                self._parsing_tasks[name], status=truncated
            )

    def complete_parsing(self, name: str, csv_count: int) -> None:
        """Mark a parsing task as complete."""
        with self._lock:
            self.parsing_progress.update(
                self._parsing_tasks[name],
                completed=100,
                status=f"[green]✅ Done ({csv_count} CSVs)",
                description=f"[green]{'✅ ' + name:14s}",
            )

    def fail_parsing(self, name: str, reason: str) -> None:
        """Mark a parsing task as failed."""
        with self._lock:
            short = reason[:50] + "…" if len(reason) > 50 else reason
            self.parsing_progress.update(
                self._parsing_tasks[name],
                completed=100,
                status=f"[red]❌ {short}",
                description=f"[red]{'❌ ' + name:14s}",
            )


# ─── Artifact Extractor ────────────────────────────────────────────────────────
class ArtifactExtractor:
    """
    Handles extraction (copying) of raw forensic artifacts from the
    mounted image to the output ``artifacts/`` directory.
    """

    def __init__(
        self,
        drive_root: str,
        artifacts_dir: str,
        progress: ProgressManager,
        logger: logging.Logger,
    ) -> None:
        self.drive_root = drive_root
        self.artifacts_dir = artifacts_dir
        self.progress = progress
        self.logger = logger

    # ── Public per-artifact methods ─────────────────────────────────────

    def extract_mft(self) -> ArtifactResult:
        """Extract $MFT from the mounted volume."""
        result = ArtifactResult(name="MFT")
        result.status = ArtifactStatus.EXTRACTING
        t0 = time.perf_counter()
        dst_dir = os.path.join(self.artifacts_dir, "MFT")
        os.makedirs(dst_dir, exist_ok=True)

        src = os.path.join(self.drive_root, "$MFT")
        self.progress.add_extraction_task("MFT", total=1)

        try:
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dst_dir, "$MFT"))
                result.files_extracted = 1
                self.progress.advance_extraction("MFT")
                self.logger.info(f"Extracted $MFT ({self._fsize(src)})")
            else:
                # $MFT might not be visible via normal FS calls on some mounts
                self.logger.warning(
                    "$MFT not directly accessible — will attempt volume-level "
                    "parsing with MFTECmd during parse phase."
                )
                result.files_extracted = 0
                self.progress.advance_extraction("MFT")

            self.progress.complete_extraction("MFT")
            result.status = ArtifactStatus.EXTRACTED

        except PermissionError:
            # $MFT is an NTFS metafile — standard copy APIs cannot access it
            # on most mounted images. This is EXPECTED. MFTECmd can parse it
            # directly from the volume letter during the parse phase.
            self.logger.warning(
                "$MFT copy failed (PermissionError) — this is normal for NTFS "
                "metafiles. MFTECmd will parse directly from the volume."
            )
            result.files_extracted = 0
            self.progress.advance_extraction("MFT")
            self.progress.complete_extraction("MFT")
            # Mark as EXTRACTED so parsing phase proceeds with volume fallback
            result.status = ArtifactStatus.EXTRACTED

        except Exception as exc:
            self.logger.error(f"MFT extraction failed: {exc}", exc_info=True)
            self.progress.fail_extraction("MFT", str(exc))
            result.status = ArtifactStatus.EXTRACT_FAILED
            result.error_message = str(exc)

        result.extraction_time = time.perf_counter() - t0
        return result

    def extract_amcache(self) -> ArtifactResult:
        """Extract Amcache.hve and its transaction logs."""
        result = ArtifactResult(name="Amcache")
        result.status = ArtifactStatus.EXTRACTING
        t0 = time.perf_counter()
        dst_dir = os.path.join(self.artifacts_dir, "Amcache")
        os.makedirs(dst_dir, exist_ok=True)

        files = ARTIFACT_PATHS["Amcache"]["files"]
        self.progress.add_extraction_task("Amcache", total=len(files))

        try:
            for entry in files:
                src = os.path.join(self.drive_root, entry["relative"])
                dst = os.path.join(dst_dir, os.path.basename(entry["relative"]))
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    result.files_extracted += 1
                    self.logger.info(f"Extracted {os.path.basename(src)} ({self._fsize(src)})")
                else:
                    if entry["required"]:
                        raise ArtifactNotFoundError(
                            f"Required artifact not found: {src}"
                        )
                    self.logger.warning(f"Optional file missing: {src}")
                self.progress.advance_extraction("Amcache")

            self.progress.complete_extraction("Amcache")
            result.status = ArtifactStatus.EXTRACTED

        except (ArtifactNotFoundError, OSError) as exc:
            self.logger.error(f"Amcache extraction failed: {exc}", exc_info=True)
            self.progress.fail_extraction("Amcache", str(exc))
            result.status = ArtifactStatus.EXTRACT_FAILED
            result.error_message = str(exc)

        result.extraction_time = time.perf_counter() - t0
        return result

    def extract_prefetch(self) -> ArtifactResult:
        """Extract all .pf files from the Prefetch directory."""
        result = ArtifactResult(name="Prefetch")
        result.status = ArtifactStatus.EXTRACTING
        t0 = time.perf_counter()
        dst_dir = os.path.join(self.artifacts_dir, "Prefetch")
        os.makedirs(dst_dir, exist_ok=True)

        src_dir = os.path.join(
            self.drive_root,
            ARTIFACT_PATHS["Prefetch"]["directory"],
        )

        try:
            if not os.path.isdir(src_dir):
                raise ArtifactNotFoundError(
                    f"Prefetch directory not found: {src_dir}"
                )

            pf_files = [
                f for f in os.listdir(src_dir)
                if f.lower().endswith(ARTIFACT_PATHS["Prefetch"]["extension"])
            ]

            if not pf_files:
                raise ArtifactNotFoundError(
                    "No .pf files found in Prefetch directory"
                )

            self.progress.add_extraction_task("Prefetch", total=len(pf_files))
            self.logger.info(f"Found {len(pf_files)} prefetch files to extract")

            for filename in pf_files:
                src = os.path.join(src_dir, filename)
                shutil.copy2(src, os.path.join(dst_dir, filename))
                result.files_extracted += 1
                self.progress.advance_extraction("Prefetch")

            self.progress.complete_extraction("Prefetch")
            result.status = ArtifactStatus.EXTRACTED

        except (ArtifactNotFoundError, OSError) as exc:
            self.logger.error(f"Prefetch extraction failed: {exc}", exc_info=True)
            # If we already registered, mark failed
            if "Prefetch" in self.progress._extraction_tasks:
                self.progress.fail_extraction("Prefetch", str(exc))
            else:
                self.progress.add_extraction_task("Prefetch", total=1)
                self.progress.fail_extraction("Prefetch", str(exc))
            result.status = ArtifactStatus.EXTRACT_FAILED
            result.error_message = str(exc)

        result.extraction_time = time.perf_counter() - t0
        return result

    def extract_srum(self) -> ArtifactResult:
        """Extract SRUDB.dat, transaction logs, and the SOFTWARE registry hive."""
        result = ArtifactResult(name="SRUMDB")
        result.status = ArtifactStatus.EXTRACTING
        t0 = time.perf_counter()
        dst_dir = os.path.join(self.artifacts_dir, "SRUMDB")
        os.makedirs(dst_dir, exist_ok=True)

        files = ARTIFACT_PATHS["SRUMDB"]["files"]
        self.progress.add_extraction_task("SRUMDB", total=len(files) + 1)

        try:
            for entry in files:
                src = os.path.join(self.drive_root, entry["relative"])
                dst = os.path.join(dst_dir, os.path.basename(entry["relative"]))
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    result.files_extracted += 1
                    self.logger.info(f"Extracted {os.path.basename(src)} ({self._fsize(src)})")
                else:
                    if entry["required"]:
                        raise ArtifactNotFoundError(
                            f"Required artifact not found: {src}"
                        )
                    self.logger.warning(
                        f"Optional file missing: {os.path.basename(entry['relative'])} "
                        f"(SRUM output may lack enrichment)"
                    )
                self.progress.advance_extraction("SRUMDB")

            # Also copy SRU transaction logs — SrumECmd needs these to repair
            # dirty ESE databases (SRU*.log, SRU*.chk, etc.)
            sru_dir = os.path.join(self.drive_root, "Windows", "System32", "sru")
            if os.path.isdir(sru_dir):
                log_count = 0
                for f in os.listdir(sru_dir):
                    fl = f.lower()
                    if fl.startswith("sru") and fl != "srudb.dat":
                        src = os.path.join(sru_dir, f)
                        if os.path.isfile(src):
                            shutil.copy2(src, os.path.join(dst_dir, f))
                            log_count += 1
                if log_count:
                    result.files_extracted += log_count
                    self.logger.info(
                        f"Extracted {log_count} SRU transaction log(s) for dirty-DB recovery"
                    )

            self.progress.advance_extraction("SRUMDB")
            self.progress.complete_extraction("SRUMDB")
            result.status = ArtifactStatus.EXTRACTED

        except (ArtifactNotFoundError, OSError) as exc:
            self.logger.error(f"SRUM extraction failed: {exc}", exc_info=True)
            self.progress.fail_extraction("SRUMDB", str(exc))
            result.status = ArtifactStatus.EXTRACT_FAILED
            result.error_message = str(exc)

        result.extraction_time = time.perf_counter() - t0
        return result

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _fsize(path: str) -> str:
        """Return a human-readable file size string."""
        try:
            sz = os.path.getsize(path)
        except OSError:
            return "??"
        for unit in ("B", "KB", "MB", "GB"):
            if sz < 1024:
                return f"{sz:.1f} {unit}"
            sz /= 1024
        return f"{sz:.1f} TB"


# ─── Artifact Parser ──────────────────────────────────────────────────────────
class ArtifactParser:
    """
    Handles parsing of extracted artifacts using EZ Tool binaries.
    Each parse method runs an EZ Tool via subprocess and streams output.
    """

    def __init__(
        self,
        tools_dir: str,
        artifacts_dir: str,
        parsed_dir: str,
        drive_root: str,
        progress: ProgressManager,
        logger: logging.Logger,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.tools_dir = tools_dir
        self.artifacts_dir = artifacts_dir
        self.parsed_dir = parsed_dir
        self.drive_root = drive_root
        self.progress = progress
        self.logger = logger
        self.timeout = timeout

    # ── Public per-artifact methods ─────────────────────────────────────

    def parse_mft(self, extraction_result: ArtifactResult) -> ArtifactResult:
        """Parse $MFT using MFTECmd."""
        result = extraction_result
        if not result.extraction_ok:
            return result

        result.status = ArtifactStatus.PARSING
        t0 = time.perf_counter()
        csv_output = os.path.join(self.parsed_dir, "MFT")
        os.makedirs(csv_output, exist_ok=True)

        tool = self._tool_path("MFT")
        self.progress.start_parsing("MFT")

        # Determine source: extracted copy or direct volume access
        extracted_mft = os.path.join(self.artifacts_dir, "MFT", "$MFT")
        if os.path.exists(extracted_mft) and os.path.getsize(extracted_mft) > 0:
            source = extracted_mft
        else:
            source = os.path.join(self.drive_root, "$MFT")
            self.logger.info("Using volume-level $MFT (direct copy was unavailable)")

        cmd = [tool, "-f", source, "--csv", csv_output]
        self.logger.info(f"MFT parse command: {' '.join(cmd)}")

        try:
            exit_code = self._run_ez_tool(cmd, "MFT")
            if exit_code != 0:
                raise ParseError(f"MFTECmd exited with code {exit_code}")

            csv_count = self._count_csvs(csv_output)
            result.csvs_generated = csv_count
            result.status = ArtifactStatus.COMPLETE
            self.progress.complete_parsing("MFT", csv_count)
            self.logger.info(f"MFT parsing complete — {csv_count} CSV(s) generated")

        except (ParseError, ToolNotFoundError, subprocess.TimeoutExpired) as exc:
            self.logger.error(f"MFT parsing failed: {exc}", exc_info=True)
            result.status = ArtifactStatus.PARSE_FAILED
            result.error_message = str(exc)
            self.progress.fail_parsing("MFT", str(exc))

        result.parsing_time = time.perf_counter() - t0
        return result

    def parse_amcache(self, extraction_result: ArtifactResult) -> ArtifactResult:
        """Parse Amcache.hve using AmcacheParser."""
        result = extraction_result
        if not result.extraction_ok:
            return result

        result.status = ArtifactStatus.PARSING
        t0 = time.perf_counter()
        csv_output = os.path.join(self.parsed_dir, "Amcache")
        os.makedirs(csv_output, exist_ok=True)

        tool = self._tool_path("Amcache")
        amcache_path = os.path.join(self.artifacts_dir, "Amcache", "Amcache.hve")

        self.progress.start_parsing("Amcache")

        cmd = [tool, "-f", amcache_path, "-i", "--csv", csv_output]
        self.logger.info(f"Amcache parse command: {' '.join(cmd)}")

        try:
            exit_code = self._run_ez_tool(cmd, "Amcache")
            if exit_code != 0:
                raise ParseError(f"AmcacheParser exited with code {exit_code}")

            csv_count = self._count_csvs(csv_output)
            result.csvs_generated = csv_count
            result.status = ArtifactStatus.COMPLETE
            self.progress.complete_parsing("Amcache", csv_count)
            self.logger.info(f"Amcache parsing complete — {csv_count} CSV(s)")

        except (ParseError, ToolNotFoundError, subprocess.TimeoutExpired) as exc:
            self.logger.error(f"Amcache parsing failed: {exc}", exc_info=True)
            result.status = ArtifactStatus.PARSE_FAILED
            result.error_message = str(exc)
            self.progress.fail_parsing("Amcache", str(exc))

        result.parsing_time = time.perf_counter() - t0
        return result

    def parse_prefetch(self, extraction_result: ArtifactResult) -> ArtifactResult:
        """Parse Prefetch files using PECmd."""
        result = extraction_result
        if not result.extraction_ok:
            return result

        result.status = ArtifactStatus.PARSING
        t0 = time.perf_counter()
        csv_output = os.path.join(self.parsed_dir, "Prefetch")
        os.makedirs(csv_output, exist_ok=True)

        tool = self._tool_path("Prefetch")
        prefetch_dir = os.path.join(self.artifacts_dir, "Prefetch")

        self.progress.start_parsing("Prefetch")

        # -d for directory mode (all .pf files)
        cmd = [tool, "-d", prefetch_dir, "--csv", csv_output]
        self.logger.info(f"Prefetch parse command: {' '.join(cmd)}")

        try:
            exit_code = self._run_ez_tool(cmd, "Prefetch")
            if exit_code != 0:
                raise ParseError(f"PECmd exited with code {exit_code}")

            csv_count = self._count_csvs(csv_output)
            result.csvs_generated = csv_count
            result.status = ArtifactStatus.COMPLETE
            self.progress.complete_parsing("Prefetch", csv_count)
            self.logger.info(f"Prefetch parsing complete — {csv_count} CSV(s)")

        except (ParseError, ToolNotFoundError, subprocess.TimeoutExpired) as exc:
            self.logger.error(f"Prefetch parsing failed: {exc}", exc_info=True)
            result.status = ArtifactStatus.PARSE_FAILED
            result.error_message = str(exc)
            self.progress.fail_parsing("Prefetch", str(exc))

        result.parsing_time = time.perf_counter() - t0
        return result

    def parse_srum(self, extraction_result: ArtifactResult) -> ArtifactResult:
        """Parse SRUDB.dat using SrumECmd, with automatic dirty-DB repair."""
        result = extraction_result
        if not result.extraction_ok:
            return result

        result.status = ArtifactStatus.PARSING
        t0 = time.perf_counter()
        csv_output = os.path.join(self.parsed_dir, "SRUMDB")
        os.makedirs(csv_output, exist_ok=True)

        tool = self._tool_path("SRUMDB")
        srudb_dir = os.path.join(self.artifacts_dir, "SRUMDB")
        srudb_path = os.path.join(srudb_dir, "SRUDB.dat")
        software_path = os.path.join(srudb_dir, "SOFTWARE")

        self.progress.start_parsing("SRUMDB")

        # Build the SrumECmd command
        cmd = [tool, "-f", srudb_path, "--csv", csv_output]
        if os.path.exists(software_path):
            cmd.extend(["-r", software_path])
            self.logger.info("SOFTWARE hive found — SRUM output will include enrichment")
        else:
            self.logger.warning(
                "SOFTWARE hive not available — SRUM network names will not be resolved"
            )

        self.logger.info(f"SRUM parse command: {' '.join(cmd)}")

        try:
            # --- First attempt ---
            exit_code = self._run_ez_tool(cmd, "SRUMDB")
            csv_count = self._count_csvs(csv_output)

            needs_repair = (exit_code != 0) or (csv_count == 0)

            if needs_repair:
                self.logger.warning(
                    f"SrumECmd failed or produced 0 CSVs (exit={exit_code}, "
                    f"csvs={csv_count}). Attempting automatic dirty-DB repair…"
                )
                self.progress.update_parsing_status(
                    "SRUMDB", "Repairing dirty database…"
                )

                # Run esentutl repair sequence
                repair_ok = self._repair_srum_db(srudb_dir)

                if repair_ok:
                    self.logger.info(
                        "SRUDB.dat repair succeeded — retrying SrumECmd…"
                    )
                    self.progress.update_parsing_status(
                        "SRUMDB", "Retrying after repair…"
                    )

                    # --- Second attempt after repair ---
                    exit_code = self._run_ez_tool(cmd, "SRUMDB")
                    csv_count = self._count_csvs(csv_output)

                    if exit_code != 0:
                        raise ParseError(
                            f"SrumECmd still failed after repair (exit={exit_code})"
                        )
                else:
                    self.logger.error(
                        "esentutl repair failed — cannot parse SRUDB.dat"
                    )
                    raise ParseError(
                        "SRUDB.dat is dirty and automatic repair failed"
                    )

            # --- Evaluate final result ---
            result.csvs_generated = csv_count
            if csv_count == 0:
                result.status = ArtifactStatus.PARSE_FAILED
                result.error_message = "0 CSVs generated even after repair"
                self.progress.fail_parsing("SRUMDB", "0 CSVs after repair")
            else:
                result.status = ArtifactStatus.COMPLETE
                self.progress.complete_parsing("SRUMDB", csv_count)
                self.logger.info(f"SRUM parsing complete — {csv_count} CSV(s)")

        except (ParseError, ToolNotFoundError, subprocess.TimeoutExpired) as exc:
            self.logger.error(f"SRUM parsing failed: {exc}", exc_info=True)
            result.status = ArtifactStatus.PARSE_FAILED
            result.error_message = str(exc)
            self.progress.fail_parsing("SRUMDB", str(exc))

        result.parsing_time = time.perf_counter() - t0
        return result

    def _repair_srum_db(self, srudb_dir: str) -> bool:
        """
        Repair a dirty SRUDB.dat ESE database using esentutl.

        Runs two commands in sequence from the SRUMDB artifacts directory:
          1. esentutl.exe /r sru /i   — soft recovery with /i (ignore mismatches)
          2. esentutl.exe /p SRUDB.dat — hard repair

        Args:
            srudb_dir: Directory containing SRUDB.dat and SRU transaction logs.

        Returns:
            True if both commands succeeded, False otherwise.
        """
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        # Ensure files are not read-only (esentutl needs write access)
        for f in os.listdir(srudb_dir):
            fpath = os.path.join(srudb_dir, f)
            if os.path.isfile(fpath):
                try:
                    os.chmod(fpath, 0o666)
                except OSError:
                    pass

        # Step 1: Soft recovery
        self.logger.info("Running: esentutl.exe /r sru /i")
        try:
            r1 = subprocess.run(
                ["esentutl.exe", "/r", "sru", "/i"],
                cwd=srudb_dir,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=creation_flags,
            )
            self.logger.info(f"esentutl /r exit code: {r1.returncode}")
            if r1.stdout:
                for line in r1.stdout.strip().splitlines():
                    self.logger.debug(f"[esentutl /r] {line}")
            if r1.returncode != 0 and r1.stderr:
                for line in r1.stderr.strip().splitlines():
                    self.logger.warning(f"[esentutl /r stderr] {line}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self.logger.error(f"esentutl /r failed: {exc}")
            return False

        # Step 2: Hard repair
        self.logger.info("Running: esentutl.exe /p SRUDB.dat")
        try:
            r2 = subprocess.run(
                ["esentutl.exe", "/p", "SRUDB.dat"],
                cwd=srudb_dir,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=creation_flags,
                input="y\n",  # Auto-confirm repair prompt
            )
            self.logger.info(f"esentutl /p exit code: {r2.returncode}")
            if r2.stdout:
                for line in r2.stdout.strip().splitlines():
                    self.logger.debug(f"[esentutl /p] {line}")
            if r2.stderr:
                for line in r2.stderr.strip().splitlines():
                    self.logger.warning(f"[esentutl /p stderr] {line}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self.logger.error(f"esentutl /p failed: {exc}")
            return False

        # Consider success even if exit codes are non-zero warnings (like 595)
        self.logger.info("SRUDB.dat repair sequence completed")
        return True

    # ── Internal helpers ────────────────────────────────────────────────

    def _tool_path(self, artifact_key: str) -> str:
        """Resolve and validate the path to an EZ Tool binary."""
        binary = EZ_TOOLS[artifact_key]
        path = os.path.join(self.tools_dir, binary)
        if not os.path.isfile(path):
            raise ToolNotFoundError(
                f"EZ Tool not found: {path}\n"
                f"Please place {binary} in the tools directory."
            )
        return path

    def _run_ez_tool(
        self,
        cmd: list[str],
        artifact_name: str,
    ) -> int:
        """
        Execute an EZ Tool binary via subprocess, streaming stdout/stderr
        in real-time and updating the progress manager.

        Args:
            cmd: Full command as a list of strings.
            artifact_name: Key name for progress updates.

        Returns:
            Process exit code.

        Raises:
            subprocess.TimeoutExpired: If the tool exceeds the timeout.
        """
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creation_flags,
        )

        try:
            deadline = time.monotonic() + self.timeout
            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue

                # Update progress display with latest tool output
                self.progress.update_parsing_status(artifact_name, line)

                # Log every line for audit
                self.logger.debug(f"[{artifact_name}] {line}")

                # Check timeout
                if time.monotonic() > deadline:
                    process.kill()
                    raise subprocess.TimeoutExpired(
                        cmd, self.timeout,
                        output=f"Killed after {self.timeout}s timeout"
                    )

            process.stdout.close()
            process.wait(timeout=30)

        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise

        return process.returncode

    @staticmethod
    def _count_csvs(directory: str) -> int:
        """Count the number of CSV files in a directory."""
        if not os.path.isdir(directory):
            return 0
        return sum(
            1 for f in os.listdir(directory) if f.lower().endswith(".csv")
        )


# ─── Pipeline Orchestrator ─────────────────────────────────────────────────────
class ForensicPipeline:
    """
    Main orchestrator for the two-phase forensic artifact processing pipeline.

    Phase 1 (Extraction):
        Copies raw artifacts from the mounted image to the output directory
        using ThreadPoolExecutor for concurrent I/O.

    Phase 2 (Parsing):
        Runs EZ Tool binaries against the extracted artifacts using
        ThreadPoolExecutor + subprocess for concurrent processing.
    """

    def __init__(
        self,
        drive_letter: str,
        output_dir: str,
        tools_dir: str,
        console: Console,
        timeout: int = DEFAULT_TIMEOUT,
        workers: int = DEFAULT_WORKERS,
        skip: Optional[list[str]] = None,
        verbose: bool = False,
    ) -> None:
        self.drive_letter = drive_letter.rstrip(":\\").upper()
        self.drive_root = f"{self.drive_letter}:\\"
        self.output_dir = os.path.abspath(output_dir)
        self.tools_dir = os.path.abspath(tools_dir)
        self.console = console
        self.timeout = timeout
        self.workers = workers
        self.skip = set(s.lower() for s in (skip or []))
        self.verbose = verbose

        # Derived paths
        self.artifacts_dir = os.path.join(self.output_dir, "artifacts")
        self.parsed_dir = os.path.join(self.output_dir, "parsed_artifacts")

        # Artifact name mapping for --skip
        self._artifact_keys = {
            "mft": "MFT",
            "amcache": "Amcache",
            "prefetch": "Prefetch",
            "srum": "SRUMDB",
        }

        # Results tracking
        self.results: dict[str, ArtifactResult] = {}

    def preflight_checks(self) -> list[str]:
        """
        Run pre-flight validation checks before processing.

        Returns:
            List of error messages. Empty list means all checks passed.
        """
        errors: list[str] = []

        # 1. Validate drive
        if not os.path.exists(self.drive_root):
            errors.append(
                f"Drive {self.drive_letter}: is not accessible. "
                f"Ensure the forensic image is mounted."
            )

        # 2. Validate output directory writability
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            test_file = os.path.join(self.output_dir, ".write_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except OSError as exc:
            errors.append(f"Output directory not writable: {exc}")

        # 3. Validate EZ Tools presence
        active_artifacts = [
            k for k, v in self._artifact_keys.items()
            if k not in self.skip
        ]
        for artifact_key in active_artifacts:
            canonical = self._artifact_keys[artifact_key]
            binary = EZ_TOOLS[canonical]
            tool_path = os.path.join(self.tools_dir, binary)
            if not os.path.isfile(tool_path):
                errors.append(f"Missing EZ Tool: {tool_path}")

        # 4. Validate tools directory exists
        if not os.path.isdir(self.tools_dir):
            errors.append(f"Tools directory not found: {self.tools_dir}")

        return errors

    def run(self) -> dict[str, ArtifactResult]:
        """
        Execute the full two-phase pipeline.

        Returns:
            Dictionary mapping artifact names to their results.
        """
        # Create directory structure
        os.makedirs(self.artifacts_dir, exist_ok=True)
        os.makedirs(self.parsed_dir, exist_ok=True)

        # Setup logging
        logger = setup_logging(self.output_dir, self.verbose)
        logger.info("=" * 70)
        logger.info(f"Forensic Artifact Parser Agent v{VERSION}")
        logger.info(f"Source Drive: {self.drive_root}")
        logger.info(f"Output Directory: {self.output_dir}")
        logger.info(f"Tools Directory: {self.tools_dir}")
        logger.info(f"Workers: {self.workers} | Timeout: {self.timeout}s")
        logger.info(f"Skipped artifacts: {self.skip or 'none'}")
        logger.info("=" * 70)

        # Log EZ Tool versions
        self._log_tool_versions(logger)

        # Initialize progress manager
        progress = ProgressManager(self.console)

        # Initialize parsing progress tasks for all artifacts upfront
        for key in ["MFT", "Amcache", "Prefetch", "SRUMDB"]:
            progress.add_parsing_task(key)

        # Build extractor & parser
        extractor = ArtifactExtractor(
            self.drive_root, self.artifacts_dir, progress, logger
        )
        parser = ArtifactParser(
            self.tools_dir, self.artifacts_dir, self.parsed_dir,
            self.drive_root, progress, logger, self.timeout
        )

        # Map artifact keys to extraction and parsing methods
        extraction_map = {
            "MFT":      extractor.extract_mft,
            "Amcache":  extractor.extract_amcache,
            "Prefetch": extractor.extract_prefetch,
            "SRUMDB":   extractor.extract_srum,
        }
        parsing_map = {
            "MFT":      parser.parse_mft,
            "Amcache":  parser.parse_amcache,
            "Prefetch": parser.parse_prefetch,
            "SRUMDB":   parser.parse_srum,
        }

        # ── Phase 1: Extraction ─────────────────────────────────────────
        self.console.print()
        self.console.print(
            Panel(
                "[bold cyan]📦  Phase 1: Artifact Extraction[/bold cyan]",
                expand=False,
            )
        )

        extraction_results: dict[str, ArtifactResult] = {}

        with progress.extraction_progress:
            with ThreadPoolExecutor(
                max_workers=self.workers,
                thread_name_prefix="extract",
            ) as executor:
                futures = {}
                for key, func in extraction_map.items():
                    skip_key = key.lower().replace("srumdb", "srum")
                    if skip_key in self.skip:
                        r = ArtifactResult(name=key, status=ArtifactStatus.SKIPPED)
                        extraction_results[key] = r
                        progress.add_extraction_task(key, total=1)
                        progress.advance_extraction(key)
                        progress.complete_extraction(key)
                        logger.info(f"Skipping {key} (user requested)")
                        continue
                    futures[executor.submit(func)] = key

                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        extraction_results[key] = future.result()
                    except Exception as exc:
                        logger.error(f"Unexpected error in {key} extraction: {exc}", exc_info=True)
                        extraction_results[key] = ArtifactResult(
                            name=key,
                            status=ArtifactStatus.EXTRACT_FAILED,
                            error_message=str(exc),
                        )

        # ── Phase 2: Parsing ────────────────────────────────────────────
        self.console.print()
        self.console.print(
            Panel(
                "[bold magenta]🔬  Phase 2: Artifact Parsing (EZ Tools)[/bold magenta]",
                expand=False,
            )
        )

        with progress.parsing_progress:
            with ThreadPoolExecutor(
                max_workers=self.workers,
                thread_name_prefix="parse",
            ) as executor:
                futures = {}
                for key, func in parsing_map.items():
                    ext_result = extraction_results.get(key)
                    if ext_result is None or not ext_result.extraction_ok:
                        # Skip parsing if extraction failed or was skipped
                        if ext_result and ext_result.status == ArtifactStatus.SKIPPED:
                            progress.update_parsing_status(key, "[dim]Skipped[/dim]")
                            progress.fail_parsing(key, "Skipped by user")
                        else:
                            msg = ext_result.error_message if ext_result else "Not extracted"
                            progress.fail_parsing(key, f"Extraction failed: {msg}")
                        if ext_result:
                            self.results[key] = ext_result
                        continue
                    futures[executor.submit(func, ext_result)] = key

                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        self.results[key] = future.result()
                    except Exception as exc:
                        logger.error(f"Unexpected error in {key} parsing: {exc}", exc_info=True)
                        r = extraction_results[key]
                        r.status = ArtifactStatus.PARSE_FAILED
                        r.error_message = str(exc)
                        self.results[key] = r

        # Ensure all skipped/failed extractions are in results
        for key, r in extraction_results.items():
            if key not in self.results:
                self.results[key] = r

        logger.info("Pipeline execution complete")
        return self.results

    def display_summary(self) -> None:
        """Print a formatted execution summary table to the console."""
        self.console.print()

        table = Table(
            title="📊 FORENSIC ARTIFACT PARSER — EXECUTION SUMMARY",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_blue",
            title_style="bold white",
        )
        table.add_column("Artifact", style="bold", width=12)
        table.add_column("Extraction", justify="center", width=14)
        table.add_column("Parsing", justify="center", width=14)
        table.add_column("Files", justify="right", width=6)
        table.add_column("CSVs", justify="right", width=6)
        table.add_column("Duration", justify="right", width=10)

        total_csvs = 0
        total_time = 0.0

        for key in ["MFT", "Amcache", "Prefetch", "SRUMDB"]:
            r = self.results.get(key)
            if r is None:
                table.add_row(key, "[dim]—[/dim]", "[dim]—[/dim]", "—", "—", "—")
                continue

            total_csvs += r.csvs_generated
            total_time += r.total_time

            duration = self._format_duration(r.total_time)
            table.add_row(
                key,
                r.extraction_status_text,
                r.parsing_status_text,
                str(r.files_extracted) if r.files_extracted else "—",
                str(r.csvs_generated) if r.csvs_generated else "—",
                duration,
            )

        self.console.print(table)
        self.console.print()

        # Paths summary
        info_table = Table(box=None, show_header=False, padding=(0, 2))
        info_table.add_column("Label", style="bold")
        info_table.add_column("Value")
        info_table.add_row("📁 Output Location:", self.output_dir)
        info_table.add_row("📦 Raw Artifacts:", self.artifacts_dir)
        info_table.add_row("📊 Parsed CSVs:", self.parsed_dir)
        info_table.add_row(
            "📝 Execution Log:",
            os.path.join(self.output_dir, "forensic_parser.log"),
        )
        info_table.add_row("⏱  Total Duration:", self._format_duration(total_time))
        info_table.add_row("🔢 Total CSVs Generated:", str(total_csvs))
        self.console.print(info_table)
        self.console.print()

    def get_exit_code(self) -> int:
        """
        Determine the appropriate exit code based on results.

        Returns:
            0 if all artifacts completed, 1 if partial, 2 if all failed.
        """
        statuses = [r.status for r in self.results.values()]
        completed = sum(1 for s in statuses if s == ArtifactStatus.COMPLETE)
        skipped = sum(1 for s in statuses if s == ArtifactStatus.SKIPPED)
        total = len(statuses) - skipped

        if total == 0:
            return 0  # Everything was skipped
        if completed == total:
            return 0  # All succeeded
        if completed > 0:
            return 1  # Partial success
        return 2      # All failed

    # ── Internal helpers ────────────────────────────────────────────────

    def _log_tool_versions(self, logger: logging.Logger) -> None:
        """Attempt to capture EZ Tool version strings for audit logging."""
        for key, binary in EZ_TOOLS.items():
            tool_path = os.path.join(self.tools_dir, binary)
            if not os.path.isfile(tool_path):
                continue
            try:
                result = subprocess.run(
                    [tool_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if sys.platform == "win32" else 0
                    ),
                )
                version_line = (result.stdout or result.stderr or "").strip()
                if version_line:
                    # Take the first line only
                    first_line = version_line.split("\n")[0].strip()
                    logger.info(f"Tool version [{binary}]: {first_line}")
            except Exception:
                logger.debug(f"Could not determine version for {binary}")

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format a duration in seconds to 'Xm Ys' string."""
        if seconds < 0.01:
            return "< 1s"
        m, s = divmod(int(seconds), 60)
        if m > 0:
            return f"{m}m {s:02d}s"
        return f"{s}s"


# ─── CLI Argument Parsing ──────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="forensic_parser",
        description=(
            "🔍 Forensic Artifact Parser Agent — Extract and parse key Windows "
            "forensic artifacts using Eric Zimmerman's tools."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python forensic_parser.py -d E -o C:\\Cases\\Case001\\output\n"
            "  python forensic_parser.py -d F -o D:\\Output --tools-dir D:\\EZTools\n"
            "  python forensic_parser.py -d E -o .\\output --skip mft srum\n"
        ),
    )

    parser.add_argument(
        "-d", "--drive",
        required=True,
        help="Drive letter of the mounted forensic image (e.g., E or E:)"
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Path to the output directory (created if it doesn't exist)"
    )
    parser.add_argument(
        "--tools-dir",
        default=None,
        help="Path to directory containing EZ Tools executables (default: ./tools)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds for each EZ Tool execution (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Maximum concurrent workers (default: {DEFAULT_WORKERS})"
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        choices=["mft", "amcache", "prefetch", "srum"],
        default=[],
        help="Skip specific artifacts (e.g., --skip mft srum)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose console output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser.parse_args()


# ─── Entry Point ───────────────────────────────────────────────────────────────
def main() -> None:
    """Main entry point for the Forensic Artifact Parser Agent."""
    args = parse_args()
    console = Console()

    # Display banner
    console.print(BANNER, style="bold cyan")

    # Resolve tools directory
    if args.tools_dir:
        tools_dir = args.tools_dir
    else:
        # Default: ./tools relative to the script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        tools_dir = os.path.join(script_dir, "tools")

    # Display configuration
    drive = args.drive.rstrip(":").upper()
    config_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    config_table.add_column("Setting", style="bold cyan")
    config_table.add_column("Value")
    config_table.add_row("Source Drive", f"{drive}:\\")
    config_table.add_row("Output Directory", os.path.abspath(args.output))
    config_table.add_row("Tools Directory", os.path.abspath(tools_dir))
    config_table.add_row("Workers", str(args.workers))
    config_table.add_row("Timeout", f"{args.timeout}s")
    config_table.add_row("Skipped", ", ".join(args.skip) if args.skip else "none")
    console.print(config_table)
    console.print()

    # Create pipeline
    pipeline = ForensicPipeline(
        drive_letter=drive,
        output_dir=args.output,
        tools_dir=tools_dir,
        console=console,
        timeout=args.timeout,
        workers=args.workers,
        skip=args.skip,
        verbose=args.verbose,
    )

    # Run pre-flight checks
    console.print("[bold]Running pre-flight checks…[/bold]")
    errors = pipeline.preflight_checks()
    if errors:
        console.print()
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
        console.print()
        console.print(
            "[bold red]Pre-flight checks failed. "
            "Please fix the issues above and retry.[/bold red]"
        )
        sys.exit(2)
    console.print("  [green]✓[/green] All pre-flight checks passed\n")

    # Execute pipeline
    t_start = time.perf_counter()
    pipeline.run()
    t_total = time.perf_counter() - t_start

    # Display summary
    pipeline.display_summary()

    # Exit
    exit_code = pipeline.get_exit_code()
    if exit_code == 0:
        console.print("[bold green]✅ All artifacts processed successfully![/bold green]")
    elif exit_code == 1:
        console.print(
            "[bold yellow]⚠️  Some artifacts failed. "
            "Check the log for details.[/bold yellow]"
        )
    else:
        console.print(
            "[bold red]❌ All artifact processing failed. "
            "Check the log for details.[/bold red]"
        )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
