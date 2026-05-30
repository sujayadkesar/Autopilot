"""
ToolRunner — robust EZ Tools subprocess wrapper.
Lifted and centralised from forensic_usn-lnk-mru_FIXED.py:266-460.

Tools directory is always <repo_root>/tools/ — no user input.
"""

from __future__ import annotations

import glob as _glob
import logging
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("dfir.tools")

MAX_RETRIES = 3
RETRY_DELAY_SEC = 2.0

RETRY_ABORT_MARKERS = (
    "access denied",
    "file not found",
    "invalid choice",
    "not found. exiting",
    "unrecognized arguments",
    "unicodeencodeerror",
)

TOOL_NAMES = {
    "mftecmd":        "MFTECmd.exe",
    "amcacheparser":  "AmcacheParser.exe",
    "pecmd":          "PECmd.exe",
    "srumecmd":       "SrumECmd.exe",
    "recmd":          "RECmd.exe",
    "lecmd":          "LECmd.exe",
    "evtxecmd":       "EvtxECmd.exe",
    "hindsight":      "hindsight.exe",
    # Additional EZ Tools
    "sbecmd":         "SBECmd.exe",         # Shellbags
    "jlecmd":         "JLECmd.exe",         # Jump Lists
    "wxtcmd":         "WxTCmd.exe",         # Win10 ActivitiesCache
    "appcompatcacheparser": "AppCompatCacheParser.exe",  # ShimCache
    # Threat-hunting
    "hayabusa":       "hayabusa.exe",       # Sigma-rule event log threat hunter
    "chainsaw":       "chainsaw.exe",       # Alternative event log hunter
    # Malware capability analysis
    "capa":           "capa.exe",           # Mandiant FLARE capability + ATT&CK extractor
}

RECMD_BATCH_CANDIDATES = (
    "DFIRBatch.reb",
    "RECmd_Batch_MC.reb",
)


class ForensicError(Exception):
    pass


class ToolNotFoundError(ForensicError):
    pass


class ExecutionError(ForensicError):
    def __init__(self, message: str, *, returncode: Optional[int] = None, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ToolRunner:
    def __init__(self, tools_dir: Path, retries: int = MAX_RETRIES):
        self.tools_dir = Path(tools_dir)
        self._retries = retries

    def resolve(self, tool_key: str) -> Path:
        name = TOOL_NAMES.get(tool_key.lower())
        if not name:
            raise ToolNotFoundError(f"Unknown tool key: {tool_key}")
        exe = self.tools_dir / name
        if not exe.is_file():
            raise ToolNotFoundError(
                f"Tool '{name}' not found in {self.tools_dir}\n"
                f"  Expected: {exe}\n"
                "  → Place EZ Tools binaries in the tools/ directory at the repo root."
            )
        return exe

    def resolve_recmd_batch(self, explicit: Optional[Path] = None) -> Path:
        candidates: List[Path] = []
        if explicit:
            candidates.append(explicit if explicit.is_absolute() else self.tools_dir / explicit)
        for parent in (self.tools_dir, self.tools_dir / "BatchExamples"):
            for name in RECMD_BATCH_CANDIDATES:
                candidates.append(parent / name)
        for c in candidates:
            if c.is_file():
                return c
        searched = "\n".join(f"  {c}" for c in candidates)
        raise ToolNotFoundError(f"RECmd batch file not found.\nSearched:\n{searched}")

    @staticmethod
    def _snapshot(paths: Sequence[Path]) -> Dict[Path, Tuple[bool, Optional[int], Optional[int]]]:
        snap = {}
        for p in paths:
            try:
                st = p.stat()
                snap[p] = (True, st.st_mtime_ns, st.st_size)
            except FileNotFoundError:
                snap[p] = (False, None, None)
        return snap

    @staticmethod
    def _validate(paths: Sequence[Path], snap: Dict) -> Optional[str]:
        if not paths:
            return None
        missing, stale = [], []
        for p in paths:
            try:
                st = p.stat()
            except FileNotFoundError:
                missing.append(str(p))
                continue
            existed, mtime, size = snap.get(p, (False, None, None))
            if existed and st.st_mtime_ns == mtime and st.st_size == size:
                stale.append(str(p))
        if missing:
            return "Missing: " + ", ".join(missing)
        if stale:
            return "Not updated: " + ", ".join(stale)
        return None

    def run(
        self,
        cmd: List[str],
        artifact_name: str,
        timeout: int = 600,
        expected_outputs: Optional[Sequence[Path]] = None,
        failure_markers: Optional[Sequence[str]] = None,
        no_retry_markers: Sequence[str] = RETRY_ABORT_MARKERS,
        retries: Optional[int] = None,
        env: Optional[dict] = None,
        log_file: Optional[Path] = None,
    ) -> Tuple[int, str, str]:
        """Run a tool with retry, validation, and (optionally) UTF-8 output redirection.

        log_file: if set, redirect stdout+stderr through `cmd.exe` to this file
                  using UTF-8 codepage 65001. Required for tools like hindsight.exe
                  which use Rich and crash on cp1252-piped stdout.
        """
        out_paths = [Path(p) for p in (expected_outputs or [])]
        snap = self._snapshot(out_paths)
        effective = max(1, retries if retries is not None else self._retries)
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0

        cmd_str = " ".join(f'"{c}"' if " " in str(c) else str(c) for c in cmd)
        log.debug("[%s] CMD: %s", artifact_name, cmd_str)

        # Build the shell wrapper for tools that need UTF-8 console (Hindsight)
        if log_file is not None and platform.system() == "Windows":
            log_file.parent.mkdir(parents=True, exist_ok=True)
            quoted = " ".join(f'"{c}"' if (" " in str(c) or "\\" in str(c)) else str(c) for c in cmd)
            shell_cmd = f'chcp 65001 >nul 2>&1 && {quoted} > "{log_file}" 2>&1'

        last_exc: Optional[ExecutionError] = None
        for attempt in range(1, effective + 1):
            retryable = True
            try:
                if log_file is not None and platform.system() == "Windows":
                    proc = subprocess.run(
                        shell_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=timeout,
                        creationflags=creationflags,
                        env=env,
                    )
                    # Read tool's output from the redirected file (best-effort)
                    try:
                        file_text = log_file.read_text(encoding="utf-8", errors="replace")
                        proc = subprocess.CompletedProcess(
                            args=cmd,
                            returncode=proc.returncode,
                            stdout=file_text,
                            stderr="",
                        )
                    except Exception:
                        pass
                else:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=timeout,
                        creationflags=creationflags,
                        env=env,
                    )
                combined = "\n".join(p for p in (proc.stdout, proc.stderr) if p)
                lower = combined.lower()
                has_abort = any(m in lower for m in no_retry_markers)

                if proc.returncode == 0:
                    if failure_markers and any(m.lower() in lower for m in failure_markers):
                        last_exc = ExecutionError(f"[{artifact_name}] failure marker in output", returncode=0, stdout=proc.stdout, stderr=proc.stderr)
                    else:
                        issue = self._validate(out_paths, snap)
                        if issue is None:
                            return proc.returncode, proc.stdout, proc.stderr
                        last_exc = ExecutionError(f"[{artifact_name}] {issue}", returncode=0, stdout=proc.stdout, stderr=proc.stderr)
                    if has_abort:
                        break
                else:
                    last_exc = ExecutionError(f"[{artifact_name}] RC={proc.returncode}. {proc.stderr[:300]}", returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
                    if has_abort:
                        break

                log.warning("[%s] attempt %d/%d failed: %s", artifact_name, attempt, effective, last_exc)

            except subprocess.TimeoutExpired as exc:
                last_exc = ExecutionError(f"[{artifact_name}] timeout after {timeout}s", stdout=exc.stdout or "", stderr=exc.stderr or "")
                log.warning("[%s] timeout on attempt %d/%d", artifact_name, attempt, effective)
            except FileNotFoundError:
                raise ToolNotFoundError(f"Executable not found: {cmd[0]}")
            except Exception as exc:
                last_exc = ExecutionError(f"[{artifact_name}] unexpected: {exc}")
                log.warning("[%s] unexpected error attempt %d/%d: %s", artifact_name, attempt, effective, exc)

            if attempt < effective and retryable:
                delay = RETRY_DELAY_SEC * attempt
                log.info("[%s] retrying in %.1fs…", artifact_name, delay)
                time.sleep(delay)

        raise ExecutionError(
            f"[{artifact_name}] all {effective} attempt(s) failed. Last: {last_exc}",
            returncode=last_exc.returncode if last_exc else None,
            stdout=last_exc.stdout if last_exc else "",
            stderr=last_exc.stderr if last_exc else "",
        ) from last_exc


def discover_paths(base: Path, pattern: str) -> List[Path]:
    return [Path(p) for p in _glob.glob(str(base / pattern), recursive=True)]
