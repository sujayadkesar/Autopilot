"""
Prefetch / Amcache / MFT / SRUM Agent.
Wraps forensic_prefetch-amcache-mft.py logic into BaseAgent.
"""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path
from typing import List

_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.fsutil import safe_exists, safe_glob
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner

ARTIFACT_SOURCES = {
    "mft": [
        {"rel": "$MFT", "required": True},
    ],
    "amcache": [
        {"rel": "Windows/AppCompat/Programs/Amcache.hve", "required": True},
        {"rel": "Windows/AppCompat/Programs/Amcache.hve.LOG1", "required": False},
        {"rel": "Windows/AppCompat/Programs/Amcache.hve.LOG2", "required": False},
    ],
    "prefetch": None,  # directory glob
    "srum": [
        {"rel": "Windows/System32/sru/SRUDB.dat", "required": True},
        {"rel": "Windows/System32/config/SOFTWARE", "required": False},
    ],
}

# SRUM ESE log files — required for esentutl recovery
SRU_LOG_PATTERNS = ["SRU*.log", "SRU*.LOG", "sru*.log", "sru.chk", "SRU.chk"]

PREFETCH_DIR = "Windows/Prefetch"


class Agent(BaseAgent):
    name = "prefetch_amcache_mft"
    display_name = "Prefetch / Amcache / MFT / SRUM"
    description = "$MFT, Amcache.hve, Prefetch .pf files, SRUDB.dat — program execution history"
    version = "1.0"
    artifact_subdirs = ["mft", "amcache", "prefetch", "srum"]

    # ── extract ──────────────────────────────────────────────────────────

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []

        # File-based artifacts
        # NOTE: $MFT is a locked NTFS system file; Python APIs (shutil, Path.exists) cannot
        # access it even as admin. MFTECmd uses raw volume access and reads it directly.
        # We skip copying $MFT here — _parse_mft() runs MFTECmd directly on the mount point.
        for artifact, sources in ARTIFACT_SOURCES.items():
            if sources is None:
                continue
            if artifact == "mft":
                continue  # parsed directly from mount point in _parse_mft()
            dest_dir = ctx.agent_artifacts_dir(self.name) / artifact
            dest_dir.mkdir(parents=True, exist_ok=True)
            for spec in sources:
                rel = spec["rel"].replace("/", "\\")
                src = root / rel
                if not safe_exists(src):
                    src = root / spec["rel"]
                if not safe_exists(src):
                    if spec["required"]:
                        errors.append(f"Required artifact not found: {rel}")
                        progress.log("WARNING", self.name, f"Not found: {rel}")
                    continue
                try:
                    dst = dest_dir / src.name
                    shutil.copy2(str(src), str(dst))
                    copied.append(dst)
                    progress.log("INFO", self.name, f"Copied {artifact}/{src.name}")
                except OSError as e:
                    # I/O device errors mid-copy — log and keep going
                    errors.append(f"Copy failed: {src}: {e}")
                    progress.log("WARNING", self.name, f"Copy error ({e.__class__.__name__}): {e}")
                except Exception as e:
                    errors.append(f"Copy failed: {src}: {e}")
                    progress.log("ERROR", self.name, f"Copy error: {e}")

        # SRU log files (.log/.chk) — needed for esentutl recovery if SRUDB is dirty
        sru_src = root / "Windows" / "System32" / "sru"
        srum_dest = ctx.agent_artifacts_dir(self.name) / "srum"
        if safe_exists(sru_src):
            sru_log_count = 0
            for pat in SRU_LOG_PATTERNS:
                for log_file in safe_glob(sru_src, pat):
                    try:
                        shutil.copy2(str(log_file), str(srum_dest / log_file.name))
                        copied.append(srum_dest / log_file.name)
                        sru_log_count += 1
                    except OSError as e:
                        errors.append(f"SRU log copy {log_file.name}: {e}")
            if sru_log_count:
                progress.log("INFO", self.name, f"Copied {sru_log_count} SRU log/chk file(s) for ESE recovery")

        # Prefetch directory
        pf_src = root / PREFETCH_DIR.replace("/", "\\")
        if not safe_exists(pf_src):
            pf_src = root / PREFETCH_DIR
        if safe_exists(pf_src):
            pf_dest = ctx.agent_artifacts_dir(self.name) / "prefetch"
            pf_dest.mkdir(parents=True, exist_ok=True)
            count = 0
            for pf_file in safe_glob(pf_src, "*.pf"):
                try:
                    dst = pf_dest / pf_file.name
                    shutil.copy2(str(pf_file), str(dst))
                    copied.append(dst)
                    count += 1
                except OSError as e:
                    errors.append(f"Prefetch copy error {pf_file.name}: {e}")
            progress.log("INFO", self.name, f"Copied {count} prefetch files")
        else:
            progress.log("WARNING", self.name, "Prefetch directory not found")

        # MFT is parsed directly from mount point — count it as a virtual artifact
        mft_src = root / "$MFT"
        progress.log("INFO", self.name, f"MFT will be parsed directly from {mft_src} (raw volume access via MFTECmd)")

        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=True,  # MFT is always attempted; other artifacts copied above
            artifacts=copied,
            elapsed=time.time() - t0,
            error="; ".join(errors),
            metadata={"copied_count": len(copied), "mft_source": str(mft_src)},
        )

    # ── parse ─────────────────────────────────────────────────────────────

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        art_dir = ctx.agent_artifacts_dir(self.name)
        parsed_dir = ctx.agent_parsed_dir(self.name)
        output_files: List[Path] = []
        errors: List[str] = []

        parse_tasks = [
            ("mft",      self._parse_mft,     art_dir / "mft",      parsed_dir / "mft"),
            ("amcache",  self._parse_amcache,  art_dir / "amcache",  parsed_dir / "amcache"),
            ("prefetch", self._parse_prefetch, art_dir / "prefetch", parsed_dir / "prefetch"),
            ("srum",     self._parse_srum,     art_dir / "srum",     parsed_dir / "srum"),
        ]

        total = len(parse_tasks)
        for i, (name, fn, in_dir, out_dir) in enumerate(parse_tasks, 1):
            out_dir.mkdir(parents=True, exist_ok=True)
            progress.stage_progress(self.name, "parse", (i / total) * 100, f"Parsing {name}")
            try:
                new_files = fn(runner, in_dir, out_dir, ctx)
                output_files.extend(new_files)
                progress.log("INFO", self.name, f"{name}: {len(new_files)} output files")
            except ToolNotFoundError as e:
                errors.append(f"{name}: Tool not found — {e}")
                progress.log("WARNING", self.name, f"{name}: Tool not found: {e}")
            except ExecutionError as e:
                errors.append(f"{name}: Parse failed — {e}")
                progress.log("WARNING", self.name, f"{name}: Parse failed: {e}")
            except Exception as e:
                errors.append(f"{name}: Unexpected error — {e}")
                progress.log("ERROR", self.name, f"{name}: Error: {e}")

        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=len(output_files) > 0,
            output_files=output_files,
            elapsed=time.time() - t0,
            error="; ".join(errors),
            metadata={"parsed_count": len(output_files)},
        )

    # ── parse helpers ─────────────────────────────────────────────────────

    def _parse_mft(self, runner: ToolRunner, in_dir: Path, out_dir: Path, ctx: CaseContext) -> List[Path]:
        # $MFT cannot be copied by Python APIs (locked NTFS system file).
        # MFTECmd opens the volume directly via raw device handle — pass the source path.
        mft = ctx.mount_point / "$MFT"
        exe = runner.resolve("mftecmd")
        runner.run(
            [str(exe), "-f", str(mft), "--csv", str(out_dir)],
            "MFT", timeout=600,
        )
        return list(out_dir.glob("*.csv"))

    def _parse_amcache(self, runner: ToolRunner, in_dir: Path, out_dir: Path, ctx: CaseContext) -> List[Path]:
        hive = in_dir / "Amcache.hve"
        if not hive.exists():
            return []
        exe = runner.resolve("amcacheparser")
        runner.run(
            [str(exe), "-f", str(hive), "-i", "--csv", str(out_dir)],
            "Amcache", timeout=300,
        )
        return list(out_dir.glob("*.csv"))

    def _parse_prefetch(self, runner: ToolRunner, in_dir: Path, out_dir: Path, ctx: CaseContext) -> List[Path]:
        if not in_dir.exists() or not any(in_dir.glob("*.pf")):
            return []
        exe = runner.resolve("pecmd")
        runner.run(
            [str(exe), "-d", str(in_dir), "--csv", str(out_dir)],
            "Prefetch", timeout=300,
        )
        return list(out_dir.glob("*.csv"))

    def _parse_srum(self, runner: ToolRunner, in_dir: Path, out_dir: Path, ctx: CaseContext) -> List[Path]:
        import logging as _logging
        _log = _logging.getLogger("dfir.srum")
        srudb = in_dir / "SRUDB.dat"
        if not srudb.exists():
            _log.warning("SRUDB.dat not found at %s", srudb)
            return []

        # SRUDB.dat is almost always "dirty" because Windows didn't shut down cleanly.
        # esentutl (built into Windows) replays logs to bring the DB to a consistent state.
        self._repair_ese_database(srudb, in_dir)

        exe = runner.resolve("srumecmd")
        cmd = [str(exe), "-f", str(srudb)]
        sw = in_dir / "SOFTWARE"
        if sw.exists():
            cmd += ["-r", str(sw)]
        cmd += ["--csv", str(out_dir)]

        try:
            rc, stdout, stderr = runner.run(cmd, "SRUM", timeout=300)
            _log.info("SrumECmd RC=%d, stdout: %s", rc, (stdout or "")[:500])
            if stderr:
                _log.info("SrumECmd stderr: %s", stderr[:500])
        except Exception as e:
            _log.warning("SrumECmd execution failed: %s", e)

        # SrumECmd writes to subdirectories sometimes — recursive glob
        produced = list(out_dir.rglob("*.csv"))
        if not produced:
            _log.warning("SrumECmd produced no CSVs. Output dir: %s. "
                        "Check pipeline.log for esentutl repair messages.", out_dir)
        else:
            _log.info("SRUM produced %d CSV(s)", len(produced))
        return produced

    def _repair_ese_database(self, edb_path: Path, log_dir: Path) -> None:
        """Soft- then hard-repair an ESE database (e.g. SRUDB.dat) using esentutl.exe.

        SrumECmd refuses to parse dirty/inconsistent databases. esentutl is shipped
        with Windows and can replay log files to bring the DB to a consistent state.
        """
        import subprocess as _sp
        import platform as _pf
        import logging as _logging
        _log = _logging.getLogger("dfir.srum")

        if _pf.system() != "Windows":
            return
        esentutl = Path(r"C:\Windows\System32\esentutl.exe")
        if not esentutl.exists():
            _log.warning("esentutl.exe not found — skipping SRUDB repair")
            return

        flags = _sp.CREATE_NO_WINDOW

        # Step 1: Check header to see if dirty
        try:
            mh = _sp.run(
                [str(esentutl), "/mh", str(edb_path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30, creationflags=flags,
            )
            header = (mh.stdout or "") + (mh.stderr or "")
            is_dirty = ("State: Dirty" in header) or ("inconsistent" in header.lower()) or \
                       ("Shutdown" in header and "Dirty" in header)
            _log.info("SRUDB header check: dirty=%s", is_dirty)
        except Exception as e:
            _log.warning("esentutl /mh failed (will still try repair): %s", e)
            is_dirty = True  # err on side of attempting repair

        if not is_dirty:
            return

        # Step 2: Soft recovery — replay log files. The Eric-Zimmerman-documented
        # syntax for SRUDB recovery is `esentutl /r sru /i` run from the directory
        # containing SRUDB.dat + SRU*.log files. The /i (ignore-missing) flag is
        # required because the recovery context references a database that
        # doesn't quite match the snapshot — without /i the recovery refuses with
        # "outstanding database attachment ... missing or does not match attachment info".
        try:
            r = _sp.run(
                [str(esentutl), "/r", "sru", "/i"],
                cwd=str(log_dir),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=120, creationflags=flags,
            )
            _log.info("esentutl /r sru /i RC=%d: %s", r.returncode, (r.stdout or "")[:200])
            mh2 = _sp.run(
                [str(esentutl), "/mh", str(edb_path)],
                cwd=str(log_dir),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30, creationflags=flags,
            )
            if "State: Clean Shutdown" in (mh2.stdout or ""):
                _log.info("SRUDB recovered to clean state via soft recovery")
                return
        except Exception as e:
            _log.warning("esentutl /r failed: %s", e)

        # Step 3: Hard repair — `esentutl /p SRUDB.dat /o`. The /o suppresses the
        # interactive "OK to repair?" prompt. Must be run from the same dir as
        # the .dat so it can find the temp working files.
        try:
            r = _sp.run(
                [str(esentutl), "/p", edb_path.name, "/o"],
                cwd=str(log_dir),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=300, creationflags=flags,
            )
            _log.info("esentutl /p (hard repair) RC=%d: %s",
                      r.returncode, (r.stdout or "")[:200])
        except Exception as e:
            _log.warning("esentutl /p failed: %s", e)
