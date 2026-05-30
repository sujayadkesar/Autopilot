r"""
Shellbags Agent — Windows folder-browsing history.

Shellbags are registry artifacts created by Windows Explorer to remember view
preferences for folders. They survive folder/drive deletion: a folder browsed
on an external USB drive remains in shellbags even after the drive is unplugged
or the folder is deleted. They also record:

  - Network UNC paths (\\server\share)
  - ZIP archive contents the user expanded in Explorer
  - Encrypted/dismounted volumes that were previously mounted

Tool: SBECmd.exe (Eric Zimmerman) — drop in the tools/ directory.

Why a separate agent (vs. inside the registry agent)?
  Different parser, different output schema, different category in reports.
  Keeping it standalone makes it easy to disable independently.
"""

from __future__ import annotations

import logging
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
from core.fsutil import safe_exists, safe_iterdir, safe_is_dir
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner

log = logging.getLogger("dfir.shellbags")


class Agent(BaseAgent):
    name = "shellbags"
    display_name = "Shellbags (Folder Browsing)"
    description = "User folder-access history including removable & network paths"
    version = "1.0"
    artifact_subdirs = ["."]

    # ── extract ──────────────────────────────────────────────────────────

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []
        dest_dir = ctx.agent_artifacts_dir(self.name)
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Re-use registry agent's hive-copy strategy via shutil (NTUSER.DAT and
        # UsrClass.dat are user-specific). For locked hives the registry agent
        # already does heavy lifting; we just need a snapshot for SBECmd.
        users_dir = root / "Users"
        if not safe_exists(users_dir):
            progress.stage_done(self.name, "extract")
            return ExtractResult(agent=self.name, success=False,
                                 error="Users directory not found",
                                 elapsed=time.time() - t0)

        for user_dir in safe_iterdir(users_dir):
            if not safe_is_dir(user_dir):
                continue
            uname = user_dir.name
            for hive_rel, dest_pattern in [
                ("NTUSER.DAT", f"NTUSER_{uname}.DAT"),
                (r"AppData\Local\Microsoft\Windows\UsrClass.dat", f"USRCLASS_{uname}.DAT"),
            ]:
                src = user_dir / hive_rel
                if not safe_exists(src):
                    continue
                try:
                    dst = dest_dir / dest_pattern
                    shutil.copy2(str(src), str(dst))
                    copied.append(dst)
                    progress.log("INFO", self.name, f"Copied {dest_pattern}")
                except OSError as e:
                    errors.append(f"{dest_pattern}: {e}")
                    progress.log("WARNING", self.name, f"Copy {dest_pattern}: {e}")

        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=len(copied) > 0,
            artifacts=copied,
            elapsed=time.time() - t0,
            error="; ".join(errors[:5]),
            metadata={"hive_count": len(copied)},
        )

    # ── parse ─────────────────────────────────────────────────────────────

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        parsed_dir = ctx.agent_parsed_dir(self.name)
        parsed_dir.mkdir(parents=True, exist_ok=True)

        try:
            exe = runner.resolve("sbecmd")
        except ToolNotFoundError as e:
            progress.log("WARNING", self.name,
                         f"SBECmd.exe not found in tools/ — skipping shellbag parse: {e}")
            progress.stage_done(self.name, "parse")
            return ParseResult(agent=self.name, success=False,
                               error="SBECmd.exe missing", elapsed=time.time() - t0)

        # SBECmd accepts -d <hive_dir> --csv <out>; it scans every NTUSER.DAT /
        # UsrClass.dat in the directory and produces deduped CSVs per user.
        hive_dir = ctx.agent_artifacts_dir(self.name)
        if not list(hive_dir.glob("*.DAT")):
            progress.log("WARNING", self.name, "No hives to parse")
            progress.stage_done(self.name, "parse")
            return ParseResult(agent=self.name, success=False,
                               error="No hives", elapsed=time.time() - t0)

        cmd = [str(exe), "-d", str(hive_dir), "--csv", str(parsed_dir), "--nl"]
        try:
            rc, stdout, stderr = runner.run(cmd, "SBECmd", timeout=600, retries=1)
            progress.log("INFO", self.name, f"SBECmd RC={rc}")
        except ExecutionError as e:
            progress.log("WARNING", self.name, f"SBECmd failed: {str(e)[:200]}")
            progress.stage_done(self.name, "parse")
            return ParseResult(agent=self.name, success=False,
                               error=str(e), elapsed=time.time() - t0)

        produced = list(parsed_dir.rglob("*.csv"))
        progress.log("INFO", self.name, f"Shellbags: {len(produced)} CSV(s) produced")
        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=len(produced) > 0,
            output_files=produced,
            elapsed=time.time() - t0,
            metadata={"parsed_count": len(produced)},
        )
