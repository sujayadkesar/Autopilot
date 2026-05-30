r"""
Windows Timeline Agent — ActivitiesCache.db via WxTCmd.

ActivitiesCache.db (an ESE database) backs the Windows 10/11 Timeline / Activity
History feature, recording applications used and files opened per user. Located at:
  \Users\<user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db

Tool: WxTCmd.exe (Eric Zimmerman) — drop in tools/.
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
from core.fsutil import safe_exists, safe_glob, safe_iterdir, safe_is_dir
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner


class Agent(BaseAgent):
    name = "timeline"
    display_name = "Windows Timeline (ActivitiesCache)"
    description = "App/file usage history from ActivitiesCache.db (Windows Timeline)"
    version = "1.0"
    artifact_subdirs = ["."]

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []
        dest = ctx.agent_artifacts_dir(self.name)
        dest.mkdir(parents=True, exist_ok=True)

        users_dir = root / "Users"
        if not safe_exists(users_dir):
            progress.stage_done(self.name, "extract")
            return ExtractResult(agent=self.name, success=False,
                                 error="Users directory not found", elapsed=time.time() - t0)

        for user_dir in safe_iterdir(users_dir):
            if not safe_is_dir(user_dir):
                continue
            cdp = user_dir / "AppData" / "Local" / "ConnectedDevicesPlatform"
            if not safe_exists(cdp):
                continue
            for ldir in safe_iterdir(cdp):
                if not safe_is_dir(ldir):
                    continue
                for db in safe_glob(ldir, "ActivitiesCache.db"):
                    try:
                        dst = dest / f"{user_dir.name}_ActivitiesCache.db"
                        shutil.copy2(str(db), str(dst))
                        copied.append(dst)
                        progress.log("INFO", self.name, f"Copied {dst.name}")
                    except OSError as e:
                        errors.append(f"{db}: {e}")

        progress.stage_done(self.name, "extract")
        return ExtractResult(agent=self.name, success=len(copied) > 0, artifacts=copied,
                             elapsed=time.time() - t0, error="; ".join(errors[:5]),
                             metadata={"db_count": len(copied)})

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        parsed_dir = ctx.agent_parsed_dir(self.name)
        parsed_dir.mkdir(parents=True, exist_ok=True)
        output_files: List[Path] = []

        try:
            exe = runner.resolve("wxtcmd")
        except ToolNotFoundError as e:
            progress.log("WARNING", self.name, f"WxTCmd.exe not found — skipping: {e}")
            progress.stage_done(self.name, "parse")
            return ParseResult(agent=self.name, success=False, error="WxTCmd.exe missing",
                               elapsed=time.time() - t0)

        for db in ctx.agent_artifacts_dir(self.name).glob("*ActivitiesCache.db"):
            try:
                runner.run([str(exe), "-f", str(db), "--csv", str(parsed_dir)],
                           f"WxTCmd_{db.stem}", timeout=300, retries=1)
            except ExecutionError as e:
                progress.log("WARNING", self.name, f"WxTCmd failed on {db.name}: {str(e)[:160]}")

        output_files = list(parsed_dir.rglob("*.csv"))
        progress.log("INFO", self.name, f"Timeline: {len(output_files)} CSV(s)")
        progress.stage_done(self.name, "parse")
        return ParseResult(agent=self.name, success=bool(output_files),
                           output_files=output_files, elapsed=time.time() - t0,
                           metadata={"parsed_count": len(output_files)})
