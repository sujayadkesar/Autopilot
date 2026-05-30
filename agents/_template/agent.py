"""
Template Agent — copy this folder to agents/<your_name>/ and implement
the two required methods: extract() and parse().
analyze() and report() have working defaults — override only if needed.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import List

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner


class Agent(BaseAgent):
    # ── Required class attributes ─────────────────────────────────────────
    name = "my_agent"               # must match folder name and manifest.yaml
    display_name = "My Agent"       # shown in GUI
    description = "What I extract"
    version = "1.0"
    artifact_subdirs = ["my_artifact_type"]

    # ── Required: extract ─────────────────────────────────────────────────
    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        """Copy raw artifacts from ctx.mount_point to ctx.agent_artifacts_dir(self.name)."""
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        dest = ctx.agent_artifacts_dir(self.name) / "my_artifact_type"
        dest.mkdir(parents=True, exist_ok=True)
        copied: List[Path] = []

        # Example: copy a single file
        src = ctx.mount_point / "Windows" / "SomeFile.dat"
        if src.exists():
            dst = dest / src.name
            shutil.copy2(str(src), str(dst))
            copied.append(dst)
            progress.log("INFO", self.name, f"Copied {src.name}")
        else:
            progress.log("WARNING", self.name, f"Artifact not found: {src}")

        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=len(copied) > 0,
            artifacts=copied,
            elapsed=time.time() - t0,
        )

    # ── Required: parse ───────────────────────────────────────────────────
    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        """Run EZ Tools / python parsers; write CSVs to ctx.agent_parsed_dir(self.name)."""
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        art_dir = ctx.agent_artifacts_dir(self.name) / "my_artifact_type"
        out_dir = ctx.agent_parsed_dir(self.name)
        out_dir.mkdir(parents=True, exist_ok=True)
        output_files: List[Path] = []

        # Example: run MFTECmd (replace with whatever tool you need)
        try:
            exe = runner.resolve("mftecmd")   # key from core/tool_runner.py TOOL_NAMES
            target = art_dir / "SomeFile.dat"
            if target.exists():
                runner.run(
                    [str(exe), "-f", str(target), "--csv", str(out_dir)],
                    artifact_name="MyArtifact",
                    timeout=300,
                )
                output_files.extend(out_dir.glob("*.csv"))
        except ToolNotFoundError as e:
            progress.log("WARNING", self.name, f"Tool not found: {e}")
        except ExecutionError as e:
            progress.log("ERROR", self.name, f"Parse failed: {e}")

        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=len(output_files) > 0,
            output_files=output_files,
            elapsed=time.time() - t0,
        )

    # ── Optional: analyze ────────────────────────────────────────────────
    # Uncomment and override if you need custom LLM prompting.
    # The default sends every CSV/JSON in your parsed_dir to the LLM.
    #
    # def analyze(self, ctx, parse_result, llm, progress):
    #     from core.finding import Finding
    #     progress.stage_started(self.name, "analyze")
    #     findings = []
    #     # ... custom logic ...
    #     progress.stage_done(self.name, "analyze")
    #     return findings

    # ── Optional: report ─────────────────────────────────────────────────
    # Uncomment and override if you need a custom HTML layout.
    # The default renders agents/registry/manifest.yaml and your findings.
    #
    # def report(self, ctx, findings, parse_result):
    #     from pathlib import Path
    #     # ... custom HTML build ...
    #     return Path("path/to/my_report.html")
