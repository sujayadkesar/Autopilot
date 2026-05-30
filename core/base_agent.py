"""
BaseAgent — the contribution contract for forensic agents.

Every agent is a folder under agents/<name>/ exporting an Agent class
that subclasses BaseAgent. Minimum required: extract() and parse().
analyze() and report() have defaults that work without overriding.
"""

from __future__ import annotations

import csv
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .case_context import CaseContext
from .finding import Finding
from .llm_client import LLMClient
from .progress_bus import ProgressBus

log = logging.getLogger("dfir.agent")


@dataclass
class ExtractResult:
    agent: str
    success: bool
    artifacts: List[Path] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    agent: str
    success: bool
    output_files: List[Path] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    system_info: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    name: str = "base"
    display_name: str = "Base Agent"
    description: str = ""
    version: str = "1.0"
    artifact_subdirs: List[str] = []

    @abstractmethod
    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        """Copy raw artifacts from ctx.mount_point to ctx.artifacts_dir/<name>/."""

    @abstractmethod
    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        """Run EZ Tools / python parsers; write CSVs/JSONLs to ctx.parsed_dir/<name>/."""

    def analyze(
        self,
        ctx: CaseContext,
        parse_result: ParseResult,
        llm: LLMClient,
        progress: ProgressBus,
    ) -> List[Finding]:
        """
        Default: chunk every CSV/JSON in parsed_dir/<name>/ → LLM → Finding list.
        Override for custom prompting (e.g. registry agent's deep per-artifact prompts).
        """
        progress.stage_started(self.name, "analyze")
        findings: List[Finding] = []
        parsed_dir = ctx.agent_parsed_dir(self.name)
        files = list(parsed_dir.rglob("*.csv")) + list(parsed_dir.rglob("*.json")) + list(parsed_dir.rglob("*.jsonl"))

        if not files:
            progress.log("WARNING", self.name, "No parsed files found — skipping AI analysis")
            progress.stage_done(self.name, "analyze")
            return findings

        for i, f in enumerate(files, 1):
            pct = (i / len(files)) * 100
            progress.stage_progress(self.name, "analyze", pct, f.name)
            data = self._load_file_sample(f)
            if not data:
                continue
            try:
                result = llm.analyze_chunk(self.name, f.stem, data)
                for raw in result.findings_raw:
                    finding = Finding.from_llm(self.name, f.stem, raw, result.risk_score)
                    findings.append(finding)
                    progress.finding_added(self.name, len(findings), finding.severity)
            except Exception as e:
                progress.log("WARNING", self.name, f"LLM analysis failed for {f.name}: {e}")

        progress.stage_done(self.name, "analyze")
        return findings

    def report(
        self,
        ctx: CaseContext,
        findings: List[Finding],
        parse_result: ParseResult,
    ) -> Path:
        """
        Default: render per-agent HTML using the base Jinja2 template.
        Override to produce a custom layout (like the rich registry report).
        """
        from .report.agent_report import render_agent_report
        return render_agent_report(self, ctx, findings, parse_result)

    @staticmethod
    def _load_file_sample(path: Path, max_rows: int = 200) -> Any:
        """Load a CSV/JSON sample for LLM analysis."""
        suffix = path.suffix.lower()
        try:
            if suffix == ".csv":
                rows = []
                with open(path, encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        rows.append(dict(row))
                        if len(rows) >= max_rows:
                            break
                return rows
            elif suffix in (".json", ".jsonl"):
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read(32 * 1024)
                if suffix == ".jsonl":
                    lines = [json.loads(l) for l in content.splitlines() if l.strip()]
                    return lines[:max_rows]
                return json.loads(content)
        except Exception as e:
            log.debug("Could not load %s: %s", path, e)
        return None
