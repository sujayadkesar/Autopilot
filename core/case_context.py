"""CaseContext — single source of truth for a pipeline run."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional

# Repo root = directory containing this file's parent
_REPO_ROOT = Path(__file__).parent.parent


@dataclass
class CaseContext:
    mount_point: Path
    output_dir: Path
    investigation_prompt: str = ""
    llm_model: str = ""           # optional — empty string means "no AI"
    customer_name: str = "Unknown"
    investigation_date: date = field(default_factory=date.today)
    case_reference: str = ""
    enabled_agents: List[str] = field(default_factory=list)

    # Case-profile selection (dlp, malware, phishing, ransomware, lateral, generic)
    case_profile: str = "generic"
    # User-supplied profile-specific keywords: {prompt_key: multiline_text}
    profile_keywords: dict = field(default_factory=dict)

    # Report output formats. "html" always produced; "pdf" requires Playwright + Chromium.
    report_formats: List[str] = field(default_factory=lambda: ["html"])
    # Malware-analysis options (capa/yara). Keys:
    #   run_capa: bool, run_yara: bool,
    #   sample_dirs: List[str]  (extra on-image dirs to capa/yara-scan),
    #   yara_rules: List[str]   (extra .yar/.yara rule file or dir paths)
    malware_opts: dict = field(default_factory=dict)

    # Derived paths (computed in __post_init__)
    artifacts_dir: Path = field(init=False)
    parsed_dir: Path = field(init=False)
    reports_dir: Path = field(init=False)
    tools_dir: Path = field(init=False)
    workers: int = field(init=False)

    def __post_init__(self):
        self.mount_point = Path(self.mount_point)
        self.output_dir = Path(self.output_dir)
        self.artifacts_dir = self.output_dir / "artifacts"
        self.parsed_dir = self.output_dir / "parsed_artifacts"
        self.reports_dir = self.output_dir / "reports"
        self.tools_dir = _REPO_ROOT / "tools"
        self.workers = os.cpu_count() or 4
        if not self.case_reference:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            self.case_reference = f"DFIR-{stamp}"

    def ensure_dirs(self) -> None:
        for d in (self.artifacts_dir, self.parsed_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)

    def agent_artifacts_dir(self, agent_name: str) -> Path:
        p = self.artifacts_dir / agent_name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def agent_parsed_dir(self, agent_name: str) -> Path:
        p = self.parsed_dir / agent_name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def to_dict(self) -> dict:
        return {
            "mount_point": str(self.mount_point),
            "output_dir": str(self.output_dir),
            "llm_model": self.llm_model,
            "customer_name": self.customer_name,
            "investigation_date": self.investigation_date.isoformat(),
            "case_reference": self.case_reference,
            "enabled_agents": self.enabled_agents,
            "workers": self.workers,
            "case_profile": self.case_profile,
            "profile_keywords_supplied": [k for k, v in self.profile_keywords.items() if v],
        }
