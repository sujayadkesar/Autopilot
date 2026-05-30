"""Universal finding schema — every agent emits this shape."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Literal, Optional


@dataclass
class Finding:
    agent: str
    artifact: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str
    detail: str
    ioc: str = ""
    timestamp: Optional[datetime] = None
    source_row: Optional[Dict[str, Any]] = field(default=None, repr=False)
    risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.timestamp:
            d["timestamp"] = self.timestamp.isoformat()
        return d

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_llm(
        cls,
        agent: str,
        artifact: str,
        raw: Dict[str, Any],
        risk_score: int = 0,
    ) -> "Finding":
        """Construct from a single LLM findings-array entry."""
        sev = str(raw.get("severity", "INFO")).upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "INFO"
        return cls(
            agent=agent,
            artifact=artifact,
            severity=sev,  # type: ignore[arg-type]
            title=str(raw.get("title", "")),
            detail=str(raw.get("detail", "")),
            ioc=str(raw.get("ioc", "")),
            risk_score=risk_score,
        )


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
