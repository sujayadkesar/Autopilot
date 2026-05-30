"""Default per-agent HTML report builder (Jinja2-based)."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, List

from jinja2 import Environment, FileSystemLoader

from ..finding import Finding, SEVERITY_ORDER

if TYPE_CHECKING:
    from ..base_agent import BaseAgent, ParseResult
    from ..case_context import CaseContext

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )


def render_agent_report(
    agent: "BaseAgent",
    ctx: "CaseContext",
    findings: List[Finding],
    parse_result: "ParseResult",
) -> Path:
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in sorted_findings:
        if f.severity in counts:
            counts[f.severity] += 1

    artifacts_by_name: dict = {}
    for f in sorted_findings:
        artifacts_by_name.setdefault(f.artifact, []).append(f)

    # Build evidence tables HTML — recursive (many agents put CSVs in subdirs).
    # In automation-only mode (no LLM) findings can be empty but parsed CSVs are
    # still the analyst's output: render the top 20 CSVs as searchable tables.
    parsed_dir = ctx.agent_parsed_dir(agent.name)
    csv_files = sorted(parsed_dir.rglob("*.csv"))
    # Skip empty CSVs and prioritise the largest tables first
    csv_files = [p for p in csv_files if p.stat().st_size > 200]
    csv_files.sort(key=lambda p: -p.stat().st_size)
    csv_files = csv_files[:20]

    from .evidence_tables import csv_to_html_table
    evidence_html = ""
    for csv_path in csv_files:
        try:
            rel = csv_path.relative_to(parsed_dir)
        except ValueError:
            rel = csv_path.name
        title = f"{csv_path.stem} — {rel}"
        evidence_html += '<div class="evidence-block">'
        evidence_html += csv_to_html_table(csv_path, max_rows=50, title=title)
        evidence_html += "</div>"

    # Also include any JSONL files (registry full-hive dumps etc.) as plain previews
    for jsonl in sorted(parsed_dir.rglob("*.jsonl"))[:5]:
        if jsonl.stat().st_size < 200:
            continue
        try:
            rel = jsonl.relative_to(parsed_dir)
        except ValueError:
            rel = jsonl.name
        try:
            with open(jsonl, encoding="utf-8", errors="replace") as f:
                head = []
                for i, line in enumerate(f):
                    if i >= 25:
                        break
                    head.append(line.rstrip("\n"))
            preview = html.escape("\n".join(head))
            evidence_html += (
                f'<div class="evidence-block">'
                f'<h3 style="color:#58a6ff">{html.escape(jsonl.stem)} — '
                f'<small style="color:#8b949e">{html.escape(str(rel))}</small></h3>'
                f'<pre style="background:#0d1117;color:#c9d1d9;padding:12px;'
                f'border:1px solid #30363d;border-radius:4px;overflow-x:auto;'
                f'font-size:11px;max-height:300px">{preview}</pre>'
                f'<p style="color:#8b949e;font-size:11px;font-style:italic">'
                f'Showing first 25 lines. Full file: '
                f'<code>{html.escape(str(jsonl))}</code></p></div>'
            )
        except Exception:
            continue

    env = _jinja_env()
    tpl = env.get_template("agent_report.html.j2")
    rendered = tpl.render(
        agent_name=agent.name,
        display_name=agent.display_name,
        description=agent.description,
        customer_name=ctx.customer_name,
        case_reference=ctx.case_reference,
        investigation_date=ctx.investigation_date.isoformat(),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        counts=counts,
        sorted_findings=sorted_findings,
        artifacts_by_name=artifacts_by_name,
        evidence_html=evidence_html,
        parse_metadata=parse_result.metadata,
        parse_success=parse_result.success,
        total_findings=len(findings),
    )

    out_path = ctx.reports_dir / f"{agent.name}_report.html"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    return out_path
