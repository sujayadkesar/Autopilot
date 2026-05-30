"""
final_report.py — Combined forensic report builder.

Produces a single self-contained HTML file with:
  cover page, TOC, executive summary, risk dashboard,
  unified timeline, IOC roll-up, per-agent sections, appendix.
"""

from __future__ import annotations

import html as html_mod
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

from ..case_context import CaseContext
from ..finding import Finding, SEVERITY_ORDER
from ..manifest import GlobalManifest
from ..text.mojibake import fix_mojibake
from .evidence_tables import csv_to_html_table

_TEMPLATES_DIR = Path(__file__).parent / "templates"

SEV_COLOR = {
    "CRITICAL": "#ff4444", "HIGH": "#ff8800",
    "MEDIUM": "#ffcc00", "LOW": "#33cc66", "INFO": "#4488ff",
}


def _jinja_env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
    env.filters["sev_color"] = lambda s: SEV_COLOR.get(s.upper(), "#888")
    return env


def build_final_report(
    ctx: CaseContext,
    all_findings: List[Finding],
    per_agent_reports: Dict[str, Path],
    exec_summary: str,
    evidence_refs: list,
    manifest: Optional[GlobalManifest] = None,
    system_info: Optional[dict] = None,
    report_suffix: str = "",
) -> Path:
    sorted_findings = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in sorted_findings:
        if f.severity in counts:
            counts[f.severity] += 1

    # IOC dedup
    ioc_map: Dict[str, List[str]] = {}
    for f in all_findings:
        if f.ioc:
            ioc_map.setdefault(f.ioc, [])
            ref = f"{f.agent}:{f.artifact}"
            if ref not in ioc_map[f.ioc]:
                ioc_map[f.ioc].append(ref)

    # Timeline (findings with timestamps)
    timeline = sorted(
        [f for f in all_findings if f.timestamp],
        key=lambda f: f.timestamp,
    )

    # Per-agent risk scores
    agent_risk: Dict[str, int] = {}
    agent_counts: Dict[str, Dict[str, int]] = {}
    for f in all_findings:
        if f.agent not in agent_risk:
            agent_risk[f.agent] = 0
            agent_counts[f.agent] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        if f.risk_score > agent_risk[f.agent]:
            agent_risk[f.agent] = f.risk_score
        if f.severity in agent_counts[f.agent]:
            agent_counts[f.agent][f.severity] += 1

    # Build evidence table HTML for each ref
    evidence_blocks = []
    for ref in evidence_refs:
        block_html = csv_to_html_table(
            ref.csv_path,
            max_rows=30,
            highlight_columns=ref.highlight_columns,
            title=f"Evidence: {ref.finding_title}",
        )
        evidence_blocks.append({"title": ref.finding_title, "html": block_html})

    # Per-agent report sections (read the HTML bodies)
    agent_sections = {}
    for agent_name, report_path in per_agent_reports.items():
        try:
            content = report_path.read_text(encoding="utf-8")
            # Try <main>, then <body>, then strip to avoid CSS bleed
            import re as _re
            m = _re.search(r'<main[^>]*>(.*?)</main>', content, _re.DOTALL)
            if m:
                body = m.group(1)
            else:
                bm = _re.search(r'<body[^>]*>(.*?)</body>', content, _re.DOTALL)
                body = bm.group(1) if bm else content
            # Strip embedded <style> and <script> blocks to prevent theme conflicts
            body = _re.sub(r'<style[^>]*>.*?</style>', '', body, flags=_re.DOTALL)
            body = _re.sub(r'<script[^>]*>.*?</script>', '', body, flags=_re.DOTALL)
            # Strip top-level nav/header/footer elements
            body = _re.sub(r'<(header|nav|footer)[^>]*>.*?</\1>', '', body, flags=_re.DOTALL)
            # Strip the registry agent's left-sidebar emoji navigation (mojibake source)
            body = _re.sub(r'<aside[^>]*>.*?</aside>', '', body, flags=_re.DOTALL)
            body = _re.sub(r'<div[^>]*class="[^"]*sidebar[^"]*"[^>]*>.*?</div>',
                           '', body, flags=_re.DOTALL)
            # Repair any cp1252-mojibake'd emoji that survived the strip
            body = fix_mojibake(body)
            agent_sections[agent_name] = body.strip()
        except Exception:
            agent_sections[agent_name] = "<p>Report unavailable.</p>"

    # Manifest appendix
    manifest_entries = []
    if manifest:
        manifest_data_path = ctx.output_dir / "manifest.json"
        if manifest_data_path.exists():
            try:
                with open(manifest_data_path) as f:
                    manifest_data = json.load(f)
                manifest_entries = manifest_data.get("artifacts", [])
            except Exception:
                pass

    env = _jinja_env()
    tpl = env.get_template("final_report.html.j2")
    rendered = tpl.render(
        customer_name=ctx.customer_name,
        case_reference=ctx.case_reference,
        investigation_date=ctx.investigation_date.isoformat(),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        agents_run=list(per_agent_reports.keys()),
        exec_summary=exec_summary,
        counts=counts,
        sorted_findings=sorted_findings,
        ioc_map=ioc_map,
        timeline=timeline,
        agent_risk=agent_risk,
        agent_counts=agent_counts,
        agent_sections=agent_sections,
        evidence_blocks=evidence_blocks,
        manifest_entries=manifest_entries,
        system_info=system_info or {},
        llm_model=ctx.llm_model,
        SEV_COLOR=SEV_COLOR,
    )

    name = f"raw_evidence_report.html" if report_suffix == "quick" else "final_forensic_report.html"
    out_path = ctx.reports_dir / name
    # Final mojibake sweep over the entire rendered document
    rendered = fix_mojibake(rendered)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    return out_path


def build_investigation_report(
    ctx: CaseContext,
    all_findings: List[Finding],
    exec_summary: str,
    recommendations: Optional[List[str]] = None,
    conclusion: Optional[str] = None,
    manifest: Optional[GlobalManifest] = None,
    system_info: Optional[dict] = None,
) -> Path:
    """Prompt-focused investigation report for investigators / legal teams."""
    sorted_findings = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in sorted_findings:
        if f.severity in counts:
            counts[f.severity] += 1

    ioc_map: Dict[str, List[str]] = {}
    for f in all_findings:
        if f.ioc and len(f.ioc) > 2:
            ioc_map.setdefault(f.ioc, [])
            ref = f"{f.agent}:{f.artifact}"
            if ref not in ioc_map[f.ioc]:
                ioc_map[f.ioc].append(ref)

    # Derive report title from investigation prompt or use default
    inv_prompt = ctx.investigation_prompt or ""
    if inv_prompt:
        first_line = inv_prompt.strip().split("\n")[0][:80]
        report_title = first_line if len(first_line) > 10 else "Forensic Investigation Report"
    else:
        report_title = "Forensic Investigation Report"

    env = _jinja_env()
    tpl = env.get_template("investigation_report.html.j2")
    rendered = tpl.render(
        customer_name=ctx.customer_name,
        case_reference=ctx.case_reference,
        investigation_date=ctx.investigation_date.isoformat(),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        investigation_prompt=ctx.investigation_prompt,
        report_title=report_title,
        agents_run=list({f.agent for f in all_findings}) or [],
        exec_summary=exec_summary,
        counts=counts,
        sorted_findings=sorted_findings,
        ioc_map=ioc_map,
        system_info=system_info or {},
        llm_model=ctx.llm_model,
        recommendations=recommendations or [],
        conclusion=conclusion or "",
    )

    out_path = ctx.reports_dir / "investigation_report.html"
    rendered = fix_mojibake(rendered)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    return out_path


def _tooling_manifest(ctx: CaseContext) -> list:
    """List the external tools relevant to this run and whether they're installed."""
    roles = [
        ("EvtxECmd.exe", "Event-log parsing"),
        ("MFTECmd.exe", "$MFT / USN journal parsing"),
        ("AmcacheParser.exe", "Amcache execution + hash extraction"),
        ("PECmd.exe", "Prefetch parsing"),
        ("SrumECmd.exe", "SRUM network/resource usage"),
        ("RECmd.exe", "Registry artifact extraction"),
        ("LECmd.exe", "LNK / shortcut parsing"),
        ("SBECmd.exe", "Shellbags parsing"),
        ("WxTCmd.exe", "Windows Timeline (ActivitiesCache)"),
        ("hayabusa.exe", "Sigma-rule event-log hunting"),
        ("capa.exe", "Malware capability + ATT&CK extraction"),
        ("hindsight.exe", "Browser history aggregation"),
    ]
    out = []
    for exe, role in roles:
        out.append({"name": exe, "role": role,
                    "present": (ctx.tools_dir / exe).is_file()})
    return out


def build_formal_investigation_report(
    ctx: CaseContext,
    findings_engine,  # InvestigationEngine instance
    investigation_findings: List,  # List[InvestigationFinding]
    system_info: Optional[dict] = None,
    conclusion: str = "",
    renderer=None,  # core.render.ReportRenderer (optional) — enables exhibit PNGs + PDF
) -> Path:
    """
    Pure-automation forensic report. NO LLM. Reproducible. Evidence-cited.
    Each finding is rendered as a numbered block with exhibit cards (highlighted CSV rows).

    If `renderer` is supplied and available, each evidence snippet is rasterized to a
    highlighted "exhibit screenshot" PNG (embedded as <img>), and — when "pdf" is in
    ctx.report_formats — a print-grade PDF is produced alongside the HTML.
    """
    # Rasterize evidence exhibits to PNG (no-op if renderer unavailable)
    if renderer is not None:
        try:
            from ..render.exhibits import render_finding_exhibits
            render_finding_exhibits(investigation_findings,
                                    ctx.reports_dir / "exhibits", renderer)
        except Exception as e:
            import logging
            logging.getLogger("dfir.report").warning("Exhibit rendering failed: %s", e)
    from ..investigation.indicators import (
        KNOWN_CLOUD_DOMAINS, KNOWN_FILESHARING_DOMAINS,
        KNOWN_PERSONAL_EMAIL, KNOWN_PRIVACY_TOOLS, KNOWN_HACKTOOLS,
    )

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in investigation_findings:
        if f.severity in counts:
            counts[f.severity] += 1

    # Title from prompt
    inv_prompt = ctx.investigation_prompt or ""
    if inv_prompt:
        first_line = inv_prompt.strip().split("\n")[0][:80]
        report_title = first_line if len(first_line) > 10 else "Forensic Investigation Report"
    else:
        report_title = "Baseline Forensic Investigation Report"

    focus_descriptions = {
        "usb_exfil":         "USB-mediated data exfiltration (registry USBSTOR, LNK files on removable drives)",
        "cloud_upload":      "Cloud-storage uploads (Drive, Dropbox, OneDrive, iCloud, Mega, Box, …)",
        "fileshare_upload":  "Anonymous file-sharing services (WeTransfer, AnonFiles, Pastebin, Transfer.sh, …)",
        "personal_email":    "Personal webmail access (Gmail, Outlook, Yahoo, ProtonMail, …)",
        "credential_theft":  "Credential-dumping tools and LSASS access indicators",
        "lateral_movement":  "Remote-execution and lateral-movement tooling (PsExec, wmiexec, atexec, …)",
        "persistence":       "Non-standard autorun, service, and scheduled-task entries",
        "log_tampering":     "Audit-log clear events (1102/104) and gaps in the security log",
        "anti_forensic":     "Privacy / Tor / VPN / file-shredding tools",
        "tor_anonymizer":    "Anonymity-network indicators (Tor, VPN domains, …)",
        "hacktools":         "Generic catalogue of known offensive-security tools",
        "ransomware":        "Ransomware indicators (encryption tools, ransom notes, locked extensions)",
        "data_destruction":  "Wiping / shredding / log-clearing tools",
        "phishing":          "Email-borne attack artifacts (macro documents, lure attachments)",
    }

    stats = {
        "cloud_domains":     len(KNOWN_CLOUD_DOMAINS),
        "fileshare_domains": len(KNOWN_FILESHARING_DOMAINS),
        "email_domains":     len(KNOWN_PERSONAL_EMAIL),
        "privacy_domains":   len(KNOWN_PRIVACY_TOOLS),
        "hacktools":         len(KNOWN_HACKTOOLS),
    }

    # Severity order for display
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(investigation_findings, key=lambda f: sev_rank.get(f.severity, 99))

    # ATT&CK Navigator layer + consolidated IOC roll-up (written to disk + report)
    attack_techniques: list = []
    ioc_rollup: dict = {}
    try:
        from .attack_navigator import build_navigator_layer, build_ioc_rollup, collect_techniques
        build_navigator_layer(investigation_findings, ctx.case_reference,
                              ctx.reports_dir / "attack_navigator.json")
        attack_techniques = sorted(collect_techniques(investigation_findings).items(),
                                   key=lambda kv: (-kv[1], kv[0]))
        ioc_rollup = build_ioc_rollup(investigation_findings,
                                      ctx.reports_dir / "ioc_rollup.json")
    except Exception as e:
        import logging
        logging.getLogger("dfir.report").warning("ATT&CK/IOC roll-up failed: %s", e)

    # Compute a small fingerprint (so the report is provably from this run)
    import hashlib
    fp_data = "|".join(f"{f.category}:{f.title}:{f.severity}" for f in sorted_findings)
    report_fp = hashlib.sha256(fp_data.encode("utf-8")).hexdigest()[:16]

    env = _jinja_env()
    tpl = env.get_template("formal_investigation_report.html.j2")
    rendered = tpl.render(
        customer_name=ctx.customer_name,
        case_reference=ctx.case_reference,
        investigation_date=ctx.investigation_date.isoformat(),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        investigation_prompt=ctx.investigation_prompt,
        report_title=report_title,
        findings=sorted_findings,
        counts=counts,
        focus_areas=sorted(findings_engine.focus) if findings_engine else [],
        focus_descriptions=focus_descriptions,
        stats=stats,
        system_info=system_info or {},
        conclusion=conclusion,
        report_fingerprint=report_fp,
        tools_used=_tooling_manifest(ctx),
        evidence_source=str(ctx.mount_point),
        attack_techniques=attack_techniques,
        ioc_rollup=ioc_rollup,
    )
    rendered = fix_mojibake(rendered)
    out_path = ctx.reports_dir / "formal_investigation_report.html"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)

    # Optional print-grade PDF
    if renderer is not None and "pdf" in (ctx.report_formats or []):
        try:
            if getattr(renderer, "available", False):
                pdf_path = ctx.reports_dir / "formal_investigation_report.pdf"
                renderer.html_to_pdf(out_path, pdf_path, title=report_title)
        except Exception as e:
            import logging
            logging.getLogger("dfir.report").warning("Formal PDF export failed: %s", e)

    return out_path
