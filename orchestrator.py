"""
orchestrator.py — Pipeline core.

Used by both GUI (via OrchestratorWorker QThread) and CLI.
Stages: extract → parse → analyze → report (parallel across agents)
       → final unified report
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from core.agent_registry import load_enabled
from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.finding import Finding
from core.llm_client import LLMClient
from core.manifest import GlobalManifest
from core.progress_bus import ProgressBus
from core.fsutil import check_mount_health, MountUnavailableError
from core.investigation import InvestigationEngine
from core.report.comprehensive_report import build_comprehensive_report
from core.report.final_report import (
    build_final_report,
    build_formal_investigation_report,
    build_investigation_report,
)
from core.render import ReportRenderer

log = logging.getLogger("dfir.orchestrator")


class OllamaUnavailable(RuntimeError):
    pass


class PipelineResult:
    """Return value of run_pipeline — wraps report paths + post-run context.
    WindowsPath objects don't support arbitrary attributes, so we wrap here.
    """
    def __init__(self, report_path: Path, refinement_ctx=None,
                 quick_report_path: Optional[Path] = None,
                 formal_report_path: Optional[Path] = None,
                 comprehensive_report_path: Optional[Path] = None):
        self.report_path = report_path
        self._refinement_ctx = refinement_ctx
        self.quick_report_path = quick_report_path
        self.formal_report_path = formal_report_path
        self.comprehensive_report_path = comprehensive_report_path

    def __str__(self):
        return str(self.report_path)

    def __fspath__(self):
        import os
        return os.fspath(self.report_path)

    def exists(self):
        return self.report_path.exists()


class RefinementContext:
    """Carries everything needed for post-run report refinement."""
    def __init__(self, ctx: CaseContext, llm: LLMClient, all_findings: List[Finding],
                 system_info: dict, final_report: Path, investigation_report: Optional[Path]):
        self.ctx = ctx
        self.llm = llm
        self.all_findings = all_findings
        self.system_info = system_info
        self.final_report = final_report
        self.investigation_report = investigation_report

    def refine(self, user_request: str, progress: ProgressBus) -> str:
        """Re-analyze artifacts based on user request and return updated narrative text."""
        if not user_request.strip():
            return ""
        # Build context: top findings + relevant artifacts
        findings_summary = "\n".join(
            f"- [{f.severity}] {f.title}: {f.detail[:150]}" for f in self.all_findings[:20]
        )
        parsed_csvs = list(self.ctx.parsed_dir.rglob("*.csv"))
        artifacts_json_path = self.ctx.parsed_dir / "registry" / "artifacts.json"
        extra_context = ""
        if artifacts_json_path.exists():
            import json as _json
            try:
                with open(artifacts_json_path, encoding="utf-8") as f:
                    artifacts = _json.load(f).get("artifacts", {})
                # Pick categories mentioned in the request
                request_lower = user_request.lower()
                relevant = {}
                for key, data in artifacts.items():
                    if any(kw in request_lower for kw in [key, key.replace("_", " ")]):
                        relevant[key] = data
                if not relevant and artifacts:
                    # Fall back to sending top categories
                    for key in list(artifacts.keys())[:4]:
                        relevant[key] = artifacts[key]
                if relevant:
                    import json as _json2
                    extra_context = _json2.dumps(relevant, indent=2, default=str)[:3000]
            except Exception:
                pass

        system = (
            "You are a senior DFIR analyst. You have been given a completed forensic investigation "
            "and the analyst is asking you to refine or re-examine a specific aspect of the report. "
            "Respond with clear, professional, evidence-based analysis. Plain text only — no JSON, no markdown headers."
        )
        if self.ctx.investigation_prompt:
            system += f"\n\nOriginal investigation brief:\n{self.ctx.investigation_prompt}"
        user = (
            f"Computer: {self.system_info.get('ComputerName','Unknown')}\n"
            f"Customer: {self.ctx.customer_name}\n\n"
            f"Existing findings summary:\n{findings_summary}\n\n"
        )
        if extra_context:
            user += f"Relevant artifact data:\n{extra_context}\n\n"
        user += f"Analyst refinement request: {user_request}\n\nProvide a focused, evidence-based response:"

        progress.log("INFO", "refinement", f"Refining: {user_request[:80]}...")
        response = self.llm._backend.ask(system, user, max_tokens=900)
        return response or "Unable to generate refinement (LLM timeout or unavailable)."


def run_pipeline(
    ctx: CaseContext,
    progress: ProgressBus,
    skip_llm: bool = False,
) -> Path:
    """
    Run the full DFIR pipeline.

    Returns the path to the final HTML report.
    Raises OllamaUnavailable if Ollama is unreachable and skip_llm=False.
    """
    progress.global_start()
    ctx.ensure_dirs()

    # ── PRE-FLIGHT: verify the forensic-image mount is alive ───────────────
    # If the mount is dead (WinError 1117 etc.), fail fast with a clear,
    # actionable message rather than letting every agent crash deep in
    # extract() with cryptic OSErrors.
    try:
        check_mount_health(ctx.mount_point)
        progress.log("INFO", "orchestrator", f"Mount verified readable: {ctx.mount_point}")
    except MountUnavailableError as e:
        progress.log("ERROR", "orchestrator", f"Mount pre-flight check FAILED:\n{e}")
        raise

    # Set up pipeline.log file handler so ALL log records are captured
    _log_path = ctx.output_dir / "pipeline.log"
    _fh = logging.FileHandler(str(_log_path), encoding="utf-8")
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
    logging.getLogger().addHandler(_fh)

    def _log_and_emit(level: str, agent: str, msg: str):
        """Log to Python logging + emit to ProgressBus so GUI/CLI see it."""
        getattr(log, level.lower(), log.info)(msg)
        progress.log(level, agent, msg)

    manifest = GlobalManifest()

    # Shared headless-Chromium renderer for PDF + evidence-exhibit PNGs.
    # Degrades gracefully (renderer.available == False) if Playwright/Chromium absent.
    want_pdf = "pdf" in (ctx.report_formats or [])
    renderer = ReportRenderer(case_reference=ctx.case_reference) if want_pdf else None
    if want_pdf and renderer is not None and not renderer.available:
        progress.log("WARNING", "orchestrator",
                     "PDF requested but Playwright/Chromium unavailable — producing HTML only. "
                     "Install with: pip install playwright && playwright install chromium")

    # ── LLM is OPTIONAL ──────────────────────────────────────────────────
    # If skip_llm is set OR no model was provided, run automation-only.
    # The deterministic investigation engine produces evidence-cited findings
    # without ever calling the LLM, so the pipeline still produces all
    # forensic value even with no AI.
    llm = None
    if not skip_llm and ctx.llm_model and ctx.llm_model.strip():
        try:
            llm = LLMClient(ctx.llm_model, ctx)
            ok, model_err = llm.health_check()
            if not ok:
                # Fall back to automation-only rather than fail the whole run
                progress.log("WARNING", "orchestrator",
                             f"LLM unavailable — continuing automation-only: {model_err.splitlines()[0]}")
                llm = None
                skip_llm = True
        except Exception as e:
            progress.log("WARNING", "orchestrator",
                         f"LLM init failed — continuing automation-only: {e}")
            llm = None
            skip_llm = True
    else:
        skip_llm = True
        progress.log("INFO", "orchestrator",
                     "Running in automation-only mode (no AI). Deterministic engine will produce findings.")

    agents: List[BaseAgent] = load_enabled(ctx.enabled_agents)
    if not agents:
        raise ValueError(f"No agents loaded. Enabled: {ctx.enabled_agents}")

    progress.log("INFO", "orchestrator", f"Running {len(agents)} agent(s): {[a.name for a in agents]}")

    all_findings: List[Finding] = []
    per_agent_reports: Dict[str, Path] = {}
    system_info: dict = {}

    with ThreadPoolExecutor(max_workers=ctx.workers, thread_name_prefix="dfir") as pool:

        # ── STAGE 1: Extract (parallel) ─────────────────────────────────
        progress.log("INFO", "orchestrator", "Stage 1: Extraction")
        extract_futures: Dict[str, Future[ExtractResult]] = {
            a.name: pool.submit(_safe_extract, a, ctx, progress) for a in agents
        }
        extract_results: Dict[str, ExtractResult] = {}
        for name, fut in extract_futures.items():
            try:
                result = fut.result()
            except Exception as e:
                import traceback
                err_msg = f"Extract FAILED for {name}: {e}\n{traceback.format_exc()}"
                _log_and_emit("ERROR", name, err_msg)
                progress.stage_error(name, "extract", str(e))
                extract_results[name] = ExtractResult(agent=name, success=False, error=str(e))
                continue

            # Store result before any manifest work — prevents overwrite on manifest exception
            extract_results[name] = result
            manifest.record_timing(name, "extract", result.elapsed)

            # Register artifacts in global manifest (best-effort — don't let hash errors block pipeline)
            for art in result.artifacts:
                try:
                    if art.is_file():
                        from core.manifest import ManifestEntry
                        entry = ManifestEntry(name, art.name, art)
                        manifest.add_artifact(entry)
                except Exception as e:
                    log.warning("Manifest entry failed for %s/%s: %s", name, art, e)

        # ── STAGE 2: Parse (parallel) ───────────────────────────────────
        progress.log("INFO", "orchestrator", "Stage 2: Parsing")
        parse_futures: Dict[str, Future[ParseResult]] = {
            a.name: pool.submit(_safe_parse, a, ctx, extract_results[a.name], progress)
            for a in agents
            if extract_results.get(a.name, ExtractResult(a.name, False)).success
        }
        parse_results: Dict[str, ParseResult] = {}
        for name, fut in parse_futures.items():
            try:
                result = fut.result()
            except Exception as e:
                import traceback
                err_msg = f"Parse FAILED for {name}: {e}\n{traceback.format_exc()}"
                _log_and_emit("ERROR", name, err_msg)
                progress.stage_error(name, "parse", str(e))
                parse_results[name] = ParseResult(agent=name, success=False, error=str(e))
                continue

            parse_results[name] = result
            manifest.record_timing(name, "parse", result.elapsed)
            if result.error:
                _log_and_emit("WARNING", name, f"Parse completed with errors: {result.error}")
            # Capture system info from registry agent
            if name == "registry" and result.system_info:
                system_info = result.system_info

        # ── QUICK REPORT — raw evidence, no LLM (available immediately after parse) ──
        progress.log("INFO", "orchestrator", "Generating quick evidence report (no AI)…")
        try:
            quick_report = build_final_report(
                ctx, [], parse_results and {} or {},
                "Raw evidence collected — AI analysis in progress.",
                [],
                manifest=manifest,
                system_info=system_info,
                report_suffix="quick",
            )
            progress.log("INFO", "orchestrator", f"Quick report ready: {quick_report}")
        except Exception as e:
            quick_report = None
            log.warning("Quick report build failed: %s", e)

        # ── COMPREHENSIVE EVIDENCE REPORT — every parsed artefact, searchable ─
        progress.log("INFO", "orchestrator",
                     "Building comprehensive evidence report (every parsed artefact)…")
        comprehensive_report = None
        try:
            comprehensive_report = build_comprehensive_report(ctx)
            progress.log("INFO", "orchestrator",
                         f"Comprehensive report ready: {comprehensive_report}")
        except Exception as e:
            log.warning("Comprehensive report build failed: %s", e)

        # ── DETERMINISTIC INVESTIGATION (no LLM) ────────────────────────────
        # Runs the curated indicator-list engine against parsed artifacts.
        # Always reproducible. Always cites concrete evidence.
        progress.log("INFO", "orchestrator",
                     f"Running deterministic forensic investigation engine "
                     f"(profile={ctx.case_profile}, "
                     f"keywords={sum(1 for v in ctx.profile_keywords.values() if v)} field(s))")
        formal_report = None
        investigation_findings: list = []
        investigator = None
        try:
            investigator = InvestigationEngine(
                ctx,
                profile_key=ctx.case_profile,
                user_keywords=ctx.profile_keywords,
            )
            investigation_findings = investigator.analyse()
            progress.log("INFO", "orchestrator",
                         f"Deterministic engine produced {len(investigation_findings)} finding(s)")
            formal_report = build_formal_investigation_report(
                ctx, investigator, investigation_findings,
                system_info=system_info,
                renderer=renderer,
            )
            progress.log("INFO", "orchestrator", f"Formal report ready: {formal_report}")
        except Exception as e:
            import traceback
            log.error("Investigation engine failed: %s\n%s", e, traceback.format_exc())

        # ── STAGE 3: Analyze (parallel, LLM-bound) ─────────────────────
        progress.log("INFO", "orchestrator", "Stage 3: AI Analysis")
        if not skip_llm:
            analyze_futures: Dict[str, Future[List[Finding]]] = {
                a.name: pool.submit(_safe_analyze, a, ctx, parse_results.get(a.name, ParseResult(a.name, False)), llm, progress)
                for a in agents
                if parse_results.get(a.name, ParseResult(a.name, False)).success
            }
            for name, fut in analyze_futures.items():
                try:
                    findings = fut.result()
                    all_findings.extend(findings)
                    manifest.record_timing(name, "analyze", 0.0)
                    _log_and_emit("INFO", name, f"Analysis complete: {len(findings)} findings")
                except Exception as e:
                    import traceback
                    _log_and_emit("ERROR", name, f"Analysis FAILED: {e}\n{traceback.format_exc()}")
                    progress.stage_error(name, "analyze", str(e))

        # ── STAGE 4: Per-agent reports (parallel) ───────────────────────
        progress.log("INFO", "orchestrator", "Stage 4: Per-agent reports")
        report_futures: Dict[str, Future[Path]] = {
            a.name: pool.submit(
                _safe_report, a, ctx,
                [f for f in all_findings if f.agent == a.name],
                parse_results.get(a.name, ParseResult(a.name, False)),
                progress,
            )
            for a in agents
        }
        for name, fut in report_futures.items():
            try:
                report_path = fut.result()
                per_agent_reports[name] = report_path
                manifest.record_timing(name, "report", 0.0)
            except Exception as e:
                log.error("Report failed for %s: %s", name, e)

    # ── STAGE 5: Final unified report ───────────────────────────────────
    progress.log("INFO", "orchestrator", "Stage 5: Final forensic report")

    # Build a deterministic exec summary as the always-available baseline.
    # If AI is enabled and works, we replace it with an AI-generated narrative.
    det_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in (investigation_findings or []):
        if f.severity in det_counts:
            det_counts[f.severity] += 1
    computer = system_info.get("ComputerName", "the host") if system_info else "the host"
    if investigation_findings:
        det_summary = (
            f"Deterministic forensic analysis of {computer} produced "
            f"{len(investigation_findings)} evidence-cited finding(s) "
            f"({det_counts['CRITICAL']} CRITICAL, {det_counts['HIGH']} HIGH, "
            f"{det_counts['MEDIUM']} MEDIUM). "
            f"Each finding includes the specific artifact rows from which it was derived; "
            f"see the Formal Investigation Report for the full evidence package."
        )
    else:
        det_summary = (
            f"Automation pass complete for {computer}. The deterministic engine did not "
            f"surface high-confidence indicators within the configured focus areas. "
            f"This does not by itself prove the negative — review the per-agent reports "
            f"for additional context."
        )
    exec_summary = det_summary

    if not skip_llm and all_findings and llm is not None:
        try:
            ai_summary = llm.executive_summary(
                all_findings,
                system_info=system_info,
                agents_run=[a.name for a in agents],
            )
            if ai_summary and ai_summary.strip():
                exec_summary = ai_summary
        except Exception as e:
            log.warning("Executive summary failed: %s", e)

    evidence_refs = []
    if not skip_llm and all_findings and llm is not None:
        try:
            parsed_csvs = list(ctx.parsed_dir.rglob("*.csv"))
            evidence_refs = llm.select_evidence(all_findings, parsed_csvs)
        except Exception as e:
            log.warning("Evidence selection failed: %s", e)

    # Save findings JSONL
    findings_path = ctx.output_dir / "findings.jsonl"
    with open(findings_path, "w", encoding="utf-8") as f:
        for finding in all_findings:
            f.write(finding.to_json_line() + "\n")

    # Save global manifest
    manifest.save(ctx.output_dir, ctx.to_dict())

    # Build final technical report
    try:
        final_report = build_final_report(
            ctx,
            all_findings,
            per_agent_reports,
            exec_summary,
            evidence_refs,
            manifest=manifest,
            system_info=system_info,
        )
    except Exception as e:
        log.error("Final report build failed: %s", e)
        final_report = ctx.reports_dir / "final_forensic_report.html"
        final_report.write_text(
            f"<h1>DFIR Report</h1><p>Report build failed: {e}</p>"
            f"<p>Findings: {len(all_findings)} total</p>",
            encoding="utf-8",
        )

    # Build investigation-focused report (prompt-specific) — only when AI ran
    investigation_report: Optional[Path] = None
    if not skip_llm and all_findings:
        try:
            investigation_report = build_investigation_report(
                ctx,
                all_findings,
                exec_summary,
                system_info=system_info,
            )
            log.info("Investigation report: %s", investigation_report)
        except Exception as e:
            log.warning("Investigation report build failed: %s", e)

    # Optional: PDF the AI-augmented final report too
    if renderer is not None and getattr(renderer, "available", False) and final_report and Path(final_report).exists():
        try:
            renderer.html_to_pdf(Path(final_report),
                                 ctx.reports_dir / "final_forensic_report.pdf",
                                 title="Final Forensic Report")
        except Exception as e:
            log.warning("Final report PDF export failed: %s", e)

    if renderer is not None:
        try:
            renderer.close()
        except Exception:
            pass

    log.info("=== Pipeline complete at %s ===", time.strftime('%Y-%m-%dT%H:%M:%S'))
    log.info("Agents: %s", [a.name for a in agents])
    log.info("Total findings: %d", len(all_findings))
    log.info("Final report: %s", final_report)

    logging.getLogger().removeHandler(_fh)
    _fh.close()

    refinement_ctx = None
    if llm is not None:
        refinement_ctx = RefinementContext(ctx, llm, all_findings, system_info,
                                           final_report, investigation_report)
    # If we ran automation-only, the formal report IS the primary report
    primary_report = formal_report if (skip_llm and formal_report is not None) else final_report

    progress.global_done(str(primary_report))
    return PipelineResult(
        report_path=primary_report,
        refinement_ctx=refinement_ctx,
        quick_report_path=quick_report,
        formal_report_path=formal_report,
        comprehensive_report_path=comprehensive_report,
    )


# ── safe wrappers (catch + rethrow with agent context) ─────────────────────

def _safe_extract(agent: BaseAgent, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
    try:
        return agent.extract(ctx, progress)
    except Exception as e:
        progress.stage_error(agent.name, "extract", str(e))
        raise


def _safe_parse(agent: BaseAgent, ctx: CaseContext, extract: ExtractResult, progress: ProgressBus) -> ParseResult:
    try:
        return agent.parse(ctx, extract, progress)
    except Exception as e:
        progress.stage_error(agent.name, "parse", str(e))
        raise


def _safe_analyze(agent: BaseAgent, ctx: CaseContext, parse: ParseResult, llm: LLMClient, progress: ProgressBus) -> List[Finding]:
    try:
        return agent.analyze(ctx, parse, llm, progress)
    except Exception as e:
        progress.stage_error(agent.name, "analyze", str(e))
        raise


def _safe_report(agent: BaseAgent, ctx: CaseContext, findings: List[Finding], parse: ParseResult, progress: ProgressBus) -> Path:
    progress.stage_started(agent.name, "report")
    try:
        path = agent.report(ctx, findings, parse)
        progress.stage_done(agent.name, "report")
        return path
    except Exception as e:
        progress.stage_error(agent.name, "report", str(e))
        raise
