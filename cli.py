"""
cli.py — Click-based CLI.

Usage:
  python main.py cli --help
  python main.py cli --drive E:\\ --output D:\\Cases\\Case001 --model ollama:phi3:mini \\
      --customer "Acme Corp" --prompt "Suspected USB exfil…"
  python main.py doctor
  python main.py list-agents
"""

from __future__ import annotations

import logging
import sys
import webbrowser
from datetime import date
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

console = Console()
log = logging.getLogger("dfir")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, markup=True)],
    )
    # File sink
    fh = logging.FileHandler("dfir_cli.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
    logging.getLogger().addHandler(fh)


def _make_rich_progress_bus():
    """Return a ProgressBus that prints Rich-formatted updates to the console."""
    from core.progress_bus import ProgressBus

    bus = ProgressBus()
    stage_bars: dict = {}

    def on_event(**kwargs):
        event = kwargs.get("event")
        agent = kwargs.get("agent", "")
        stage = kwargs.get("stage", "")
        if event == "log_line":
            level = kwargs.get("level", "INFO")
            msg = kwargs.get("message", "")
            color = {"ERROR": "red", "WARNING": "yellow", "DEBUG": "dim"}.get(level, "white")
            console.print(f"  [{color}]{level:<8}[/{color}] [{agent}] {msg}")
        elif event == "stage_done":
            elapsed = kwargs.get("elapsed", 0)
            console.print(f"  [green]✓[/green] [{agent}] {stage} done in {elapsed:.1f}s")
        elif event == "finding_added":
            count = kwargs.get("count", 0)
            sev = kwargs.get("severity", "")
            sev_colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow"}
            color = sev_colors.get(sev, "white")
            if sev in ("CRITICAL", "HIGH"):
                console.print(f"  [bold {color}]Finding #{count}[/bold {color}] [{sev}] [{agent}]")
        elif event == "global_done":
            path = kwargs.get("report_path", "")
            console.print(f"\n[bold green]✓ Pipeline complete![/bold green]")
            console.print(f"  Final report: [cyan]{path}[/cyan]")

    bus.subscribe(on_event)
    return bus


@click.group()
def cli_group():
    """DFIR Automation Tool — unified forensic pipeline."""


@cli_group.command("cli")
@click.option("--drive", "-d", required=True, help="Mounted drive letter or path (e.g. E:\\ or /mnt/win)")
@click.option("--output", "-o", required=True, help="Output directory for artifacts, parsed, reports")
@click.option("--enable-ai", is_flag=True, default=False, help="Enable AI augmentation (slower, may hallucinate). Default: deterministic only.")
@click.option("--model", default="", help="LLM model (only used with --enable-ai). E.g. ollama:phi3:mini, ollama:llama3:8b")
@click.option("--customer", default="Unknown", show_default=True, help="Customer / organisation name for report cover")
@click.option("--date", "inv_date", default=None, help="Investigation date YYYY-MM-DD (default: today)")
@click.option("--case-ref", default="", help="Case reference (auto-generated if blank)")
@click.option("--prompt", default="", help="Case background and investigation angles (drives focus areas)")
@click.option("--prompt-file", default=None, type=click.Path(exists=True), help="Path to text file containing the investigation prompt")
@click.option("--profile", default="generic", show_default=True,
              type=click.Choice(["generic", "dlp", "malware", "phishing", "ransomware", "lateral"]),
              help="Case profile — determines which detection modules run")
@click.option("--keywords-file", default=None, type=click.Path(exists=True),
              help="Path to a text file with keywords (one per line) for the case-specific search")
@click.option("--agents", default="", help="Comma-separated agents to run (default: all enabled)")
@click.option("--report-format", default="html", show_default=True,
              help="Comma-separated report formats: html,pdf (pdf needs Playwright+Chromium)")
@click.option("--malware-hashes-file", default=None, type=click.Path(exists=True),
              help="File of known-bad MD5/SHA1/SHA256 hashes (one per line) for the malware profile")
@click.option("--yara-rules", multiple=True, type=click.Path(),
              help="Extra YARA rule file/dir (repeatable)")
@click.option("--sample-dir", multiple=True,
              help="Image-relative directory to capa/YARA deep-scan (repeatable)")
@click.option("--run-capa/--no-capa", default=True, help="Run capa on located binaries (malware profile)")
@click.option("--run-yara/--no-yara", default=True, help="Run YARA on located binaries (malware profile)")
@click.option("--skip-llm", is_flag=True, default=False, help="(Deprecated; AI is off by default now. Use --enable-ai to turn on.)")
@click.option("--open-report", is_flag=True, default=False, help="Open final report in browser on completion")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose debug output")
def run_cli(drive, output, enable_ai, model, customer, inv_date, case_ref, prompt, prompt_file,
            profile, keywords_file, agents, report_format, malware_hashes_file, yara_rules,
            sample_dir, run_capa, run_yara, skip_llm, open_report, verbose):
    """Run the DFIR forensic pipeline. Default mode is deterministic (no AI).

    Pass --enable-ai with a model to additionally produce AI-augmented reports.
    The deterministic Formal Investigation Report is always generated.
    """
    # Resolve effective AI mode: --enable-ai turns it on; --skip-llm legacy flag forces off
    if skip_llm:
        enable_ai = False
    skip_llm_flag = not enable_ai
    if enable_ai and not model:
        model = "ollama:phi3:mini"  # sensible default when AI requested without model
    _setup_logging(verbose)

    # Resolve investigation prompt
    if prompt_file:
        prompt = Path(prompt_file).read_text(encoding="utf-8").strip()

    # Parse investigation date
    try:
        parsed_date = date.fromisoformat(inv_date) if inv_date else date.today()
    except ValueError:
        console.print(f"[red]Invalid date format: {inv_date}. Use YYYY-MM-DD.[/red]")
        sys.exit(1)

    # Resolve agents
    from core.agent_registry import list_agents
    all_agent_names = [a["name"] for a in list_agents()]
    if agents:
        enabled_agents = [a.strip() for a in agents.split(",") if a.strip()]
        invalid = [a for a in enabled_agents if a not in all_agent_names]
        if invalid:
            console.print(f"[red]Unknown agents: {invalid}. Available: {all_agent_names}[/red]")
            sys.exit(1)
    else:
        enabled_agents = [a["name"] for a in list_agents() if a.get("enabled_by_default", True)]

    # Optional keywords file → fed to the deterministic engine's keyword search
    profile_keywords = {}
    if keywords_file:
        try:
            kw_text = Path(keywords_file).read_text(encoding="utf-8", errors="replace")
            profile_keywords["search_keywords"] = kw_text
        except Exception as e:
            console.print(f"[yellow]Could not read keywords file: {e}[/yellow]")

    # Malware hashes file → fed to the malware analysis workflow
    if malware_hashes_file:
        try:
            profile_keywords["malicious_hashes"] = Path(malware_hashes_file).read_text(
                encoding="utf-8", errors="replace")
        except Exception as e:
            console.print(f"[yellow]Could not read malware hashes file: {e}[/yellow]")

    # Report formats + malware options
    report_formats = [fmt.strip().lower() for fmt in report_format.split(",") if fmt.strip()]
    if "html" not in report_formats:
        report_formats.insert(0, "html")  # HTML is always produced
    malware_opts = {
        "run_capa": run_capa,
        "run_yara": run_yara,
        "yara_rules": list(yara_rules),
        "sample_dirs": list(sample_dir),
    }

    from core.case_context import CaseContext
    ctx = CaseContext(
        mount_point=Path(drive),
        output_dir=Path(output),
        llm_model=model,
        investigation_prompt=prompt,
        customer_name=customer,
        investigation_date=parsed_date,
        case_reference=case_ref,
        enabled_agents=enabled_agents,
        case_profile=profile,
        profile_keywords=profile_keywords,
        report_formats=report_formats,
        malware_opts=malware_opts,
    )

    # Print banner
    mode_line = (
        f"[bold yellow]Mode:[/bold yellow] AI ENABLED ({model})"
        if enable_ai else
        f"[bold green]Mode:[/bold green] Deterministic only (no AI — fast, reproducible)"
    )
    kw_count = sum(1 for _, v in profile_keywords.items() if v)
    console.print(Panel(
        f"[bold cyan]DFIR Automation Pipeline[/bold cyan]\n"
        f"{mode_line}\n"
        f"Customer: {customer}  |  Drive: {drive}\n"
        f"Profile: [bold]{profile}[/bold]  |  Keywords: {kw_count} field(s)\n"
        f"Agents: {', '.join(enabled_agents)}\n"
        f"Output: {output}",
        title="[bold]DFIR[/bold]",
        border_style="cyan",
    ))

    progress_bus = _make_rich_progress_bus()

    from orchestrator import OllamaUnavailable, run_pipeline
    from core.fsutil import MountUnavailableError
    try:
        result = run_pipeline(ctx, progress_bus, skip_llm=skip_llm_flag)
        inv_report = result._refinement_ctx
        inv_path = inv_report.investigation_report if inv_report else None
        console.print(f"\n[bold green]Done![/bold green]")
        if result.formal_report_path and result.formal_report_path.exists():
            console.print(f"  Formal (no-AI)     : [bold cyan]{result.formal_report_path}[/bold cyan]")
        if result.comprehensive_report_path and result.comprehensive_report_path.exists():
            console.print(f"  Comprehensive      : [cyan]{result.comprehensive_report_path}[/cyan]")
        if result.quick_report_path and result.quick_report_path.exists():
            console.print(f"  Raw evidence       : [cyan]{result.quick_report_path}[/cyan]")
        if not skip_llm_flag:
            console.print(f"  AI technical report: [cyan]{result}[/cyan]")
            if inv_path and inv_path.exists():
                console.print(f"  AI investigation   : [cyan]{inv_path}[/cyan]")
        if open_report and result.exists():
            webbrowser.open(str(result))
        # Interactive refinement REPL
        if not skip_llm_flag and inv_report and inv_report.all_findings:
            _run_refinement_repl(inv_report, progress_bus)
    except MountUnavailableError as e:
        console.print(Panel(
            str(e),
            title="[bold red]Forensic Image Not Accessible[/bold red]",
            border_style="red",
        ))
        sys.exit(2)
    except OllamaUnavailable as e:
        console.print(f"[bold red]Ollama unavailable:[/bold red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Pipeline error:[/bold red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _run_refinement_repl(refinement_ctx, progress_bus):
    """Post-pipeline interactive refinement REPL."""
    from core.report.final_report import build_investigation_report
    console.print(
        "\n[bold cyan]Report Refinement[/bold cyan] — Ask the AI to re-examine any aspect of the investigation."
    )
    console.print("  Type your request and press Enter. Type [dim]exit[/dim] or press Ctrl+C to finish.\n")
    refinement_history = []
    while True:
        try:
            request = console.input("[bold yellow]Refinement>[/bold yellow] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Exiting refinement.[/dim]")
            break
        if not request or request.lower() in ("exit", "quit", "q"):
            break
        try:
            response = refinement_ctx.refine(request, progress_bus)
            console.print(f"\n[bold]Analysis:[/bold]\n{response}\n")
            refinement_history.append({"request": request, "response": response})
            # Rebuild the investigation report with refinement appended as conclusion
            conclusion_parts = [r["response"] for r in refinement_history]
            conclusion = "\n\n".join(
                f"--- Refinement: {h['request']} ---\n{h['response']}"
                for h in refinement_history
            )
            try:
                build_investigation_report(
                    refinement_ctx.ctx,
                    refinement_ctx.all_findings,
                    "",
                    conclusion=conclusion,
                    system_info=refinement_ctx.system_info,
                )
                console.print(f"  [dim]Investigation report updated.[/dim]\n")
            except Exception as e:
                log.warning("Report update failed: %s", e)
        except Exception as e:
            console.print(f"[red]Refinement failed: {e}[/red]")


@cli_group.command("doctor")
@click.option("--model", default="ollama:phi3:mini", help="LLM model to check (optional — AI is not required)")
def doctor(model):
    """Check environment: tools, agents, and (optionally) AI availability.

    AI is OPTIONAL. The pipeline runs in deterministic-only mode by default
    and produces a Formal Investigation Report from curated indicator lists
    and rule-based detections — no AI inference involved. Use --enable-ai
    on the cli command to additionally run LLM analysis.
    """
    _setup_logging(False)
    from core.agent_registry import get_all_manifests
    from core.tool_runner import TOOL_NAMES, ToolRunner

    _REPO_ROOT = Path(__file__).parent
    tools_dir = _REPO_ROOT / "tools"

    t = Table(title="DFIR Environment Check", box=box.ROUNDED, show_header=True)
    t.add_column("Check", style="bold")
    t.add_column("Status", style="bold")
    t.add_column("Detail")

    ok = lambda msg: ("[green]OK[/green]", msg)
    warn = lambda msg: ("[yellow]WARN[/yellow]", msg)
    fail = lambda msg: ("[red]FAIL[/red]", msg)

    # Tools directory
    if tools_dir.exists():
        t.add_row("tools/ directory", *ok(str(tools_dir)))
    else:
        t.add_row("tools/ directory", *fail(f"Not found: {tools_dir}"))

    # Individual tools
    for key, name in TOOL_NAMES.items():
        exe = tools_dir / name
        if exe.is_file():
            t.add_row(f"Tool: {name}", *ok("present"))
        else:
            t.add_row(f"Tool: {name}", *warn("not found (optional if not needed)"))

    # Python analysis libraries
    try:
        import yara  # noqa: F401
        t.add_row("YARA (yara-python)", *ok("importable — malware signature scanning enabled"))
    except Exception:
        t.add_row("YARA (yara-python)", *warn("not installed — pip install yara-python (optional)"))

    try:
        from core.render import renderer_available
        if renderer_available():
            from core.render import ReportRenderer
            r = ReportRenderer()
            if r.available:
                t.add_row("PDF (Playwright/Chromium)", *ok("Chromium ready — PDF + evidence exhibits enabled"))
            else:
                t.add_row("PDF (Playwright/Chromium)", *warn("Playwright installed but Chromium missing — run: playwright install chromium"))
            r.close()
        else:
            t.add_row("PDF (Playwright/Chromium)", *warn("not installed — pip install playwright && playwright install chromium (optional)"))
    except Exception as e:
        t.add_row("PDF (Playwright/Chromium)", *warn(f"unavailable: {str(e)[:60]}"))

    # Agents
    for agent_name, meta in get_all_manifests().items():
        t.add_row(f"Agent: {agent_name}", *ok(meta.get("display_name", agent_name)))

    # Ollama + model check — OPTIONAL. Tool runs without AI by default.
    from core.llm_client import LLMClient
    llm_ok, llm_err = LLMClient.validate_model_spec(model)
    if llm_ok:
        t.add_row("Ollama (optional)", *ok("reachable"))
        t.add_row(f"Model: {model}", *ok("pulled and ready"))
    else:
        first_line = llm_err.split("\n")[0]
        if "not reachable" in llm_err:
            t.add_row("Ollama (optional)", *warn(first_line + " — AI features will be unavailable"))
        elif "no models" in llm_err.lower():
            t.add_row("Ollama (optional)", *ok("reachable"))
            t.add_row(f"Model: {model} (optional)", *warn(first_line))
        else:
            t.add_row("Ollama (optional)", *ok("reachable"))
            t.add_row(f"Model: {model} (optional)", *warn(first_line))

    console.print(t)
    console.print(
        "\n[dim]Note: Ollama and EZ Tools are all optional. The deterministic engine "
        "runs without any of them and will simply skip the modules whose tools are missing.[/dim]"
    )


@cli_group.command("list-agents")
def list_agents_cmd():
    """List all discovered forensic agents."""
    from core.agent_registry import list_agents

    t = Table(title="Discovered Agents", box=box.ROUNDED)
    t.add_column("Name", style="bold cyan")
    t.add_column("Display Name")
    t.add_column("Version")
    t.add_column("Enabled by Default")
    t.add_column("Description")

    for agent in list_agents():
        enabled = "[green]Yes[/green]" if agent.get("enabled_by_default") else "[dim]No[/dim]"
        t.add_row(
            agent["name"],
            agent["display_name"],
            agent["version"],
            enabled,
            agent["description"][:70] + ("..." if len(agent["description"]) > 70 else ""),
        )
    console.print(t)
