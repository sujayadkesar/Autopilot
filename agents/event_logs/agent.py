"""
Event Logs Agent — Windows EVTX analysis via EvtxECmd.

Extracts key .evtx files from the mounted image, parses with EvtxECmd,
and performs LLM analysis focused on:
  - Authentication events (4624/4625/4648/4740)
  - Privilege escalation (4672/4673)
  - Service & driver installs (7045)
  - Scheduled task creation (4698/4702)
  - Process creation (4688) — requires audit policy enabled
  - PowerShell script blocks (4104)
  - Sysmon (1/3/11/12/13) — if Sysmon deployed
  - Lateral movement (4776/4769 Kerberos, 4771)
  - Account management (4720/4722/4725/4732/4738)
"""

from __future__ import annotations

import csv
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.finding import Finding
from core.fsutil import safe_exists, safe_glob
from core.llm_client import LLMClient
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner

# Event log directory on the image
EVTX_DIR = r"Windows\System32\winevt\Logs"

# Mapping prefixes to categories — used to bucket the discovered .evtx files
CATEGORY_PREFIXES = [
    # (filename prefix lowercase,                                      category)
    ("security.evtx",                                                  "security"),
    ("system.evtx",                                                    "system"),
    ("application.evtx",                                               "application"),
    ("setup.evtx",                                                     "system"),
    ("microsoft-windows-powershell",                                   "powershell"),
    ("microsoft-windows-sysmon",                                       "sysmon"),
    ("microsoft-windows-taskscheduler",                                "scheduled_tasks"),
    ("microsoft-windows-terminalservices",                             "rdp"),
    ("microsoft-windows-remotedesktop",                                "rdp"),
    ("microsoft-windows-winrm",                                        "remoting"),
    ("microsoft-windows-wmi",                                          "remoting"),
    ("microsoft-windows-windefend",                                    "defender"),
    ("microsoft-windows-bits",                                         "bits"),
    ("microsoft-windows-smbserver",                                    "smb"),
    ("microsoft-windows-smbclient",                                    "smb"),
    ("microsoft-windows-ntlm",                                         "auth"),
    ("microsoft-windows-kerberos",                                     "auth"),
    ("microsoft-windows-applocker",                                    "applocker"),
    ("microsoft-windows-codeintegrity",                                "code_integrity"),
    ("microsoft-windows-firewall",                                     "firewall"),
    ("microsoft-windows-dns",                                          "dns"),
    ("microsoft-windows-dhcp",                                         "dns"),
    ("microsoft-windows-storage",                                      "storage"),
    ("microsoft-windows-printservice",                                 "print"),
    ("microsoft-windows-driverframeworks",                             "drivers"),
    ("microsoft-windows-windowsupdate",                                "windows_update"),
]


def _categorise_evtx(filename: str) -> str:
    """Return a category folder name for an .evtx filename."""
    fn = filename.lower()
    for prefix, cat in CATEGORY_PREFIXES:
        if fn.startswith(prefix) or fn == prefix:
            return cat
    return "other"

# Event IDs that are high-signal for forensics — EvtxECmd filter
PRIORITY_EVENT_IDS = {
    # Authentication
    4624, 4625, 4634, 4647, 4648, 4649, 4768, 4769, 4771, 4776,
    # Privilege
    4672, 4673, 4674,
    # Account management
    4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4733, 4738, 4740, 4767,
    # Service / driver
    7045, 7034, 7036,
    # Scheduled tasks
    4698, 4699, 4700, 4701, 4702,
    # Process creation (requires audit policy)
    4688, 4689,
    # Object access
    4663, 4656, 4670,
    # Policy changes
    4719, 4739, 4904, 4905,
    # PowerShell
    4103, 4104,
    # Sysmon
    1, 3, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23, 25,
    # Misc
    1102, 1100,  # log cleared / audit stopped
}


class Agent(BaseAgent):
    name = "event_logs"
    display_name = "Windows Event Logs"
    description = "Security, System, PowerShell, Sysmon EVTX — auth, privilege, lateral movement"
    version = "1.0"
    artifact_subdirs = ["security", "system", "application", "powershell", "sysmon",
                        "scheduled_tasks", "rdp", "smb", "auth", "remoting", "defender",
                        "applocker", "firewall", "dns", "code_integrity", "other"]

    # ── extract ──────────────────────────────────────────────────────────────

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []
        metadata: dict = {"categories": {}}

        evtx_dir = root / EVTX_DIR.replace("\\", "/")
        if not safe_exists(evtx_dir):
            evtx_dir = root / EVTX_DIR
        if not safe_exists(evtx_dir):
            progress.log("WARNING", self.name, f"Event log directory not found: {evtx_dir}")
            progress.stage_done(self.name, "extract")
            return ExtractResult(agent=self.name, success=False, error="winevt/Logs not found",
                                 elapsed=time.time() - t0)

        # Discover ALL .evtx files (typically 230+ on a Windows 10/11 system)
        evtx_files = sorted(safe_glob(evtx_dir, "*.evtx"))
        if not evtx_files:
            progress.log("WARNING", self.name,
                         f"No .evtx files enumerable under {evtx_dir} "
                         f"(directory may be inaccessible)")
            progress.stage_done(self.name, "extract")
            return ExtractResult(agent=self.name, success=False,
                                 error="No EVTX files readable",
                                 elapsed=time.time() - t0)

        total = len(evtx_files)
        progress.log("INFO", self.name, f"Discovered {total} .evtx file(s) — copying all")

        for i, src in enumerate(evtx_files, 1):
            progress.stage_progress(self.name, "extract", (i / total) * 100, src.name)
            try:
                if src.stat().st_size < 70_000:
                    continue  # empty header-only EVTX
            except OSError:
                continue
            category = _categorise_evtx(src.name)
            dest_dir = ctx.agent_artifacts_dir(self.name) / category
            dest_dir.mkdir(parents=True, exist_ok=True)
            dst = dest_dir / src.name
            try:
                shutil.copy2(str(src), str(dst))
                copied.append(dst)
                metadata["categories"].setdefault(category, []).append(str(dst))
            except OSError as e:
                # I/O device errors mid-copy — skip this evtx and continue with next
                errors.append(f"{src.name}: {e}")
            except Exception as e:
                errors.append(f"{src.name}: {e}")

        # Summary by category
        cat_summary = ", ".join(f"{c}={len(v)}" for c, v in metadata["categories"].items())
        progress.log("INFO", self.name, f"Extracted {len(copied)} non-empty EVTX file(s) — {cat_summary}")
        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=len(copied) > 0,
            artifacts=copied,
            elapsed=time.time() - t0,
            error="; ".join(errors[:5]) + (f" (+{len(errors)-5} more)" if len(errors) > 5 else ""),
            metadata=metadata,
        )

    # ── parse ─────────────────────────────────────────────────────────────────

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        parsed_dir = ctx.agent_parsed_dir(self.name)
        parsed_dir.mkdir(parents=True, exist_ok=True)
        output_files: List[Path] = []
        errors: List[str] = []
        categories: dict = extract_result.metadata.get("categories", {})

        try:
            exe = runner.resolve("evtxecmd")
        except ToolNotFoundError as e:
            progress.log("WARNING", self.name, f"EvtxECmd not found — skipping: {e}")
            progress.stage_done(self.name, "parse")
            return ParseResult(
                agent=self.name, success=False, error=str(e),
                elapsed=time.time() - t0,
            )

        total = sum(len(v) for v in categories.values())
        processed = 0
        for category, evtx_paths in categories.items():
            out_dir = parsed_dir / category
            out_dir.mkdir(parents=True, exist_ok=True)
            for evtx_path in evtx_paths:
                processed += 1
                progress.stage_progress(
                    self.name, "parse", (processed / max(total, 1)) * 100,
                    Path(evtx_path).name,
                )
                stem = Path(evtx_path).stem.replace("%4", "_").replace(" ", "_")[:40]
                csv_name = f"{stem}.csv"
                # NOTE: EvtxECmd v2026.5.0+ removed the '-q' (quiet) flag — passing it
                # causes RC=1 with "Unrecognized command or argument" and ZERO output.
                cmd = [str(exe), "-f", evtx_path, "--csv", str(out_dir), "--csvf", csv_name]
                try:
                    runner.run(cmd, f"EvtxECmd_{stem}", timeout=300)
                    out_csv = out_dir / csv_name
                    if out_csv.exists() and out_csv.stat().st_size > 0:
                        output_files.append(out_csv)
                        progress.log("INFO", self.name, f"Parsed {Path(evtx_path).name} → {csv_name}")
                except ExecutionError as e:
                    errors.append(f"{Path(evtx_path).name}: {e}")
                    progress.log("WARNING", self.name, f"Parse error {Path(evtx_path).name}: {e}")

        # ── HAYABUSA: Sigma-rule threat hunting across all evtx files ────────
        # Runs after EvtxECmd produces our normalised CSVs. Hayabusa is a fast
        # Rust-based event-log hunter that maps Sigma rules → detections.
        # Output: hayabusa_results.csv with each detection's rule, severity, evtx.
        try:
            hayabusa_exe = runner.resolve("hayabusa")
            hb_out = parsed_dir / "hayabusa_results.csv"
            evtx_artifact_root = ctx.agent_artifacts_dir(self.name)
            progress.log("INFO", self.name,
                         "Hayabusa: scanning all EVTX files with Sigma rules…")
            # Note: -w IS the short form of --no-wizard, NOT overwrite.
            #       Overwrite is -C/--clobber. Don't pass both -w and --no-wizard.
            hb_cmd = [
                str(hayabusa_exe), "csv-timeline",
                "-d", str(evtx_artifact_root),
                "-o", str(hb_out),
                "-w",                 # --no-wizard: scan all rules, don't prompt
                "-C",                 # --clobber: overwrite existing output
                "--min-level", "low",
                "-q",                 # quiet (suppresses banner)
            ]
            # Hayabusa's bundled rule directory; if user has run `hayabusa update-rules`
            # it lives next to the exe under tools/rules/
            rules_dir = Path(hayabusa_exe).parent / "rules"
            if rules_dir.exists():
                hb_cmd += ["-r", str(rules_dir)]
            else:
                progress.log("INFO", self.name,
                             "Hayabusa rules/ directory missing — using built-in defaults. "
                             "Run `hayabusa update-rules` once in tools/ for full coverage.")
            try:
                runner.run(hb_cmd, "Hayabusa", timeout=1800, retries=1)
                if hb_out.exists() and hb_out.stat().st_size > 0:
                    output_files.append(hb_out)
                    line_count = sum(1 for _ in open(hb_out, encoding="utf-8", errors="replace"))
                    progress.log("INFO", self.name,
                                 f"Hayabusa: {line_count - 1:,} detection(s) → {hb_out.name}")
            except ExecutionError as e:
                progress.log("WARNING", self.name, f"Hayabusa run failed: {str(e)[:200]}")
        except ToolNotFoundError:
            progress.log("INFO", self.name,
                         "Hayabusa not found in tools/ — skipping Sigma-rule threat hunt "
                         "(install hayabusa.exe in tools/ for automated threat hunting)")

        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=len(output_files) > 0,
            output_files=output_files,
            elapsed=time.time() - t0,
            error="; ".join(errors),
            metadata={"parsed_count": len(output_files)},
        )

    # ── analyze ───────────────────────────────────────────────────────────────

    def analyze(self, ctx: CaseContext, parse_result: ParseResult,
                llm: LLMClient, progress: ProgressBus) -> List[Finding]:
        progress.stage_started(self.name, "analyze")
        findings: List[Finding] = []

        if not parse_result.success or not parse_result.output_files:
            progress.stage_done(self.name, "analyze")
            return findings

        # Load and filter to priority event IDs across all CSVs
        all_rows: List[Dict[str, str]] = []
        for csv_path in parse_result.output_files:
            try:
                with open(csv_path, encoding="utf-8-sig", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        eid = row.get("EventId", row.get("Event Id", ""))
                        try:
                            if int(eid) in PRIORITY_EVENT_IDS:
                                row["_source_file"] = csv_path.stem
                                all_rows.append(row)
                        except (ValueError, TypeError):
                            pass
            except Exception as e:
                progress.log("WARNING", self.name, f"Error reading {csv_path.name}: {e}")

        if not all_rows:
            progress.log("INFO", self.name, "No priority events found in parsed logs")
            progress.stage_done(self.name, "analyze")
            return findings

        progress.log("INFO", self.name, f"Analysing {len(all_rows)} priority events")

        # Group by event category for targeted analysis
        def _eid(r):
            try:
                return int(r.get("EventId", r.get("Event Id", 0)))
            except (ValueError, TypeError):
                return 0

        auth_rows    = [r for r in all_rows if _eid(r) in {4624,4625,4648,4649,4768,4769,4771,4776}]
        acct_rows    = [r for r in all_rows if _eid(r) in {4720,4722,4724,4725,4726,4728,4732,4738,4740,4767}]
        svc_rows     = [r for r in all_rows if _eid(r) in {7045,7034,7036}]
        task_rows    = [r for r in all_rows if _eid(r) in {4698,4699,4700,4701,4702}]
        priv_rows    = [r for r in all_rows if _eid(r) in {4672,4673,4674}]
        ps_rows      = [r for r in all_rows if _eid(r) in {4103,4104}]
        proc_rows    = [r for r in all_rows if _eid(r) in {4688,4689}]
        sysmon_rows  = [r for r in all_rows if _eid(r) in {1,3,7,8,10,11,12,13,15,17,18,22,23,25}]
        misc_rows    = [r for r in all_rows if _eid(r) in {1102,1100,4719}]

        groups = [
            ("Authentication Events",    auth_rows,   "auth"),
            ("Account Management",       acct_rows,   "account"),
            ("Service Installs",         svc_rows,    "service"),
            ("Scheduled Task Changes",   task_rows,   "scheduled_tasks"),
            ("Privilege Use",            priv_rows,   "privilege"),
            ("PowerShell Activity",      ps_rows,     "powershell"),
            ("Process Creation",         proc_rows,   "process"),
            ("Sysmon Activity",          sysmon_rows, "sysmon"),
            ("Audit / Log Tampering",    misc_rows,   "audit"),
        ]

        inv_prompt = ctx.investigation_prompt or ""
        total_groups = sum(1 for _, rows, _ in groups if rows)
        done_groups = 0

        for group_name, rows, tag in groups:
            if not rows:
                continue
            done_groups += 1
            progress.stage_progress(
                self.name, "analyze",
                (done_groups / max(total_groups, 1)) * 100,
                group_name,
            )

            # Trim to most recent/relevant 40 rows
            sample = rows[-40:]
            # Remove noisy columns to save tokens
            noisy = {"Chunk", "Offset", "IsSystem", "EventRecordId", "Hidden",
                     "UserId", "Keywords", "Level", "Opcode", "Task", "Version"}
            cleaned = [{k: v for k, v in r.items() if k not in noisy and v}
                       for r in sample]

            data_str = json.dumps(cleaned, indent=None, default=str)[:3000]

            system_msg = (
                "You are a senior DFIR analyst examining Windows event logs from a forensic image. "
                "Identify ONLY genuine suspicious or malicious activity — not normal Windows operations. "
                "Focus on: unauthorized access, persistence, privilege escalation, lateral movement, "
                "data exfiltration, tampering. For each finding provide a specific event ID, "
                "timestamp, account name, and exact detail from the data. "
                "Ignore routine system/service events.\n"
                "Respond ONLY with a JSON array. No explanation outside JSON.\n"
                '[\n  {"severity":"HIGH","title":"...","detail":"...","ioc":"","timestamp":""}\n]'
            )
            if inv_prompt:
                system_msg += f"\n\nInvestigation brief:\n{inv_prompt}"

            user_msg = (
                f"Event log group: {group_name}\n"
                f"Computer: {ctx.customer_name}\n\n"
                f"Events ({len(rows)} total, showing {len(sample)}):\n{data_str}\n\n"
                "List ONLY real suspicious findings. If nothing is suspicious, return []."
            )

            try:
                raw = llm._backend.ask(system_msg, user_msg, max_tokens=600)
                if not raw:
                    continue
                # Extract JSON array
                import re
                m = re.search(r'\[.*\]', raw, re.DOTALL)
                if not m:
                    continue
                items = json.loads(m.group(0))
                for item in items:
                    if not isinstance(item, dict) or not item.get("title"):
                        continue
                    sev = str(item.get("severity", "MEDIUM")).upper()
                    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                        sev = "MEDIUM"
                    ts_raw = item.get("timestamp", "")
                    ts = None
                    if ts_raw:
                        from datetime import datetime
                        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                            try:
                                ts = datetime.strptime(ts_raw[:19], fmt)
                                break
                            except ValueError:
                                pass
                    findings.append(Finding(
                        agent=self.name,
                        artifact=group_name,
                        severity=sev,
                        title=str(item.get("title", ""))[:120],
                        detail=str(item.get("detail", ""))[:500],
                        ioc=str(item.get("ioc", "")),
                        timestamp=ts,
                        risk_score={"CRITICAL": 95, "HIGH": 75, "MEDIUM": 45,
                                    "LOW": 20, "INFO": 5}.get(sev, 45),
                    ))
                    progress.finding_added(self.name, len(findings), sev)
                    progress.log("INFO", self.name,
                                 f"[{sev}] {group_name}: {item.get('title','')[:60]}")
            except Exception as e:
                progress.log("WARNING", self.name, f"LLM error on {group_name}: {e}")

        progress.stage_done(self.name, "analyze")
        return findings
