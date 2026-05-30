"""
Registry Agent — wraps registry_agent_v7.py logic into the BaseAgent interface.

extract() — copies hives using the locked-file strategies from the legacy script
parse()   — runs ArtifactExtractor + FullRegistryParser (from legacy)
analyze() — uses our shared LLMClient with registry-specific per-artifact prompts
report()  — uses the dark-mode HTML builder from the legacy script
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Make the legacy script importable as a module
_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.finding import Finding
from core.fsutil import safe_exists, safe_iterdir, safe_is_dir
from core.llm_client import LLMClient
from core.manifest import ManifestEntry
from core.progress_bus import ProgressBus

log = logging.getLogger("dfir.registry")

# Lazy-import the legacy module so startup stays fast
_legacy = None


def _get_legacy():
    global _legacy
    if _legacy is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "registry_agent_v7",
            str(_REPO_ROOT / "registry_agent_v7.py"),
        )
        _legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_legacy)
    return _legacy


HIVE_LOCATIONS = [
    # (relative_path_on_mounted_drive, canonical_name)
    ("Windows/System32/config/SYSTEM", "SYSTEM"),
    ("Windows/System32/config/SOFTWARE", "SOFTWARE"),
    ("Windows/System32/config/SAM", "SAM"),
    ("Windows/System32/config/SECURITY", "SECURITY"),
    ("Windows/System32/config/DEFAULT", "DEFAULT"),
    ("Windows/AppCompat/Programs/Amcache.hve", "Amcache"),
]

LOG_EXT_PAIRS = [".LOG1", ".LOG2"]


class Agent(BaseAgent):
    name = "registry"
    display_name = "Windows Registry"
    description = "All Windows Registry hives — USB, persistence, services, network, user activity, execution"
    version = "9.0"
    artifact_subdirs = ["raw_registry"]

    # ── extract ──────────────────────────────────────────────────────────

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        legacy = _get_legacy()
        dest_dir = ctx.agent_artifacts_dir(self.name) / "raw_registry"
        dest_dir.mkdir(parents=True, exist_ok=True)

        copied: List[Path] = []
        manifest_entries: List[dict] = []
        root = ctx.mount_point

        # System hives
        for rel, canon_name in HIVE_LOCATIONS:
            src = root / rel.replace("/", "\\")
            if not safe_exists(src):
                src = root / rel  # try forward-slash too
            if not safe_exists(src):
                progress.log("WARNING", self.name, f"Hive not found: {rel}")
                continue
            dest_name = canon_name
            try:
                dst = legacy.copy_locked_hive(src, dest_dir, dest_name)
            except OSError as e:
                progress.log("WARNING", self.name, f"Hive copy I/O error for {canon_name}: {e}")
                continue
            if dst:
                copied.append(dst)
                progress.log("INFO", self.name, f"Copied {canon_name}")
                # Copy transaction logs
                for ext in LOG_EXT_PAIRS:
                    log_src = Path(str(src) + ext)
                    if safe_exists(log_src):
                        log_dst = dest_dir / (dest_name + ext)
                        try:
                            import shutil
                            shutil.copy2(str(log_src), str(log_dst))
                            copied.append(log_dst)
                        except Exception:
                            pass

        # Per-user NTUSER.DAT / USRCLASS.dat
        users_dir = root / "Users"
        if safe_exists(users_dir):
            user_dirs = list(safe_iterdir(users_dir))
            for user_dir in user_dirs:
                if not safe_is_dir(user_dir):
                    continue
                uname = user_dir.name
                for hive_rel, dest_pattern in [
                    ("NTUSER.DAT", f"NTUSER_{uname}"),
                    ("AppData/Local/Microsoft/Windows/UsrClass.dat", f"USRCLASS_{uname}"),
                    ("AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", f"USRCLASS_{uname}"),
                ]:
                    try:
                        src = user_dir / hive_rel
                        if safe_exists(src):
                            try:
                                dst = legacy.copy_locked_hive(src, dest_dir, dest_pattern)
                            except OSError as e:
                                progress.log("WARNING", self.name,
                                             f"User hive I/O error for {dest_pattern}: {e}")
                                continue
                            if dst:
                                copied.append(dst)
                                progress.log("INFO", self.name, f"Copied user hive: {dest_pattern}")
                                for ext in LOG_EXT_PAIRS:
                                    log_src = Path(str(src) + ext)
                                    if safe_exists(log_src):
                                        try:
                                            import shutil
                                            log_dst = dest_dir / (dest_pattern + ext)
                                            shutil.copy2(str(log_src), str(log_dst))
                                            copied.append(log_dst)
                                        except Exception:
                                            pass
                            break
                    except (PermissionError, OSError) as e:
                        progress.log("WARNING", self.name, f"User hive error ({uname}/{hive_rel}): {e}")

        # Write SHA256 manifest
        from core.manifest import sha256 as compute_sha256
        for p in copied:
            if p.is_file():
                manifest_entries.append({
                    "agent": self.name,
                    "artifact": p.name,
                    "path": str(p),
                    "size_bytes": p.stat().st_size,
                    "sha256": compute_sha256(p),
                })

        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=len(copied) > 0,
            artifacts=copied,
            elapsed=time.time() - t0,
            metadata={"hive_count": len(copied), "dest_dir": str(dest_dir), "manifest": manifest_entries},
        )

    # ── parse ─────────────────────────────────────────────────────────────

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        legacy = _get_legacy()
        parsed_dir = ctx.agent_parsed_dir(self.name)
        dest_dir = ctx.agent_artifacts_dir(self.name) / "raw_registry"

        if not extract_result.success:
            progress.stage_error(self.name, "parse", "No hives were extracted")
            return ParseResult(agent=self.name, success=False, error="No hives extracted")

        # Load hives
        progress.stage_progress(self.name, "parse", 10, "Loading hives")
        hives: Dict[str, Any] = {}
        for hive_path in dest_dir.iterdir():
            if hive_path.suffix.upper() in (".LOG1", ".LOG2", ".json"):
                continue
            try:
                from Registry import Registry
                hives[hive_path.name.upper()] = Registry.Registry(str(hive_path))
                progress.log("INFO", self.name, f"Loaded hive: {hive_path.name}")
            except Exception as e:
                progress.log("WARNING", self.name, f"Could not load hive {hive_path.name}: {e}")

        if not hives:
            progress.stage_error(self.name, "parse", "No hives could be loaded")
            return ParseResult(agent=self.name, success=False, error="No hives loaded")

        # Full-hive JSONL export
        progress.stage_progress(self.name, "parse", 20, "Exporting full hive JSONL")
        parse_stats = {}
        output_files: List[Path] = []
        for hive_name, reg in hives.items():
            try:
                # FullRegistryParser(hive_name, source_path, user=None) — NOT hive_path
                # parse_to_jsonl(reg, output_path) — NOT export_jsonl
                parser = legacy.FullRegistryParser(
                    hive_name=hive_name,
                    source_path=str(dest_dir / hive_name),
                )
                jsonl_path = parsed_dir / f"{hive_name}.jsonl"
                stats = parser.parse_to_jsonl(reg, jsonl_path)
                parse_stats[hive_name] = stats
                if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
                    output_files.append(jsonl_path)
                    progress.log("INFO", self.name, f"JSONL: {hive_name} — {stats.get('total_keys', 0)} keys")
            except Exception as e:
                progress.log("WARNING", self.name, f"JSONL export failed for {hive_name}: {e}")

        # Triage extraction
        progress.stage_progress(self.name, "parse", 60, "Running triage extractor")
        try:
            ext = legacy.ArtifactExtractor(hives)
            users = list(hives.get("HIVES_USERS", {}).keys())
            # Detect users from hive names
            users = [n.replace("NTUSER_", "") for n in hives.keys() if n.startswith("NTUSER_")]

            system_info = {
                "ComputerName": ext.computer_name(),
                "os_info": ext.os_info(),
                "timezone": ext.timezone(),
                "last_shutdown": ext.last_shutdown(),
            }

            artifacts = self._run_all_extractions(ext, users, progress)

            # Save artifacts.json
            artifacts_path = parsed_dir / "artifacts.json"
            safe_arts = {k: v for k, v in artifacts.items() if k != "_analysis"}
            with open(artifacts_path, "w", encoding="utf-8") as f:
                json.dump({"system_info": system_info, "artifacts": safe_arts}, f, indent=2, default=str)
            output_files.append(artifacts_path)

            # Manifest
            manifest_path = parsed_dir / "registry_manifest.json"
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump({
                    "generated_at": str(time.time()),
                    "computer_name": system_info.get("ComputerName", ""),
                    "users": users,
                    "parse_stats": parse_stats,
                }, f, indent=2, default=str)
            output_files.append(manifest_path)

        except Exception as e:
            import traceback
            progress.log("ERROR", self.name, f"Triage extraction failed: {e}\n{traceback.format_exc()}")
            system_info = {}
            artifacts = {}

        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=True,
            output_files=output_files,
            elapsed=time.time() - t0,
            system_info=system_info,
            metadata={
                "users": users if "users" in dir() else [],
                "artifacts_keys": list(artifacts.keys()) if artifacts else [],
                "hives_loaded": list(hives.keys()),
                "parse_stats": parse_stats,
                "_artifacts_ref": artifacts,
                "_hives_ref": hives,
            },
        )

    def _run_all_extractions(self, ext, users, progress):
        artifacts = {}
        artifacts["usb_devices"] = ext.usb_devices()
        artifacts["persistence_system"] = ext.persistence_system()
        artifacts["winlogon"] = ext.winlogon()
        artifacts["autologon"] = ext.autologon_check()
        artifacts["appinit_dlls"] = ext.appinit_dlls()
        artifacts["ifeo"] = ext.ifeo()
        artifacts["services"] = ext.services()
        artifacts["wifi_profiles"] = ext.wifi_profiles()
        artifacts["network_signatures"] = ext.network_signatures()
        artifacts["network_interfaces"] = ext.network_interfaces()
        artifacts["firewall_status"] = ext.firewall_status()
        artifacts["shared_folders"] = ext.shared_folders()
        artifacts["vpn_indicators"] = ext.vpn_indicators()
        artifacts["user_accounts"] = ext.user_accounts()
        artifacts["last_logon_info"] = ext.last_logon_info()
        artifacts["scheduled_tasks"] = ext.scheduled_tasks()
        artifacts["bam_entries"] = ext.bam_entries()
        artifacts["shimcache"] = ext.shimcache()
        artifacts["amcache"] = ext.amcache()
        artifacts["installed_software"] = ext.installed_software()
        artifacts["capability_access"] = ext.capability_access()
        artifacts["dns_cache_registry"] = ext.dns_cache_registry()
        artifacts["svchost_groups"] = ext.svchost_groups()
        artifacts["security_policy"] = ext.security_policy()

        artifacts["users"] = {}
        for user in users:
            udata = {}
            udata["runmru"] = ext.runmru(user)
            udata["typed_paths"] = ext.typed_paths(user)
            udata["recent_docs"] = ext.recent_docs(user)
            udata["open_save_mru"] = ext.open_save_mru(user)
            udata["last_visited_mru"] = ext.last_visited_mru(user)
            udata["search_history"] = ext.search_history(user)
            udata["typed_urls"] = ext.typed_urls(user)
            udata["userassist"] = ext.userassist(user)
            udata["shellbags"] = ext.shellbags(user)
            udata["rdp_mru"] = ext.rdp_mru(user)
            udata["mapped_drives"] = ext.mapped_drives(user)
            udata["mount_points2"] = ext.mount_points2(user)
            udata["ie_zone_map"] = ext.ie_zone_map(user)
            udata["persistence_user"] = ext.persistence_user(user)
            udata["chrome_prefs_reg"] = ext.chrome_prefs_reg(user)
            artifacts["users"][user] = udata
        return artifacts

    # ── analyze ──────────────────────────────────────────────────────────

    def analyze(self, ctx: CaseContext, parse_result: ParseResult, llm: LLMClient, progress: ProgressBus) -> List[Finding]:
        progress.stage_started(self.name, "analyze")
        findings: List[Finding] = []
        artifacts = parse_result.metadata.get("_artifacts_ref", {})
        users = parse_result.metadata.get("users", [])

        if not artifacts:
            # Fall back to loading artifacts.json
            artifacts_path = ctx.agent_parsed_dir(self.name) / "artifacts.json"
            if artifacts_path.exists():
                with open(artifacts_path, encoding="utf-8") as f:
                    data = json.load(f)
                artifacts = data.get("artifacts", {})

        # Pre-filter scheduled tasks: drop obvious Microsoft/Windows noise, cap at 30
        all_tasks = artifacts.get("scheduled_tasks", [])
        _ms_prefixes = ("\\Microsoft\\", "\\MicrosoftEdge", "\\Windows ")
        suspicious_tasks = [
            t for t in all_tasks
            if not any(t.get("path", "").startswith(p) for p in _ms_prefixes)
        ][:30] or all_tasks[:20]

        # Pre-filter services: only non-standard paths (exclude system32/SysWOW64), cap at 40
        all_svcs = [
            {"name": s.get("name"), "image_path": s.get("image_path"),
             "start_label": s.get("start_label"), "suspicious": s.get("suspicious_path")}
            for s in artifacts.get("services", []) if s.get("image_path")
        ]
        suspicious_svcs = [
            s for s in all_svcs
            if s.get("suspicious") or (
                s.get("image_path") and
                "system32" not in s["image_path"].lower() and
                "syswow64" not in s["image_path"].lower() and
                "program files" not in s["image_path"].lower()
            )
        ][:40] or all_svcs[:30]

        analyze_targets = [
            ("USB Devices", artifacts.get("usb_devices", [])),
            ("System Persistence", {
                "run_keys": artifacts.get("persistence_system", []),
                "winlogon": artifacts.get("winlogon", {}),
                "ifeo": artifacts.get("ifeo", []),
                "appinit_dlls": artifacts.get("appinit_dlls", {}),
                "autologon": artifacts.get("autologon", {}),
            }),
            ("Windows Services", suspicious_svcs),
            ("Network & Connectivity", {
                "wifi_profiles": artifacts.get("wifi_profiles", []),
                "network_signatures": artifacts.get("network_signatures", []),
                "firewall_status": artifacts.get("firewall_status", {}),
                "vpn_indicators": artifacts.get("vpn_indicators", []),
                "shared_folders": artifacts.get("shared_folders", []),
            }),
            ("Execution Artifacts", {
                "bam": artifacts.get("bam_entries", [])[:20],
                "shimcache": artifacts.get("shimcache", [])[:20],
                "amcache": artifacts.get("amcache", [])[:20],
            }),
            ("Security Policy", artifacts.get("security_policy", [])[:20]),
            ("Scheduled Tasks", suspicious_tasks),
        ]

        total = len(analyze_targets) + len(users)
        done = 0
        for artifact_name, data in analyze_targets:
            progress.stage_progress(self.name, "analyze", (done / total) * 100, artifact_name)
            try:
                result = llm.analyze_chunk(self.name, artifact_name, data)
                for raw in result.findings_raw:
                    f = Finding.from_llm(self.name, artifact_name, raw, result.risk_score)
                    findings.append(f)
                    progress.finding_added(self.name, len(findings), f.severity)
            except Exception as e:
                progress.log("WARNING", self.name, f"Analysis failed for {artifact_name}: {e}")
            done += 1

        for user in users:
            udata = artifacts.get("users", {}).get(user, {})
            artifact_name = f"User Activity: {user}"
            progress.stage_progress(self.name, "analyze", (done / total) * 100, artifact_name)
            user_data = {
                "runmru": udata.get("runmru", []),
                "userassist": udata.get("userassist", [])[:20],
                "search_history": udata.get("search_history", []),
                "typed_paths": udata.get("typed_paths", []),
                "rdp_mru": udata.get("rdp_mru", []),
                "recent_docs": udata.get("recent_docs", [])[:20],
                "persistence": udata.get("persistence_user", []),
                "shellbags": udata.get("shellbags", [])[:20],
            }
            try:
                result = llm.analyze_chunk(self.name, artifact_name, user_data)
                for raw in result.findings_raw:
                    f = Finding.from_llm(self.name, artifact_name, raw, result.risk_score)
                    findings.append(f)
                    progress.finding_added(self.name, len(findings), f.severity)
            except Exception as e:
                progress.log("WARNING", self.name, f"User analysis failed for {user}: {e}")
            done += 1

        progress.stage_done(self.name, "analyze")
        return findings

    # ── report ────────────────────────────────────────────────────────────

    def report(self, ctx: CaseContext, findings: List[Finding], parse_result: ParseResult) -> Path:
        """Use the rich dark-mode HTML builder from the legacy registry script."""
        legacy = _get_legacy()

        artifacts = parse_result.metadata.get("_artifacts_ref", {})
        system_info = parse_result.system_info or {}
        users = parse_result.metadata.get("users", [])
        parsed_dir = ctx.agent_parsed_dir(self.name)

        all_findings_legacy = [
            {"severity": f.severity, "title": f.title, "detail": f.detail,
             "ioc": f.ioc, "artifact": f.artifact}
            for f in findings
        ]

        # Build a meaningful exec summary from findings (no LLM needed here)
        crit = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        computer = system_info.get("ComputerName", "the target system")
        key = [f.title for f in findings if f.severity in ("CRITICAL", "HIGH")][:4]
        exec_summary = (
            f"Registry forensic analysis of {computer} identified {len(findings)} findings "
            f"({crit} CRITICAL, {high} HIGH) across {len(users)} user profile(s). "
        )
        if key:
            exec_summary += f"Key concerns: {'; '.join(key)}."
        elif not findings:
            exec_summary += "No significant anomalies detected in the registry."

        try:
            html_path = legacy.build_report(
                artifacts, exec_summary, all_findings_legacy,
                parsed_dir, users, system_info
            )
            # Surgical mojibake repair: only fixes cp1252-mojibake'd UTF-8 sequences
            # (e.g. "ðŸ"Š" → "📊") without touching legitimate Unicode like em-dash.
            from core.text.mojibake import fix_mojibake_file
            fix_mojibake_file(html_path)

            import shutil
            out_path = ctx.reports_dir / "registry_report.html"
            html_path_p = Path(html_path)
            if html_path_p.exists():
                shutil.copy2(str(html_path_p), str(out_path))
            return out_path
        except Exception as e:
            log.warning(f"Legacy report builder failed: {e}, falling back to base report")
            return super().report(ctx, findings, parse_result)
