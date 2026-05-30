"""
Additional InvestigationEngine scan modules — split out so engine.py stays
readable. Mixed in via a small mixin import in engine.py.

Scans defined here:
  _scan_srum_exfil           — large outbound byte counts in SRUM
  _scan_hayabusa_detections  — Sigma-rule hits from Hayabusa CSV
  _scan_pca_executions       — Win 11 PCA non-standard launches
  _scan_scheduled_task_xml   — on-disk task XML persistence
  _scan_anti_forensic_gaps   — USN sequence gaps + Prefetch-disabled detection
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List

from .engine import EvidenceSnippet, InvestigationFinding, _safe_open_csv

log = logging.getLogger("dfir.investigator.extras")


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def scan_srum_exfil(parsed: Path) -> List[InvestigationFinding]:
    """Flag processes with unusually high egress byte counts in SRUM data."""
    out: List[InvestigationFinding] = []
    srum_dir = parsed / "prefetch_amcache_mft" / "srum"
    if not srum_dir.exists():
        return out

    candidates = list(srum_dir.rglob("*Network*Usage*.csv")) + \
                 list(srum_dir.rglob("*NetworkUsages.csv"))
    if not candidates:
        return out

    rows_with_bytes: List[Dict[str, Any]] = []
    for csv_path in candidates:
        rdr = _safe_open_csv(csv_path)
        if not rdr:
            continue
        for row in rdr:
            bs_raw = row.get("BytesSent") or row.get("Bytes Sent") or "0"
            try:
                bs = int(str(bs_raw).replace(",", "")) if bs_raw else 0
            except ValueError:
                bs = 0
            if bs <= 0:
                continue
            br_raw = row.get("BytesReceived") or row.get("Bytes Received") or "0"
            try:
                br = int(str(br_raw).replace(",", "")) if br_raw else 0
            except ValueError:
                br = 0
            rows_with_bytes.append({
                "exe": (row.get("ExeInfo") or row.get("AppId") or row.get("UserId") or "")[:120],
                "user": (row.get("UserName") or row.get("UserId") or "")[:60],
                "bytes_sent": bs,
                "bytes_recv": br,
                "timestamp": row.get("Timestamp", row.get("EventTimestamp", "")),
                "source": csv_path.name,
            })

    if not rows_with_bytes:
        return out

    rows_with_bytes.sort(key=lambda r: r["bytes_sent"], reverse=True)
    big = [r for r in rows_with_bytes if r["bytes_sent"] >= 100_000_000][:25]
    top = rows_with_bytes[:25]

    show = big or top
    if not show:
        return out

    rows_for_table = [[
        str(r["timestamp"])[:19],
        r["exe"],
        r["user"],
        _fmt_bytes(r["bytes_sent"]),
        _fmt_bytes(r["bytes_recv"]),
        r["source"],
    ] for r in show]

    out.append(InvestigationFinding(
        category="cloud_upload",
        title=(f"Large outbound transfers in SRUM ({len(big)} >100 MB)" if big
               else f"Top {len(top)} processes by network egress (SRUM)"),
        severity="HIGH" if big else "MEDIUM",
        summary=("SRUM recorded process-level network byte counts. "
                 "Flagged processes have notable egress."),
        detail=("SRUM aggregates per-process bytes-sent/received per hour-interface tuple. "
                "Outbound byte counts are particularly relevant in DLP investigations. "
                "Large or sustained egress from non-browser processes warrants review."),
        evidence=[EvidenceSnippet(
            title="Highest-egress processes recorded by SRUM",
            source="prefetch_amcache_mft/srum",
            headers=["timestamp", "exe", "user", "bytes_sent", "bytes_recv", "source"],
            rows=rows_for_table,
            highlight={"bytes_sent", "exe"},
        )],
        iocs=[r["exe"] for r in show if r["exe"]][:25],
    ))
    return out


def scan_hayabusa_detections(parsed: Path) -> List[InvestigationFinding]:
    out: List[InvestigationFinding] = []
    hb_csv = parsed / "event_logs" / "hayabusa_results.csv"
    if not hb_csv.exists():
        return out
    rdr = _safe_open_csv(hb_csv)
    if not rdr:
        return out

    by_sev: Dict[str, List[Dict]] = {"crit": [], "high": [], "med": [], "low": [], "info": []}
    for row in rdr:
        level = (row.get("Level") or row.get("level") or "").strip().lower()
        bucket = {"critical": "crit", "high": "high", "medium": "med",
                  "low": "low", "informational": "info", "info": "info"}.get(level, "info")
        by_sev[bucket].append(row)

    sev_map = {"crit": "CRITICAL", "high": "HIGH", "med": "MEDIUM",
               "low": "LOW", "info": "INFO"}
    for bucket, items in by_sev.items():
        if not items:
            continue
        headers = ["timestamp", "rule", "computer", "channel", "event_id", "details"]
        rows = []
        for it in items[:30]:
            rows.append([
                str(it.get("Timestamp", it.get("timestamp", "")))[:19],
                str(it.get("RuleTitle", it.get("rule", it.get("Rule", ""))))[:80],
                str(it.get("Computer", it.get("computer", "")))[:40],
                str(it.get("Channel", it.get("channel", "")))[:40],
                str(it.get("EventID", it.get("event_id", ""))),
                str(it.get("Details", it.get("details", "")))[:100],
            ])
        out.append(InvestigationFinding(
            category="threat_hunt",
            title=f"Hayabusa: {len(items)} {sev_map[bucket].lower()}-severity Sigma rule match(es)",
            severity=sev_map[bucket],
            summary=(f"Hayabusa Sigma rule engine flagged {len(items)} event(s) "
                     f"at {sev_map[bucket]} severity from parsed Windows event logs."),
            detail=("Hayabusa runs the public Sigma ruleset against parsed EVTX files. "
                    "Each detection corresponds to a specific Sigma rule that matched "
                    "an event signature; rule titles often map to MITRE ATT&CK techniques."),
            evidence=[EvidenceSnippet(
                title=f"{sev_map[bucket]} Hayabusa detections",
                source="event_logs/hayabusa",
                headers=headers,
                rows=rows,
                highlight={"rule", "event_id"},
            )],
            iocs=[],
        ))
    return out


def scan_pca_executions(parsed: Path) -> List[InvestigationFinding]:
    out: List[InvestigationFinding] = []
    pca_csv = parsed / "pca_jumplists_wer" / "pca" / "pca_app_launches.csv"
    if not pca_csv.exists():
        return out
    rdr = _safe_open_csv(pca_csv)
    if not rdr:
        return out

    suspicious = []
    for row in rdr:
        path = (row.get("executable_path") or "").lower()
        if not path:
            continue
        normal = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
        if not any(path.startswith(n) for n in normal):
            suspicious.append({
                "path": row.get("executable_path", ""),
                "timestamp": row.get("launch_time_utc", ""),
            })

    if not suspicious:
        return out
    ev_rows = [[s["path"][:120], str(s["timestamp"])[:19]] for s in suspicious[:30]]
    out.append(InvestigationFinding(
        category="execution",
        title=f"{len(suspicious)} program(s) launched from non-standard paths (PCA)",
        severity="HIGH",
        summary=(f"Windows 11 PCA recorded {len(suspicious)} program-launch event(s) "
                 f"from paths outside system / program-files directories."),
        detail=("Windows 11 22H2+ logs every program launched via Explorer in "
                "PcaAppLaunchDic.txt with a UTC timestamp. Programs launched from "
                "user-profile, AppData, Temp, or removable-media paths warrant review. "
                "Even if the executable has been deleted, this artifact preserves "
                "the path and exact timestamp."),
        evidence=[EvidenceSnippet(
            title="Non-standard paths recorded by PCA",
            source="pca_jumplists_wer/pca",
            headers=["executable_path", "launch_time_utc"],
            rows=ev_rows,
            highlight={"executable_path"},
        )],
        iocs=[s["path"] for s in suspicious[:50]],
    ))
    return out


def scan_scheduled_task_xml(parsed: Path) -> List[InvestigationFinding]:
    out: List[InvestigationFinding] = []
    tasks_csv = parsed / "pca_jumplists_wer" / "scheduled_tasks" / "tasks.csv"
    if not tasks_csv.exists():
        return out
    rdr = _safe_open_csv(tasks_csv)
    if not rdr:
        return out

    suspicious = []
    for row in rdr:
        cmd = (row.get("command") or "").lower()
        args = (row.get("arguments") or "").lower()
        tp = (row.get("task_path") or "").lower()
        if not cmd:
            continue
        if tp.startswith("\\microsoft\\") or tp.startswith("\\\\microsoft\\"):
            continue
        triggers = []
        blob = cmd + " " + args
        if "powershell" in cmd and ("-enc" in args or "-e " in args or "iex" in args
                                    or "downloadstring" in args or "frombase64" in args):
            triggers.append("encoded/inline PowerShell")
        if "cmd.exe" in cmd and ("/c " in args or "/k " in args):
            triggers.append("cmd /c invocation")
        if "http://" in blob or "https://" in blob:
            triggers.append("remote URL in args")
        if "%temp%" in cmd or "\\temp\\" in cmd or "\\appdata\\local\\temp" in cmd:
            triggers.append("Temp-folder executable")
        if "wscript" in cmd or "cscript" in cmd:
            triggers.append("scripting host")
        if not any(cmd.startswith(p) for p in
                   ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                    "c:\\program files\\", "c:\\program files (x86)\\",
                    "%systemroot%\\system32\\")):
            triggers.append("non-system path")
        if triggers:
            suspicious.append({
                "task_path": row.get("task_path", ""),
                "command": row.get("command", ""),
                "arguments": (row.get("arguments", "") or "")[:120],
                "user_id": row.get("user_id", ""),
                "trigger_reason": "; ".join(triggers),
            })

    if not suspicious:
        return out
    ev_rows = [[s["task_path"][:80], s["command"][:80], s["arguments"],
                s["user_id"], s["trigger_reason"]]
               for s in suspicious[:30]]
    out.append(InvestigationFinding(
        category="persistence",
        title=f"{len(suspicious)} suspicious scheduled task XML definition(s)",
        severity="HIGH",
        summary=(f"On-disk task XMLs contain {len(suspicious)} task(s) with "
                 f"characteristics typical of attacker-installed persistence."),
        detail=("Scheduled tasks live as XML files under Windows\\System32\\Tasks. "
                "Tasks outside the Microsoft\\ subtree, or invoking PowerShell/cmd "
                "with encoded payloads, remote URLs, or Temp-folder executables, "
                "are common persistence patterns. These XMLs survive even when the "
                "corresponding TaskScheduler EVTX has been wiped."),
        evidence=[EvidenceSnippet(
            title="Suspicious task XML definitions",
            source="pca_jumplists_wer/scheduled_tasks",
            headers=["task_path", "command", "arguments", "user_id", "trigger_reason"],
            rows=ev_rows,
            highlight={"command", "trigger_reason"},
        )],
        iocs=[s["command"] for s in suspicious if s["command"]][:50],
    ))
    return out


def scan_anti_forensic_gaps(parsed: Path) -> List[InvestigationFinding]:
    out: List[InvestigationFinding] = []
    # USN Journal sequence-number gap detection
    usn_csv = parsed / "usn_lnk_mru" / "usn_journal" / "usnjrnl.csv"
    if usn_csv.exists():
        try:
            with open(usn_csv, encoding="utf-8-sig", errors="replace", newline="") as f:
                rdr = csv.DictReader(f)
                usns: List[int] = []
                for row in rdr:
                    u = row.get("UpdateSequenceNumber", row.get("USN", "0"))
                    try:
                        usns.append(int(u))
                    except (ValueError, TypeError):
                        continue
                if len(usns) > 100:
                    usns_sorted = sorted(usns)
                    gaps = []
                    for i in range(1, len(usns_sorted)):
                        d = usns_sorted[i] - usns_sorted[i-1]
                        if d > 100_000_000:
                            gaps.append((usns_sorted[i-1], usns_sorted[i], d))
                    if gaps:
                        ev_rows = [[str(a), str(b), _fmt_bytes(d)] for a, b, d in gaps[:15]]
                        out.append(InvestigationFinding(
                            category="anti_forensic",
                            title=f"USN Journal has {len(gaps)} large sequence-number gap(s)",
                            severity="HIGH",
                            summary=("USN Journal sequence numbers should grow monotonically. "
                                     "Large gaps suggest the journal was truncated or rolled."),
                            detail=("Large gaps can indicate that the journal was deleted "
                                    "(fsutil usn deletejournal) or that significant time "
                                    "elapsed between captures. Cross-reference gap timestamps "
                                    "with PowerShell ScriptBlock logs (Event ID 4104) for "
                                    "'deletejournal' invocations."),
                            evidence=[EvidenceSnippet(
                                title="USN sequence-number gaps (>=100 MB)",
                                source="usn_lnk_mru/usn_journal",
                                headers=["before_usn", "after_usn", "gap"],
                                rows=ev_rows,
                                highlight={"gap"},
                            )],
                            iocs=[],
                        ))
        except Exception as e:
            log.debug("USN gap scan failed: %s", e)

    # Prefetch directory disabled
    pf_dir = parsed / "prefetch_amcache_mft" / "prefetch"
    if pf_dir.exists() and not list(pf_dir.glob("*.csv")):
        out.append(InvestigationFinding(
            category="anti_forensic",
            title="Windows Prefetch appears to have been disabled or wiped",
            severity="HIGH",
            summary=("No parsed prefetch records were produced — Prefetch may have been "
                     "disabled in the registry or the .pf files were deleted."),
            detail=("Prefetch is enabled by default on Windows client OSes. Its absence "
                    "is a strong anti-forensic signal: an attacker can disable Prefetch "
                    "via HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\"
                    "Memory Management\\PrefetchParameters."),
            evidence=[],
            iocs=[],
        ))
    return out
