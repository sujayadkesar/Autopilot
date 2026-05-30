"""
_artifact_scans.py — deterministic scans for artifacts that were parsed but not
previously analysed, plus newly-added parsers.

Each scan reads parsed output and returns InvestigationFinding objects with
evidence snippets. All are no-ops when their source artifact is absent.

Covers: Recycle Bin ($I), Shellbags, WMI persistence, NTFS Alternate Data
Streams (from $MFT), BAM/DAM execution timeline, and Windows Timeline
(ActivitiesCache).
"""

from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("dfir.artifact_scans")

_ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".cab", ".iso")


def _read_csv(path: Path) -> List[Dict[str, str]]:
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            return list(csv.DictReader(f))
    except Exception as e:
        log.warning("read %s: %s", path, e)
        return []


def _get(row: Dict[str, str], *names) -> str:
    for n in names:
        if n in row and row[n]:
            return str(row[n])
    low = {k.lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in low and low[n.lower()]:
            return str(low[n.lower()])
    return ""


# ── Recycle Bin ────────────────────────────────────────────────────────────
def scan_recyclebin(parsed: Path) -> List:
    from .engine import EvidenceSnippet, InvestigationFinding
    csv_path = parsed / "recyclebin" / "recyclebin.csv"
    if not csv_path.exists():
        return []
    rows = _read_csv(csv_path)
    if not rows:
        return []

    archives = [r for r in rows if _get(r, "OriginalPath").lower().endswith(_ARCHIVE_EXT)]
    # mass-deletion: many deletions sharing the same date
    by_day: Dict[str, int] = {}
    for r in rows:
        d = _get(r, "DeletedUTC")[:10]
        if d:
            by_day[d] = by_day.get(d, 0) + 1
    burst_day, burst_n = ("", 0)
    for d, n in by_day.items():
        if n > burst_n:
            burst_day, burst_n = d, n

    headers = ["SID", "OriginalPath", "SizeBytes", "DeletedUTC"]
    ev_rows = [[_get(r, "SID"), _get(r, "OriginalPath"),
                _get(r, "SizeBytes"), _get(r, "DeletedUTC")] for r in rows[:40]]

    severity = "MEDIUM"
    notes = []
    if burst_n >= 25:
        severity = "HIGH"
        notes.append(f"{burst_n} files were deleted on {burst_day} (possible mass deletion / anti-forensics).")
    if archives:
        severity = "HIGH"
        notes.append(f"{len(archives)} archive file(s) were deleted (relevant to staging/exfiltration).")

    return [InvestigationFinding(
        category="anti_forensic",
        title=f"{len(rows)} file(s) recovered from Recycle Bin metadata",
        severity=severity,
        summary="Recycle Bin $I records reveal original paths and deletion times of deleted files.",
        detail=("The $I metadata preserves each deleted file's original full path, size, and "
                "deletion timestamp even after the file content is purged. "
                + " ".join(notes)),
        evidence=[EvidenceSnippet(
            title="Deleted files (Recycle Bin $I)", source="recyclebin/$I",
            headers=headers, rows=ev_rows, highlight={"OriginalPath", "DeletedUTC"})],
        attack=["T1070.004"] if severity == "HIGH" else [],
    )]


# ── Shellbags ────────────────────────────────────────────────────────────────
def scan_shellbags(parsed: Path) -> List:
    from .engine import EvidenceSnippet, InvestigationFinding
    sb_dir = parsed / "shellbags"
    if not sb_dir.exists():
        return []
    rows: List[Dict[str, str]] = []
    for c in sb_dir.rglob("*.csv"):
        rows.extend(_read_csv(c))
    if not rows:
        return []

    flagged = []
    for r in rows:
        path = _get(r, "AbsolutePath", "Value", "ShellType")
        pl = path.lower()
        reason = ""
        if re.match(r"^[d-z]:\\", pl):
            reason = "Removable/secondary drive"
        elif pl.startswith("\\\\"):
            reason = "Network (UNC) share"
        elif ".zip\\" in pl or pl.endswith(".zip") or any(e in pl for e in _ARCHIVE_EXT):
            reason = "Archive browsed in Explorer"
        if reason:
            flagged.append([path[:90],
                            _get(r, "FirstInteracted", "FirstInteractedTimestamp"),
                            _get(r, "LastInteracted", "LastInteractedTimestamp"), reason])

    if not flagged:
        return []
    return [InvestigationFinding(
        category="usb_exfil",
        title=f"{len(flagged)} shellbag(s) reference removable/network/archive locations",
        severity="MEDIUM",
        summary="Shellbags evidence folder browsing on removable drives, network shares, or archives.",
        detail="Shellbags record folders opened in Explorer and survive deletion of the source. "
               "The locations below indicate the user navigated to media or shares of interest.",
        evidence=[EvidenceSnippet(
            title="Notable shellbag locations", source="registry/shellbags",
            headers=["Path", "FirstInteracted", "LastInteracted", "Why flagged"],
            rows=flagged[:40], highlight={"Path", "Why flagged"})],
        attack=["T1074", "T1052.001"],
    )]


# ── WMI persistence ──────────────────────────────────────────────────────────
def scan_wmi_persistence(parsed: Path) -> List:
    from .engine import EvidenceSnippet, InvestigationFinding
    rows = []
    ev_dir = parsed / "event_logs"
    if ev_dir.exists():
        for c in ev_dir.rglob("*.csv"):
            if "wmi" not in c.name.lower() and "remoting" not in str(c.parent).lower():
                # still scan: 5861 can appear in WMI-Activity csv anywhere
                pass
            for r in _read_csv(c):
                eid = _get(r, "EventId", "Event Id")
                if eid == "5861":
                    rows.append([_get(r, "TimeCreated"),
                                 (_get(r, "Payload") or _get(r, "MapDescription"))[:160]])
    if not rows:
        return []
    return [InvestigationFinding(
        category="persistence",
        title=f"{len(rows)} WMI permanent event subscription(s) recorded (EID 5861)",
        severity="HIGH",
        summary="WMI-Activity logged permanent event-consumer bindings — a stealthy persistence mechanism.",
        detail="WMI permanent event subscriptions (filter + consumer + binding) survive reboots and "
               "are a common fileless-persistence technique. Each record below references a "
               "registered consumer; review the consumer command/script.",
        evidence=[EvidenceSnippet(
            title="WMI event subscriptions (EID 5861)", source="eventlog/WMI-Activity",
            headers=["Time", "Detail"], rows=rows[:30], highlight={"Detail"})],
        attack=["T1546.003"],
    )]


# ── NTFS Alternate Data Streams (from $MFT) ──────────────────────────────────
def scan_ads(parsed: Path) -> List:
    from .engine import EvidenceSnippet, InvestigationFinding
    mft_dir = parsed / "prefetch_amcache_mft" / "mft"
    if not mft_dir.exists():
        return []
    flagged = []
    for c in mft_dir.glob("*.csv"):
        for r in _read_csv(c):
            is_ads = _get(r, "IsAds").lower() in ("true", "1", "yes")
            name = _get(r, "FileName", "Name")
            if not is_ads and ":" not in name:
                continue
            # extract stream name
            stream = name.split(":", 1)[1] if ":" in name else name
            if stream.lower().startswith("zone.identifier") or not stream:
                continue  # benign download mark-of-the-web
            flagged.append([_get(r, "ParentPath", "Path"), name,
                            _get(r, "FileSize", "Size")])
            if len(flagged) >= 60:
                break
    if not flagged:
        return []
    return [InvestigationFinding(
        category="anti_forensic",
        title=f"{len(flagged)} non-benign NTFS Alternate Data Stream(s) found",
        severity="HIGH",
        summary="Alternate Data Streams (other than Zone.Identifier) can hide executable payloads.",
        detail="ADS allow data to be attached to a file invisibly to normal directory listings. "
               "Zone.Identifier (mark-of-the-web) is excluded; the streams below warrant inspection.",
        evidence=[EvidenceSnippet(
            title="Suspicious Alternate Data Streams", source="mft/ADS",
            headers=["ParentPath", "Stream", "Size"], rows=flagged[:40],
            highlight={"Stream"})],
        attack=["T1564.004"],
    )]


# ── BAM / DAM execution timeline ─────────────────────────────────────────────
def scan_bam(parsed: Path) -> List:
    from .engine import EvidenceSnippet, InvestigationFinding
    aj = parsed / "registry" / "artifacts.json"
    if not aj.exists():
        return []
    try:
        data = json.loads(aj.read_text(encoding="utf-8", errors="replace")).get("artifacts", {})
    except Exception:
        return []
    bam_key = next((k for k in data if "bam" in k.lower() or "dam" in k.lower()), None)
    if not bam_key:
        return []
    payload = data[bam_key]
    if isinstance(payload, dict) and "data" in payload:
        payload = payload["data"]
    entries = payload if isinstance(payload, list) else []
    if not entries:
        return []
    rows = []
    for e in entries[:40]:
        if isinstance(e, dict):
            rows.append([str(e.get("path") or e.get("Path") or e.get("program", ""))[:90],
                         str(e.get("last_execution") or e.get("LastExecution")
                             or e.get("timestamp", ""))])
    if not rows:
        return []
    return [InvestigationFinding(
        category="hacktools",
        title=f"BAM/DAM recorded {len(entries)} program execution(s)",
        severity="INFO",
        summary="Background Activity Moderator preserves per-user last-execution times for programs.",
        detail="BAM/DAM (SYSTEM hive) records the last time each program ran per user — a reliable "
               "execution-evidence source that complements Prefetch and Amcache.",
        evidence=[EvidenceSnippet(
            title="BAM/DAM execution times", source="registry/bam",
            headers=["Program", "LastExecution"], rows=rows, highlight={"Program"})],
        attack=["T1059"],
    )]


# ── Windows Timeline (ActivitiesCache.db) ────────────────────────────────────
def scan_timeline(parsed: Path) -> List:
    from .engine import EvidenceSnippet, InvestigationFinding
    tl_dir = parsed / "timeline"
    if not tl_dir.exists():
        return []
    rows = []
    for c in tl_dir.rglob("*.csv"):
        for r in _read_csv(c):
            exe = _get(r, "Executable", "AppId", "Application")
            disp = _get(r, "DisplayText", "ContentInfo", "Payload")
            start = _get(r, "StartTime", "LastModifiedTime", "Start")
            if exe or disp:
                rows.append([start, exe[:50], disp[:90]])
    if not rows:
        return []
    return [InvestigationFinding(
        category="user_keywords",
        title=f"Windows Timeline recorded {len(rows)} application/file activity entries",
        severity="INFO",
        summary="ActivitiesCache.db (Windows Timeline) records apps used and files opened with timestamps.",
        detail="Windows Timeline correlates application usage and document access into a per-user "
               "activity feed — useful for establishing what the user was doing and when.",
        evidence=[EvidenceSnippet(
            title="Windows Timeline activities", source="timeline/ActivitiesCache",
            headers=["Start", "Executable", "Activity"], rows=rows[:40],
            highlight={"Activity"})],
    )]


def run_all(parsed: Path) -> List:
    """Run every artifact scan and return combined findings."""
    out: List = []
    for fn in (scan_recyclebin, scan_shellbags, scan_wmi_persistence,
               scan_ads, scan_bam, scan_timeline):
        try:
            out.extend(fn(parsed))
        except Exception as e:
            log.warning("%s failed: %s", fn.__name__, e)
    return out
