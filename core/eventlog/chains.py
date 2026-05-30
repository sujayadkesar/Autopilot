"""
chains.py — suspicious process-ancestry detection from 4688 / Sysmon 1.

Rather than building a full process tree (which needs PID correlation that is
often incomplete in exported logs), this flags high-signal parent→child
relationships and command-line tradecraft that are reliable on their own.
"""

from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Dict, List

_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
           "msaccess.exe", "mspub.exe", "visio.exe"}
_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
           "mshta.exe", "regsvr32.exe", "rundll32.exe"}
_SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "hh.exe"}
_LOLBINS_DOWNLOAD = {"certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"}
_DISCOVERY = {"whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe",
              "systeminfo.exe", "quser.exe", "tasklist.exe", "arp.exe", "route.exe"}


def _base(path: str) -> str:
    if not path:
        return ""
    try:
        return PureWindowsPath(path.strip().strip('"')).name.lower()
    except Exception:
        return path.strip().lower().rsplit("\\", 1)[-1]


def _classify(parent: str, child: str, cmd: str):
    """Return (label, attack_id) if the lineage is suspicious, else (None, None)."""
    cl = (cmd or "").lower()
    if parent in _OFFICE and child in _SHELLS:
        return "Office application spawned a shell/script interpreter", "T1566.001"
    if parent in _SCRIPT_HOSTS and child in {"powershell.exe", "pwsh.exe", "cmd.exe"}:
        return "Script host spawned a command shell", "T1059"
    if child in {"powershell.exe", "pwsh.exe"} and re.search(
            r"-enc|encodedcommand|-w\s+hidden|-windowstyle\s+h|bypass|frombase64string|downloadstring", cl):
        return "PowerShell launched with obfuscated/hidden flags", "T1059.001"
    if parent in {"powershell.exe", "pwsh.exe", "cmd.exe"} and child in _LOLBINS_DOWNLOAD:
        return "Shell spawned a download LOLBin", "T1105"
    if "comsvcs.dll" in cl and ("minidump" in cl or "lsass" in cl):
        return "LSASS credential dump via comsvcs MiniDump", "T1003.001"
    if parent in _OFFICE and child in _DISCOVERY:
        return "Discovery command spawned by Office application", "T1059"
    return None, None


def analyze_chains(events: List[Dict]):
    from ..investigation.engine import EvidenceSnippet, InvestigationFinding

    rows = []
    attack = set()
    has_critical = False
    for ev in events:
        eid = ev.get("eid")
        channel = (ev.get("channel") or "").lower()
        pl = ev.get("payload", {}) or {}
        if eid == 4688:
            parent = _base(pl.get("ParentProcessName", ""))
            child = _base(pl.get("NewProcessName", ""))
            cmd = pl.get("CommandLine", "") or pl.get("ProcessCommandLine", "")
        elif eid == 1 and "sysmon" in channel:
            parent = _base(pl.get("ParentImage", ""))
            child = _base(pl.get("Image", ""))
            cmd = pl.get("CommandLine", "")
        else:
            continue
        if not child:
            continue
        label, tid = _classify(parent, child, cmd)
        if label:
            if tid:
                attack.add(tid)
            if "LSASS" in label:
                has_critical = True
            rows.append([ev.get("time", "")[:19], parent or "?", child,
                         (cmd or "")[:90], label])

    if not rows:
        return []

    return [InvestigationFinding(
        category="process_chain",
        title=f"{len(rows)} suspicious process-execution chain(s) detected",
        severity="CRITICAL" if has_critical else "HIGH",
        summary="Process-creation events show parent→child relationships consistent with "
                "malicious execution.",
        detail="Each row pairs a parent process with the child it launched and the reason "
               "the lineage is notable (e.g. Office spawning PowerShell, script hosts "
               "launching shells, LSASS access). Validate against the command line shown.",
        evidence=[EvidenceSnippet(
            title="Suspicious parent → child process chains",
            source="eventlog/process-create",
            headers=["Time", "Parent", "Child", "Command line", "Why flagged"],
            rows=rows[:30],
            highlight={"Why flagged", "Child"},
        )],
        attack=sorted(attack),
    )]
