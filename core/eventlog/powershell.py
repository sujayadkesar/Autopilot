"""
powershell.py — reconstruct and triage PowerShell activity from 4103/4104 events.

EID 4104 (script-block logging) emits the executed source. Large scripts are split
across multiple records sharing a ScriptBlockId, with MessageNumber/MessageTotal
indicating ordering — we reassemble those into the full script, then apply
deobfuscation heuristics (encoded commands, AMSI bypass, download cradles,
character-level obfuscation) to flag malicious tradecraft.
"""

from __future__ import annotations

import base64
import logging
import re
from collections import defaultdict
from typing import Dict, List, Tuple

log = logging.getLogger("dfir.eventlog.powershell")

_OBFUSCATION_PATTERNS = [
    (r"-enc(odedcommand)?\b", "Encoded command (-EncodedCommand)", "T1027"),
    (r"frombase64string", "Base64 payload decoding", "T1140"),
    (r"amsiutils|amsiinitfailed|amsicontext", "AMSI bypass attempt", "T1562.001"),
    (r"\[ref\]\.assembly\.gettype", "Reflection-based AMSI/ETW patch", "T1562.001"),
    (r"(iex|invoke-expression)\b", "Invoke-Expression (in-memory execution)", "T1059.001"),
    (r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|start-bitstransfer",
     "Download cradle (remote payload retrieval)", "T1105"),
    (r"-w(indowstyle)?\s+hidden|-windowstyle\s+h", "Hidden window", "T1564.003"),
    (r"-ep\s+bypass|-executionpolicy\s+bypass", "Execution-policy bypass", "T1059.001"),
    (r"\[char\](\[|\d)|\-join|\bchar\b\s*\]", "Character-level obfuscation", "T1027"),
    (r"securestring|convertto-securestring", "Credential handling", "T1003"),
    (r"reflection\.assembly|loadwithpartialname|\[system\.reflection", "Assembly loading", "T1620"),
    (r"mimikatz|invoke-mimikatz|sekurlsa|lsadump", "Mimikatz / credential dumping", "T1003.001"),
]


def _decode_encoded_commands(text: str) -> List[str]:
    """Find -EncodedCommand base64 blobs and decode them (UTF-16LE)."""
    out: List[str] = []
    for m in re.finditer(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", text, re.IGNORECASE):
        blob = m.group(1)
        try:
            pad = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(pad)
            decoded = raw.decode("utf-16-le", errors="replace")
            if decoded.strip():
                out.append(decoded.strip())
        except Exception:
            continue
    return out


def reassemble_scriptblocks(ps_events: List[Dict]) -> Dict[str, str]:
    """Group 4104 events by ScriptBlockId and concatenate fragments in order."""
    fragments: Dict[str, Dict[int, str]] = defaultdict(dict)
    order: List[str] = []
    for ev in ps_events:
        pl = ev.get("payload", {}) or {}
        if ev.get("eid") != 4104:
            continue
        sbid = str(pl.get("ScriptBlockId") or pl.get("ScriptBlockID") or
                   ev.get("time") or len(order))
        text = pl.get("ScriptBlockText") or pl.get("ScriptBlock") or ""
        try:
            num = int(pl.get("MessageNumber") or 1)
        except (ValueError, TypeError):
            num = 1
        if sbid not in fragments:
            order.append(sbid)
        fragments[sbid][num] = text
    scripts: Dict[str, str] = {}
    for sbid in order:
        parts = fragments[sbid]
        scripts[sbid] = "".join(parts[k] for k in sorted(parts))
    return scripts


def analyze_powershell(events: List[Dict]):
    """Return InvestigationFinding objects for suspicious PowerShell activity."""
    from ..investigation.engine import EvidenceSnippet, InvestigationFinding

    ps_events = [e for e in events if e.get("eid") in (4103, 4104)]
    if not ps_events:
        return []

    scripts = reassemble_scriptblocks(ps_events)
    findings = []
    rows = []
    flagged_attack = set()
    flagged_techniques: List[Tuple[str, str]] = []
    decoded_samples: List[str] = []

    for sbid, script in scripts.items():
        low = script.lower()
        hits = []
        for pat, label, tid in _OBFUSCATION_PATTERNS:
            if re.search(pat, low):
                hits.append(label)
                flagged_attack.add(tid)
                flagged_techniques.append((label, tid))
        if hits:
            decoded = _decode_encoded_commands(script)
            decoded_samples.extend(decoded[:2])
            preview = (script[:160] + "…") if len(script) > 160 else script
            rows.append([sbid[:18], "; ".join(sorted(set(hits)))[:80],
                         preview.replace("\n", " ")])

    if not rows:
        return []

    evidence = [EvidenceSnippet(
        title="Suspicious PowerShell script blocks (EID 4104)",
        source="powershell/4104",
        headers=["ScriptBlockId", "Indicators", "Script preview"],
        rows=rows[:25],
        highlight={"Indicators"},
    )]
    if decoded_samples:
        evidence.append(EvidenceSnippet(
            title="Decoded -EncodedCommand payloads",
            source="powershell/decoded",
            headers=["Decoded command"],
            rows=[[s[:240]] for s in decoded_samples[:10]],
            highlight={"Decoded command"},
        ))

    uniq_labels = sorted({lbl for lbl, _ in flagged_techniques})
    findings.append(InvestigationFinding(
        category="powershell_abuse",
        title=f"Suspicious PowerShell activity in {len(rows)} script block(s)",
        severity="HIGH" if not any("Mimikatz" in l for l in uniq_labels) else "CRITICAL",
        summary=("PowerShell script-block logging recorded execution exhibiting "
                 "offensive tradecraft."),
        detail=("Reassembled PowerShell script blocks (EID 4104) contain the following "
                "indicators: " + ", ".join(uniq_labels) + ". "
                + (f"{len(decoded_samples)} encoded command(s) were decoded and are shown "
                   "as a separate exhibit." if decoded_samples else "")),
        evidence=evidence,
        attack=sorted(flagged_attack),
    ))
    return findings
