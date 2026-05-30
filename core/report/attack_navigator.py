"""
attack_navigator.py — MITRE ATT&CK Navigator layer + consolidated IOC roll-up.

Builds:
  * a Navigator layer JSON (importable at mitre-attack.github.io/attack-navigator)
    from the ATT&CK technique IDs tagged on findings, scored by hit frequency.
  * a typed, de-duplicated IOC roll-up (ip / domain / url / hash / path / account)
    aggregated from finding IOC lists, written to JSON and surfaced in the report.
"""

from __future__ import annotations

import json
import re
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Dict, List


def collect_techniques(findings) -> Counter:
    """Count ATT&CK technique IDs across findings exposing `.attack`."""
    c: Counter = Counter()
    for f in findings:
        for tid in (getattr(f, "attack", None) or []):
            c[str(tid).upper()] += 1
    return c


def build_navigator_layer(findings, case_reference: str, out_path: Path) -> Path:
    techniques = collect_techniques(findings)
    max_hits = max(techniques.values(), default=1)
    layer = {
        "name": f"DFIR — {case_reference}",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques observed by the DFIR automation deterministic engine.",
        "techniques": [
            {
                "techniqueID": tid,
                "score": round(100 * hits / max_hits),
                "color": "",
                "comment": f"{hits} finding(s)",
                "enabled": True,
            }
            for tid, hits in techniques.items()
        ],
        "gradient": {
            "colors": ["#ffe6e6", "#ff6666", "#990000"],
            "minValue": 0, "maxValue": 100,
        },
        "legendItems": [], "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd", "selectTechniquesAcrossTactics": True,
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return out_path


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)


def _classify_ioc(value: str) -> str:
    v = value.strip()
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if "\\" in v or v.lower().startswith(("c:", "d:")) or "/" in v and "." not in v.split("/")[-1]:
        return "path"
    if _IP_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "other"


def build_ioc_rollup(findings, out_path: Path) -> Dict[str, List[str]]:
    """Aggregate + type IOCs from finding `.iocs` (list[str]) and `.ioc` (str)."""
    buckets: "OrderedDict[str, OrderedDict]" = OrderedDict(
        (t, OrderedDict()) for t in ("ip", "domain", "url", "hash", "path", "account", "other"))
    for f in findings:
        raw_iocs: List[str] = []
        raw_iocs.extend(getattr(f, "iocs", None) or [])
        single = getattr(f, "ioc", None)
        if single:
            raw_iocs.append(single)
        for item in raw_iocs:
            item = str(item).strip()
            if not item:
                continue
            # honour explicit "TYPE:value" prefixes from extractors
            m = re.match(r"^(ip|domain|url|hash|sha1|sha256|md5|account|yara)\s*:\s*(.+)$",
                         item, re.IGNORECASE)
            if m:
                typ = m.group(1).lower()
                val = m.group(2).strip()
                typ = {"sha1": "hash", "sha256": "hash", "md5": "hash",
                       "yara": "other"}.get(typ, typ)
            else:
                val, typ = item, _classify_ioc(item)
            buckets.setdefault(typ, OrderedDict())[val] = None

    rollup = {t: list(vals.keys()) for t, vals in buckets.items() if vals}
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(rollup, indent=2), encoding="utf-8")
    return rollup
