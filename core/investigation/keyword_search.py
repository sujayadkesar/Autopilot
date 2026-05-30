"""
User-keyword search engine.

Scans every parsed CSV/JSON for the user's case-specific keywords (sensitive
filenames, malware names, C2 domains, etc.) and produces evidence-cited findings.

Design:
  * Case-insensitive substring match — simple and robust
  * For each keyword, group hits by source artefact and produce one finding
  * Each hit becomes an EvidenceSnippet row with the matching artefact data
"""

from __future__ import annotations

import csv
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .engine import EvidenceSnippet, InvestigationFinding

log = logging.getLogger("dfir.kwsearch")


@dataclass
class KeywordHit:
    keyword: str
    source: str           # e.g. "registry/usbstor.csv" or "browsers/chrome/Default/urls.csv"
    artefact_label: str   # human-readable category e.g. "Browser URLs"
    matched_field: str
    row_data: Dict[str, str]


# Mapping of (parsed-dir relative path glob) → (artefact label, severity bump)
ARTEFACT_LABELS: List[Tuple[str, str, str]] = [
    # (glob pattern relative to parsed/, label, severity)
    ("usn_lnk_mru/browsers/*/*/urls.csv",          "Browser URL history",       "HIGH"),
    ("usn_lnk_mru/browsers/*/*/visits.csv",        "Browser visit log",         "HIGH"),
    ("usn_lnk_mru/browsers/*/*/downloads.csv",     "Browser downloads",         "CRITICAL"),
    ("usn_lnk_mru/browsers/*/*/searches.csv",      "Browser search terms",      "MEDIUM"),
    ("usn_lnk_mru/browsers/*/*/cookies.csv",       "Browser cookies",           "LOW"),
    ("usn_lnk_mru/browsers/*/*/logins.csv",        "Browser saved logins",      "MEDIUM"),
    ("usn_lnk_mru/lnk/*.csv",                      "Recent shortcuts (LNK)",    "HIGH"),
    ("usn_lnk_mru/mru/*.csv",                      "MRU registry hives",        "HIGH"),
    ("usn_lnk_mru/usn_journal/*.csv",              "USN Journal",               "HIGH"),
    ("prefetch_amcache_mft/prefetch/*.csv",        "Prefetch (executions)",     "HIGH"),
    ("prefetch_amcache_mft/amcache/*.csv",         "Amcache (binary inventory)","HIGH"),
    ("prefetch_amcache_mft/mft/*.csv",             "$MFT (filesystem records)", "MEDIUM"),
    ("prefetch_amcache_mft/srum/*.csv",            "SRUM (resource usage)",     "MEDIUM"),
    ("event_logs/*/*.csv",                         "Windows event log",         "MEDIUM"),
    ("registry/*.csv",                             "Registry artefact",         "HIGH"),
]

# Fields we never display (noisy or sensitive)
SUPPRESS_FIELDS = {"_source_file", "Hidden", "EventRecordId", "Chunk", "Offset",
                   "Keywords", "ProviderId", "OpcodeName", "TaskName"}


def _iter_artefact_files(parsed_dir: Path) -> Iterable[Tuple[Path, str, str]]:
    """Yield (csv_path, label, severity) for every parsed artefact CSV."""
    for pattern, label, sev in ARTEFACT_LABELS:
        for p in parsed_dir.glob(pattern):
            if p.is_file() and p.suffix.lower() == ".csv":
                yield p, label, sev


def _normalize_keywords(raw: str) -> List[str]:
    """Split a multiline string into individual keywords; trim, dedupe, lower."""
    if not raw:
        return []
    seen: Set[str] = set()
    out: List[str] = []
    for line in raw.splitlines():
        kw = line.strip().lower()
        if not kw or kw.startswith("#"):
            continue
        if kw in seen:
            continue
        seen.add(kw)
        out.append(kw)
    return out


def search_keywords(parsed_dir: Path, keywords: List[str],
                    label: str = "User keywords",
                    severity: str = "HIGH",
                    max_hits_per_keyword: int = 200) -> List[KeywordHit]:
    """Search every parsed CSV for any of the given (lowercase) keywords."""
    if not keywords:
        return []
    hits: List[KeywordHit] = []
    per_kw_count: Dict[str, int] = {kw: 0 for kw in keywords}

    for csv_path, art_label, _sev in _iter_artefact_files(parsed_dir):
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace", newline="") as f:
                rdr = csv.DictReader(f)
                rel = str(csv_path.relative_to(parsed_dir))
                for row in rdr:
                    # Build searchable blob from all fields' values
                    blob_parts = [str(v) for v in row.values() if v]
                    blob = " | ".join(blob_parts).lower()
                    if not blob.strip():
                        continue
                    for kw in keywords:
                        if per_kw_count[kw] >= max_hits_per_keyword:
                            continue
                        if kw in blob:
                            # Find which field matched
                            matched_field = ""
                            for k, v in row.items():
                                if v and kw in str(v).lower():
                                    matched_field = k
                                    break
                            hits.append(KeywordHit(
                                keyword=kw,
                                source=rel,
                                artefact_label=art_label,
                                matched_field=matched_field,
                                row_data=dict(row),
                            ))
                            per_kw_count[kw] += 1
                            break  # one hit per row is enough
        except Exception as e:
            log.warning("Keyword scan failed on %s: %s", csv_path, e)
            continue

    return hits


def hits_to_findings(hits: List[KeywordHit], category: str = "user_keywords",
                     severity_default: str = "HIGH") -> List[InvestigationFinding]:
    """Bucket hits by keyword and emit one InvestigationFinding per keyword."""
    if not hits:
        return []
    by_kw: Dict[str, List[KeywordHit]] = {}
    for h in hits:
        by_kw.setdefault(h.keyword, []).append(h)

    findings: List[InvestigationFinding] = []
    for kw, kw_hits in by_kw.items():
        # Group by source artefact for tidy evidence cards
        by_source: Dict[str, List[KeywordHit]] = {}
        for h in kw_hits:
            by_source.setdefault(h.artefact_label, []).append(h)

        evidence = []
        for art_label, ah in by_source.items():
            # Pick a stable column ordering — common columns first
            cols_priority = ["timestamp", "url", "target", "path", "FullPath",
                             "ExecutableName", "Name", "FileName", "Channel",
                             "EventId", "TimeCreated", "user", "matched_field"]
            seen_cols: List[str] = []
            for h in ah[:30]:
                for k in h.row_data.keys():
                    if k in SUPPRESS_FIELDS:
                        continue
                    if k not in seen_cols:
                        seen_cols.append(k)
            ordered = [c for c in cols_priority if c in seen_cols] + \
                      [c for c in seen_cols if c not in cols_priority]
            ordered = ordered[:6]  # cap to keep evidence cards readable

            rows = []
            for h in ah[:25]:
                row = []
                for col in ordered:
                    val = str(h.row_data.get(col, ""))
                    if len(val) > 80:
                        val = val[:79] + "…"
                    row.append(val)
                rows.append(row)

            evidence.append(EvidenceSnippet(
                title=f"'{kw}' hits in {art_label} ({len(ah)} match{'es' if len(ah)!=1 else ''})",
                source=ah[0].source.split("/")[0] if ah else art_label,
                headers=ordered,
                rows=rows,
                highlight={ah[0].matched_field} if ah[0].matched_field else set(),
            ))

        sev = severity_default
        # Bump severity if there are many hits or hits in critical artefacts
        crit_arts = {"Browser downloads", "Recent shortcuts (LNK)", "USN Journal",
                     "Prefetch (executions)", "Amcache (binary inventory)"}
        if any(h.artefact_label in crit_arts for h in kw_hits) and len(kw_hits) > 5:
            sev = "CRITICAL"

        findings.append(InvestigationFinding(
            category=category,
            title=f"Keyword '{kw}' matched in {len(kw_hits)} artefact row(s)",
            severity=sev,
            summary=(
                f"User-supplied keyword '{kw}' was found in {len(kw_hits)} row(s) across "
                f"{len(by_source)} artefact category(ies)."
            ),
            detail=(
                f"This finding shows every row in the parsed artefacts where the user-supplied "
                f"keyword appears verbatim (case-insensitive). Each exhibit groups hits by the "
                f"source artefact category. Use the supporting evidence to reconstruct when, "
                f"where, and how the keyword was referenced on this host."
            ),
            evidence=evidence,
            iocs=[kw],
        ))

    return findings
