"""
Comprehensive Evidence Report.

A single self-contained HTML file containing every parsed artefact CSV/JSONL as a
searchable HTML table. Designed for analysts who want to do their own keyword
search (Ctrl+F in browser, or PDF text-search after print-to-PDF).

Design priorities:
  * Self-contained — no external CSS/JS, all inline
  * Searchable — Ctrl+F-friendly: every cell is plain text, no tooltips/JS-only
  * Browsable — TOC sidebar with sections per category and per artefact
  * Performant — caps at N rows per table by default (configurable) so the file
    stays under a few MB even on heavy cases
"""

from __future__ import annotations

import csv
import html as _html
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from ..case_context import CaseContext
from ..text.mojibake import fix_mojibake


# Map a parsed-dir relative path glob → (category, label, sort priority)
ARTEFACT_GROUPS: List[Tuple[str, str, str, int]] = [
    # (glob,                                   category,            label,                          priority)
    ("registry/*.jsonl",                       "Registry",          "Registry full-hive JSONL",     1),
    ("registry/*.csv",                         "Registry",          "Registry artefact CSV",        2),
    ("usn_lnk_mru/usn_journal/*.csv",          "Filesystem",        "USN Journal",                  10),
    ("prefetch_amcache_mft/mft/*.csv",         "Filesystem",        "$MFT",                         11),
    ("prefetch_amcache_mft/prefetch/*.csv",    "Execution",         "Prefetch",                     20),
    ("prefetch_amcache_mft/amcache/*.csv",     "Execution",         "Amcache",                      21),
    ("prefetch_amcache_mft/srum/*.csv",        "Execution",         "SRUM (resource usage)",        22),
    ("usn_lnk_mru/lnk/*.csv",                  "User Activity",     "LNK shortcuts (Recent)",       30),
    ("usn_lnk_mru/mru/*.csv",                  "User Activity",     "MRU registry hives",           31),
    ("usn_lnk_mru/browsers/*/*/urls.csv",      "Browser",           "Browser URL history",          40),
    ("usn_lnk_mru/browsers/*/*/visits.csv",    "Browser",           "Browser visits",               41),
    ("usn_lnk_mru/browsers/*/*/downloads.csv", "Browser",           "Browser downloads",            42),
    ("usn_lnk_mru/browsers/*/*/searches.csv",  "Browser",           "Browser search terms",         43),
    ("usn_lnk_mru/browsers/*/*/cookies.csv",   "Browser",           "Browser cookies",              44),
    ("usn_lnk_mru/browsers/*/*/logins.csv",    "Browser",           "Browser saved logins",         45),
    ("event_logs/*/*.csv",                     "Event Logs",        "Windows event log",            50),
]


def _read_csv_rows(path: Path, max_rows: int) -> Tuple[List[str], List[List[str]], int]:
    """Read up to max_rows from a CSV. Return (headers, rows, total_count)."""
    headers: List[str] = []
    rows: List[List[str]] = []
    total = 0
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            rdr = csv.reader(f)
            try:
                headers = next(rdr)
            except StopIteration:
                return [], [], 0
            for row in rdr:
                total += 1
                if len(rows) < max_rows:
                    # Cap each cell to keep the page light
                    cleaned = [(c if len(c) <= 200 else c[:199] + "…") for c in row]
                    rows.append(cleaned)
    except Exception:
        pass
    return headers, rows, total


def _read_jsonl_rows(path: Path, max_rows: int) -> Tuple[List[str], List[List[str]], int]:
    """Read up to max_rows from a JSONL — flatten each line to top-level keys."""
    import json
    headers: List[str] = []
    rows: List[List[str]] = []
    total = 0
    seen_headers: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                total += 1
                if len(rows) >= max_rows:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                for k in obj.keys():
                    if k not in seen_headers and len(seen_headers) < 8:
                        seen_headers.append(k)
                row = []
                for h in seen_headers:
                    v = obj.get(h, "")
                    if not isinstance(v, str):
                        v = str(v)
                    if len(v) > 200:
                        v = v[:199] + "…"
                    row.append(v)
                rows.append(row)
    except Exception:
        pass
    headers = seen_headers
    return headers, rows, total


def _safe(text: str) -> str:
    return _html.escape(text or "", quote=True)


def build_comprehensive_report(ctx: CaseContext, max_rows_per_table: int = 500) -> Path:
    """Build a single HTML containing every parsed artefact as a searchable table."""
    parsed_dir = ctx.parsed_dir

    # Discover and group artefact files
    by_category: Dict[str, List[Tuple[Path, str, int]]] = {}
    for glob, category, label, priority in ARTEFACT_GROUPS:
        for p in sorted(parsed_dir.glob(glob)):
            if not p.is_file():
                continue
            by_category.setdefault(category, []).append((p, label, priority))

    # Sort each category by priority then filename
    for cat in by_category:
        by_category[cat].sort(key=lambda t: (t[2], t[0].name))

    # ── Build the HTML body ─────────────────────────────────────────────────
    parts: List[str] = []

    parts.append("""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Comprehensive Evidence Report — """)
    parts.append(_safe(ctx.customer_name))
    parts.append("""</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,sans-serif;
       background:#f6f6f4;color:#1a1a1a;margin:0;padding:0;font-size:13px}
  header{background:#1f4e79;color:white;padding:24px 32px;
         border-bottom:4px solid #163d62}
  header h1{margin:0;font-size:22pt;font-weight:600}
  header .subtitle{font-size:11pt;opacity:0.85;margin-top:4px}
  header .meta{font-size:10pt;opacity:0.75;margin-top:12px}
  main{display:flex;min-height:calc(100vh - 120px)}
  nav{width:280px;background:#1c1c1c;color:#ccc;
      padding:16px 0;position:sticky;top:0;align-self:flex-start;
      max-height:100vh;overflow-y:auto;font-size:11pt}
  nav .nav-title{padding:0 16px 8px;font-size:9pt;letter-spacing:2px;
                 text-transform:uppercase;color:#666;font-weight:700}
  nav details{margin:0}
  nav summary{padding:8px 16px;cursor:pointer;color:#58a6ff;
              font-weight:600;font-size:10pt;letter-spacing:1px;
              text-transform:uppercase}
  nav summary:hover{background:#2a2a2a}
  nav a{display:block;padding:5px 16px 5px 28px;color:#aaa;
        text-decoration:none;font-size:10pt;border-left:2px solid transparent}
  nav a:hover{background:#2a2a2a;color:white;border-left-color:#58a6ff}
  nav .count{color:#666;font-size:9pt;margin-left:6px}
  article{flex:1;padding:24px 32px;background:white;overflow-x:auto}
  h2{color:#1f4e79;border-bottom:2px solid #1f4e79;
     padding-bottom:6px;margin:32px 0 12px;font-size:18pt}
  h3{color:#163d62;margin:24px 0 8px;font-size:14pt;font-weight:600}
  .artefact{background:#fafaf8;border:1px solid #d8d8d4;
            border-radius:4px;padding:14px 18px;margin:12px 0;
            page-break-inside:avoid}
  .artefact-meta{font-size:10pt;color:#666;margin-bottom:8px;
                 display:flex;justify-content:space-between}
  .artefact-meta code{background:#eee;padding:1px 6px;
                      border-radius:3px;font-size:9pt}
  .artefact-meta .count{font-weight:700;color:#1f4e79}
  table{border-collapse:collapse;width:100%;font-family:Consolas,monospace;
        font-size:9pt;margin-top:6px;background:white}
  th{background:#e8e4d8;color:#1a1a1a;text-align:left;
     padding:5px 8px;border-bottom:2px solid #1f4e79;
     font-weight:700;text-transform:uppercase;font-size:8pt;
     letter-spacing:1px;position:sticky;top:0;z-index:1}
  td{padding:4px 8px;border-bottom:1px solid #eee;
     vertical-align:top;word-break:break-all}
  tr:hover td{background:#fffbe8}
  tr:nth-child(even) td{background:#f9f7f0}
  tr:nth-child(even):hover td{background:#fffbe8}
  .truncated{font-style:italic;color:#888;font-size:9pt;
             padding:6px;text-align:center;background:#f0e8d8}
  .empty{font-style:italic;color:#aaa;padding:8px}
  details[open] summary{color:#79c0ff}
  .search-hint{background:#fffae6;border:1px solid #f0c98e;
               border-radius:4px;padding:12px 16px;margin:16px 0;
               font-size:11pt}
  .search-hint code{background:#fff;padding:2px 6px;border-radius:3px;
                    border:1px solid #d0d0d0;font-size:10pt}
  footer{background:#1c1c1c;color:#888;padding:16px 32px;
         text-align:center;font-size:9pt}
  @media print{
    nav{display:none}
    main{display:block}
    article{padding:8px}
    table{font-size:8pt}
  }
</style></head><body>
<header>
  <h1>Comprehensive Evidence Report</h1>
  <div class="subtitle">Every parsed artefact in one searchable document</div>
  <div class="meta">""")
    parts.append(f"<strong>{_safe(ctx.customer_name)}</strong> · "
                 f"Case {_safe(ctx.case_reference)} · "
                 f"Investigation {ctx.investigation_date.isoformat()} · "
                 f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    parts.append("</div></header><main>")

    # ── Sidebar nav ─────────────────────────────────────────────────────────
    parts.append('<nav><div class="nav-title">Sections</div>')
    for cat, files in sorted(by_category.items()):
        cat_id = cat.lower().replace(" ", "-")
        parts.append(f'<details open><summary>{_safe(cat)} '
                     f'<span class="count">({len(files)})</span></summary>')
        for path, label, _pri in files:
            anchor = f"art-{abs(hash(str(path))) & 0xFFFFFFFF:x}"
            parts.append(f'<a href="#{anchor}">{_safe(path.name)}</a>')
        parts.append("</details>")
    parts.append("</nav>")

    # ── Main article ────────────────────────────────────────────────────────
    parts.append("<article>")
    parts.append('<div class="search-hint">'
                 '<strong>Tip:</strong> Use <code>Ctrl+F</code> (or <code>Cmd+F</code>) '
                 'in your browser to search across <em>every</em> artefact in this report. '
                 'Print-to-PDF preserves searchability.'
                 '</div>')

    if not by_category:
        parts.append('<div class="empty">No parsed artefacts found in '
                     f'<code>{_safe(str(parsed_dir))}</code>. Run extract + parse first.</div>')

    for cat, files in sorted(by_category.items()):
        cat_id = cat.lower().replace(" ", "-")
        parts.append(f'<h2 id="cat-{cat_id}">{_safe(cat)}</h2>')
        for path, label, _pri in files:
            anchor = f"art-{abs(hash(str(path))) & 0xFFFFFFFF:x}"
            try:
                rel = path.relative_to(parsed_dir)
            except ValueError:
                rel = path
            size = path.stat().st_size if path.exists() else 0
            size_kb = size / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"

            if path.suffix.lower() == ".jsonl":
                headers, rows, total = _read_jsonl_rows(path, max_rows_per_table)
            else:
                headers, rows, total = _read_csv_rows(path, max_rows_per_table)

            parts.append(f'<div class="artefact" id="{anchor}">')
            parts.append(f'<h3>{_safe(label)}: {_safe(path.name)}</h3>')
            parts.append(f'<div class="artefact-meta"><span><code>{_safe(str(rel))}</code> · {size_str}</span>'
                         f'<span class="count">{total:,} row(s)'
                         f'{" — showing first " + format(max_rows_per_table, ",") if total > max_rows_per_table else ""}'
                         f'</span></div>')
            if not headers:
                parts.append('<div class="empty">(empty or unreadable)</div>')
            else:
                parts.append("<table><thead><tr>")
                for h in headers:
                    parts.append(f"<th>{_safe(h)}</th>")
                parts.append("</tr></thead><tbody>")
                for row in rows:
                    parts.append("<tr>")
                    for cell in row:
                        parts.append(f"<td>{_safe(cell)}</td>")
                    parts.append("</tr>")
                parts.append("</tbody></table>")
                if total > len(rows):
                    parts.append(f'<div class="truncated">… {total - len(rows):,} more row(s) '
                                 f'omitted from the report. Open the source CSV for the full data: '
                                 f'<code>{_safe(str(rel))}</code></div>')
            parts.append("</div>")

    parts.append("</article></main>")
    parts.append('<footer>'
                 f'Generated by DFIR Automation Pipeline · '
                 f'{ctx.customer_name} · Case {ctx.case_reference}'
                 '</footer></body></html>')

    rendered = "".join(parts)
    rendered = fix_mojibake(rendered)
    out_path = ctx.reports_dir / "comprehensive_evidence_report.html"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    return out_path
