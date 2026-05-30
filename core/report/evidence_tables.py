"""Render CSV rows as HTML evidence tables, with IOC cells highlighted."""

from __future__ import annotations

import csv
import html
from pathlib import Path
from typing import List, Optional


def csv_to_html_table(
    path: Path,
    max_rows: int = 100,
    highlight_columns: Optional[List[str]] = None,
    highlight_values: Optional[List[str]] = None,
    title: str = "",
) -> str:
    highlight_columns = [c.lower() for c in (highlight_columns or [])]
    highlight_vals_lower = [v.lower() for v in (highlight_values or [])]

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            rows = []
            for row in reader:
                rows.append(row)
                if len(rows) >= max_rows:
                    break
    except Exception as e:
        return f'<p class="err">Could not read {html.escape(str(path))}: {html.escape(str(e))}</p>'

    if not headers or not rows:
        return '<p class="no-data">No data in file.</p>'

    def cell(header: str, value: str) -> str:
        escaped = html.escape(str(value) if value else "")
        highlight_col = header.lower() in highlight_columns
        highlight_val = any(v in str(value).lower() for v in highlight_vals_lower) if highlight_vals_lower else False
        if highlight_col or highlight_val:
            return f'<td class="highlight-cell">{escaped}</td>'
        return f"<td>{escaped}</td>"

    title_html = f'<div class="evidence-title">{html.escape(title or path.name)}</div>' if title or True else ""
    total = len(rows)
    note = f'<p class="note">Showing first {max_rows} of {total}+ rows</p>' if total >= max_rows else ""

    th_row = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body_rows = []
    for row in rows:
        cells = "".join(cell(h, row.get(h, "")) for h in headers)
        body_rows.append(f"<tr>{cells}</tr>")

    return (
        f'{title_html}'
        f'<div class="evidence-table-wrap">'
        f"<table><thead><tr>{th_row}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
        f"</div>{note}"
    )
