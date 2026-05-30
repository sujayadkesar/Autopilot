"""
exhibits.py — render an EvidenceSnippet as an authentic-looking tool "screenshot".

Given a piece of evidence (headers + rows + columns to highlight), produce a
self-contained HTML fragment styled to resemble the native Windows tool the
evidence came from:

  * registry/*            → Registry Editor (Regedit) look-alike
  * event-log channels    → Event Viewer look-alike
  * browsers/*            → browser-history viewer
  * mft/prefetch/amcache  → file-table / Explorer-detail look-alike
  * everything else       → neutral "Evidence Viewer" grid

Highlighted cells get a yellow marker + red outline so the relevant data is
visually called out — the "highlight the things" requirement. The fragment is
rasterized to PNG by core.render.pdf.ReportRenderer.fragment_to_png() and
embedded into the report; if rendering is unavailable the HTML table is shown
inline instead (existing behaviour).
"""

from __future__ import annotations

import html as _html
import logging
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("dfir.render.exhibits")


def _classify(source: str) -> str:
    s = (source or "").lower()
    if s.startswith("registry") or "regist" in s or "ntuser" in s or "usbstor" in s:
        return "registry"
    if any(k in s for k in ("event", "evtx", "security", "sysmon", "powershell",
                            "system log", "winevt", "/4", "rdp", "wmi-activity")):
        return "eventlog"
    if "browser" in s or "chrome" in s or "edge" in s or "firefox" in s or "history" in s:
        return "browser"
    if any(k in s for k in ("mft", "prefetch", "amcache", "usn", "lnk", "shellbag",
                            "recycle", "file", "timeline", "srum", "capa", "yara")):
        return "files"
    return "generic"


_CHROME = {
    "registry": ("Registry Editor", "#f0f0f0", "#7a3b00"),
    "eventlog": ("Event Viewer", "#f0f0f0", "#1f4e79"),
    "browser":  ("Browsing History", "#dee1e6", "#3b3b3b"),
    "files":    ("File Details", "#f0f0f0", "#1f4e79"),
    "generic":  ("Evidence Viewer", "#f0f0f0", "#333333"),
}


def build_exhibit_html(snippet, exhibit_no: int = 1) -> str:
    """Return a self-contained HTML fragment (with #exhibit-root) for one snippet."""
    kind = _classify(getattr(snippet, "source", ""))
    tool_name, titlebar_bg, accent = _CHROME[kind]
    title = _html.escape(str(getattr(snippet, "title", "") or "Evidence"))
    source = _html.escape(str(getattr(snippet, "source", "") or ""))
    headers = list(getattr(snippet, "headers", []) or [])
    rows = list(getattr(snippet, "rows", []) or [])
    highlight = set(getattr(snippet, "highlight", set()) or set())

    addr_bar = ""
    if kind == "registry":
        # Use the source as a regedit-style key path in the address bar
        reg_path = source.replace("/", "\\")
        addr_bar = (
            '<div class="ex-addr"><span class="ex-addr-ico">🗝</span>'
            f'Computer\\{reg_path}</div>'
        )
    elif kind == "files":
        addr_bar = f'<div class="ex-addr"><span class="ex-addr-ico">📁</span>{source}</div>'
    elif kind == "browser":
        addr_bar = f'<div class="ex-addr ex-addr-url">{source}</div>'

    # Table head
    thead = "".join(f"<th>{_html.escape(str(h))}</th>" for h in headers)
    # Rows
    body_rows = []
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            col = headers[i] if i < len(headers) else ""
            cls = "hl" if col in highlight else ""
            cells.append(f'<td class="{cls}">{_html.escape(str(cell))}</td>')
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    tbody = "".join(body_rows)

    caption = (
        f'<div class="ex-caption">EXHIBIT {exhibit_no} — {title}'
        f'<span class="ex-src">Source: {source or tool_name}</span></div>'
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 14px; background: #c8cdd6;
       font-family: "Segoe UI", Tahoma, Arial, sans-serif; }}
#exhibit-root {{ display: inline-block; min-width: 640px; max-width: 1100px;
       background: #fff; border: 1px solid #9aa0a8;
       box-shadow: 0 6px 22px rgba(0,0,0,.28); border-radius: 6px; overflow: hidden; }}
.ex-titlebar {{ background: {titlebar_bg}; border-bottom: 1px solid #c8c8c8;
       padding: 7px 12px; display: flex; align-items: center; gap: 8px;
       font-size: 12px; color: #222; }}
.ex-titlebar .ex-dots {{ margin-left: auto; color: #888; letter-spacing: 2px; }}
.ex-tool {{ font-weight: 600; color: {accent}; }}
.ex-menu {{ background: #fafafa; border-bottom: 1px solid #e2e2e2;
       padding: 4px 12px; font-size: 11px; color: #555; }}
.ex-addr {{ background: #fff; border: 1px solid #d6d6d6; border-radius: 3px;
       margin: 8px 12px; padding: 5px 10px; font-size: 11px; color: #333;
       font-family: Consolas, monospace; white-space: nowrap; overflow: hidden;
       text-overflow: ellipsis; }}
.ex-addr-ico {{ margin-right: 6px; }}
.ex-addr-url {{ color: #1a5fb4; }}
.ex-grid {{ width: 100%; border-collapse: collapse; font-size: 11.5px; }}
.ex-grid th {{ position: sticky; top: 0; background: #eef1f5; text-align: left;
       padding: 6px 10px; border-bottom: 1px solid #c4ccd6; border-right: 1px solid #e3e8ee;
       color: #2a2a2a; font-weight: 600; white-space: nowrap; }}
.ex-grid td {{ padding: 5px 10px; border-bottom: 1px solid #eef0f3;
       border-right: 1px solid #f3f5f7; color: #333; font-family: Consolas, monospace;
       font-size: 11px; vertical-align: top; word-break: break-word; max-width: 360px; }}
.ex-grid tr:nth-child(even) td {{ background: #fafbfc; }}
.ex-grid td.hl {{ background: #fff1a8; outline: 2px solid #d23b3b; outline-offset: -2px;
       color: #111; font-weight: 700; }}
.ex-body {{ max-height: 360px; overflow: auto; border-top: 1px solid #e6e6e6; }}
.ex-caption {{ font-family: Georgia, serif; font-size: 11px; color: #555;
       padding: 8px 12px 10px; font-style: italic; border-top: 1px solid #eee; }}
.ex-caption .ex-src {{ float: right; font-style: normal; color: #999;
       font-family: Consolas, monospace; font-size: 10px; }}
</style></head><body>
<div id="exhibit-root">
  <div class="ex-titlebar"><span class="ex-tool">{tool_name}</span>
     <span>— {title}</span><span class="ex-dots">— □ ✕</span></div>
  <div class="ex-menu">File&nbsp;&nbsp;Edit&nbsp;&nbsp;View&nbsp;&nbsp;Help</div>
  {addr_bar}
  <div class="ex-body">
    <table class="ex-grid"><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>
  </div>
  {caption}
</div></body></html>"""


def render_finding_exhibits(findings, out_dir: Path, renderer) -> int:
    """For each finding's evidence snippets, rasterize an exhibit PNG and attach
    the path back onto the snippet as `.image_path` (str). Returns count rendered.

    `findings` is a list of objects each exposing `.evidence` (list of snippets).
    `renderer` is a ReportRenderer (or None). No-op if renderer unavailable.
    """
    if renderer is None or not getattr(renderer, "available", False):
        return 0
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for fi, finding in enumerate(findings, start=1):
        evidence = getattr(finding, "evidence", None) or []
        for ei, snippet in enumerate(evidence, start=1):
            if not getattr(snippet, "rows", None):
                continue
            frag = build_exhibit_html(snippet, exhibit_no=ei)
            png = out_dir / f"exhibit_{fi:02d}_{ei:02d}.png"
            result = renderer.fragment_to_png(frag, png, width=1000)
            if result is not None:
                try:
                    # Path relative to the reports/ dir where the HTML/PDF lives
                    setattr(snippet, "image_path", f"exhibits/{png.name}")
                    n += 1
                except Exception:
                    pass
    return n
