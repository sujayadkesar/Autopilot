"""
pdf.py — Playwright-backed renderer for PDF export and evidence-exhibit PNGs.

A single headless Chromium instance is started lazily and reused for the whole
run (cheap after warm-up). The renderer is a context manager:

    with ReportRenderer(ctx) as r:
        if r.available:
            png = r.fragment_to_png(html_fragment, out_png, width=900)
            pdf = r.html_to_pdf(html_path, out_pdf, title="Case 123")

If Playwright (or its Chromium download) is unavailable, `r.available` is False
and the methods return None. Callers must treat None as "skip, keep HTML".

Threading note: the Playwright *sync* API cannot run inside an asyncio event
loop, but the DFIR pipeline runs on plain worker threads (no loop), so the sync
API is the right choice here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("dfir.render")

_CONFIDENTIAL = "CONFIDENTIAL — INVESTIGATIVE MATERIAL"


def renderer_available() -> bool:
    """True if Playwright is importable. Chromium presence is checked at launch."""
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


class ReportRenderer:
    """Lazily-started, reusable headless-Chromium renderer."""

    def __init__(self, case_reference: str = "", footer_text: str = _CONFIDENTIAL):
        self.case_reference = case_reference
        self.footer_text = footer_text
        self._pw = None
        self._browser = None
        self._started = False
        self._failed = False

    # ── lifecycle ────────────────────────────────────────────────────────
    @property
    def available(self) -> bool:
        if self._failed:
            return False
        if not self._started:
            self._start()
        return self._browser is not None and not self._failed

    def _start(self) -> None:
        self._started = True
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            log.warning("Playwright not installed — PDF/exhibit rendering disabled (%s). "
                        "Install with: pip install playwright && playwright install chromium", e)
            self._failed = True
            return
        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(args=["--no-sandbox"])
        except Exception as e:
            log.warning("Chromium launch failed — PDF/exhibit rendering disabled (%s). "
                        "Run: playwright install chromium", e)
            self._failed = True
            self._cleanup()

    def _cleanup(self) -> None:
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._pw = None

    def close(self) -> None:
        self._cleanup()

    def __enter__(self) -> "ReportRenderer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── rendering ────────────────────────────────────────────────────────
    def fragment_to_png(self, html_fragment: str, out_png: Path,
                        width: int = 900, selector: str = "#exhibit-root") -> Optional[Path]:
        """Render a self-contained HTML fragment and screenshot one element to PNG.

        The fragment must contain an element matching `selector` (default
        '#exhibit-root'); only that element is captured for tight bounds.
        Returns the PNG path, or None if rendering is unavailable/failed.
        """
        if not self.available:
            return None
        out_png = Path(out_png)
        out_png.parent.mkdir(parents=True, exist_ok=True)
        page = None
        try:
            page = self._browser.new_page(viewport={"width": width, "height": 600},
                                          device_scale_factor=2)
            page.set_content(html_fragment, wait_until="networkidle")
            el = page.query_selector(selector)
            if el is not None:
                el.screenshot(path=str(out_png))
            else:
                page.screenshot(path=str(out_png), full_page=True)
            return out_png
        except Exception as e:
            log.warning("Exhibit PNG render failed (%s): %s", out_png.name, e)
            return None
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass

    def html_to_pdf(self, html_path: Path, out_pdf: Path,
                    title: str = "") -> Optional[Path]:
        """Print an HTML file to PDF with page numbers + confidential footer.

        Returns the PDF path, or None if rendering is unavailable/failed.
        """
        if not self.available:
            return None
        html_path = Path(html_path)
        out_pdf = Path(out_pdf)
        out_pdf.parent.mkdir(parents=True, exist_ok=True)
        page = None
        try:
            page = self._browser.new_page()
            page.goto(html_path.resolve().as_uri(), wait_until="networkidle")
            page.emulate_media(media="print")
            header = (
                '<div style="font-family:Helvetica,Arial,sans-serif;font-size:7px;'
                'color:#888;width:100%;padding:0 12mm;display:flex;'
                'justify-content:space-between;">'
                f'<span>{_esc(title or self.case_reference)}</span>'
                f'<span>{_esc(self.case_reference)}</span></div>'
            )
            footer = (
                '<div style="font-family:Helvetica,Arial,sans-serif;font-size:7px;'
                'color:#888;width:100%;padding:0 12mm;display:flex;'
                'justify-content:space-between;">'
                f'<span>{_esc(self.footer_text)}</span>'
                '<span>Page <span class="pageNumber"></span> of '
                '<span class="totalPages"></span></span></div>'
            )
            page.pdf(
                path=str(out_pdf),
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template=header,
                footer_template=footer,
                margin={"top": "18mm", "bottom": "16mm", "left": "0", "right": "0"},
            )
            return out_pdf
        except Exception as e:
            log.warning("PDF render failed (%s): %s", out_pdf.name, e)
            return None
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass


def _esc(s: str) -> str:
    return (str(s or "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
