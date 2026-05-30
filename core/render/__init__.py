"""
core.render — high-fidelity rendering helpers (PDF + evidence-exhibit PNGs).

All rendering goes through a single headless-Chromium instance (Playwright).
Everything degrades gracefully: if Playwright or its Chromium build is missing,
the renderer reports `available == False` and every method becomes a no-op that
returns None, so the pipeline still produces HTML reports without hard-failing.
"""

from .pdf import ReportRenderer, renderer_available

__all__ = ["ReportRenderer", "renderer_available"]
