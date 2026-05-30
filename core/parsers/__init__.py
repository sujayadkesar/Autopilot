"""Native (no-subprocess) parsers."""
from .browser_history import parse_browser_profile, BrowserParseResult

__all__ = ["parse_browser_profile", "BrowserParseResult"]
