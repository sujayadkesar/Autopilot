"""
Mojibake repair — surgical fix for emoji that were stored as cp1252 bytes
then re-encoded as UTF-8 (the classic "ðŸ"Š" pattern for "📊").

Why a surgical approach is needed:
  A naive `text.encode("cp1252").decode("utf-8")` on the whole document fails
  if any character isn't representable in cp1252 (en-dash —, smart quotes ' ',
  etc.). We only want to "rescue" the cp1252-encoded sequences, not touch
  legitimate Unicode.

Approach:
  Find candidate sequences of length 2-4 starting with a high-byte cp1252
  character (Â/Ã/â/ã/ð/ñ etc.) followed by other high-bytes, then try
  cp1252.encode → utf-8.decode. If both succeed and produce a non-control
  character, replace; otherwise leave as-is.
"""

from __future__ import annotations

import re

# Lead bytes for UTF-8 multi-byte sequences when they appear as cp1252 chars.
# UTF-8 leads: 0xC2-0xDF (2-byte), 0xE0-0xEF (3-byte), 0xF0-0xF4 (4-byte).
# When decoded as cp1252, those bytes map to: Â-ß, à-ï, ð-ô.
_LEAD_2 = "ÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß"           # 0xC2-0xDF
_LEAD_3 = "àáâãäåæçèéêëìíîï"                           # 0xE0-0xEF
_LEAD_4 = "ðñòóô"                                       # 0xF0-0xF4

# Continuation bytes 0x80-0xBF in cp1252 map to a wider range because
# 0x80-0x9F have specific glyph mappings (€‚ƒ"…†‡ˆ‰Š‹Œ Ž   ' ' " " •–—˜™š›œ žŸ).
# In UTF-8 BMP-encoded form via cp1252 we only need to match anything that
# is a cp1252 high-byte glyph or U+0080-U+00FF. For practical purposes:
_CONT = (
    r"[-ÿŒœŠšŸŽž"
    r"ƒˆ˜–—‘’‚“”„"
    r"†‡•…‰‹›€™]"
)

# Regex: match leadX followed by (X-1) continuations. Try longest first.
_PATTERN = re.compile(
    r"(?P<m4>[" + _LEAD_4 + r"]" + _CONT + r"{3})"
    r"|(?P<m3>[" + _LEAD_3 + r"]" + _CONT + r"{2})"
    r"|(?P<m2>[" + _LEAD_2 + r"]" + _CONT + r")"
)


def _try_decode(seq: str) -> str | None:
    """Try cp1252→utf-8 round-trip. Return decoded char or None on failure."""
    try:
        b = seq.encode("cp1252")
    except UnicodeEncodeError:
        return None
    try:
        out = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not out or any(ord(c) < 0x20 for c in out):
        return None
    return out


def fix_mojibake(text: str) -> str:
    """Repair cp1252-mojibake'd UTF-8 sequences in `text`.

    Idempotent: applying twice returns the same result.
    Conservative: only replaces sequences that round-trip cleanly.
    """
    if not text:
        return text

    def _repl(m: re.Match) -> str:
        seq = m.group(0)
        decoded = _try_decode(seq)
        return decoded if decoded is not None else seq

    return _PATTERN.sub(_repl, text)


def fix_mojibake_file(path, encoding: str = "utf-8") -> bool:
    """Read, fix, and rewrite a file. Returns True if any change was made."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return False
    try:
        original = p.read_text(encoding=encoding, errors="replace")
    except Exception:
        return False
    fixed = fix_mojibake(original)
    if fixed != original:
        p.write_text(fixed, encoding=encoding)
        return True
    return False
