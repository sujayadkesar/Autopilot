"""
Shared types + registry + helpers used by every ingester.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

log = logging.getLogger("dfir.supertimeline")

# ────────────────────────────────────────────────────────────────────────────
# Event shape
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class Event:
    ts_utc: str
    ts_epoch: int
    agent: str
    source: str
    event_type: str
    actor: str = ""
    target: str = ""
    severity: str = "INFO"
    summary: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


# ────────────────────────────────────────────────────────────────────────────
# Ingester registry — every source module registers itself on import
# ────────────────────────────────────────────────────────────────────────────

# Each ingester takes (parsed_dir: Path) and yields Event objects.
IngesterFn = Callable[[Path], Iterator[Event]]
INGESTERS: List[IngesterFn] = []


def register(fn: IngesterFn) -> IngesterFn:
    INGESTERS.append(fn)
    return fn


def ingest_all(parsed_dir: Path) -> Iterator[Event]:
    """Run every registered ingester sequentially, yielding events."""
    for fn in INGESTERS:
        name = getattr(fn, "__name__", "?")
        try:
            n = 0
            for evt in fn(parsed_dir):
                yield evt
                n += 1
            log.info("Ingester %s produced %d event(s)", name, n)
        except Exception as e:
            log.warning("Ingester %s failed: %s", name, e)


# ────────────────────────────────────────────────────────────────────────────
# Time parsing helpers
# ────────────────────────────────────────────────────────────────────────────

_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y/%m/%d %H:%M:%S",
)


def parse_time(s: Any) -> Optional[datetime]:
    """Best-effort parse — returns timezone-aware UTC datetime or None."""
    if s is None:
        return None
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    s = str(s).strip()
    if not s:
        return None
    # Strip trailing Z + microsec overflow (.fffffff)
    s_norm = s.rstrip("Z")
    if "." in s_norm:
        # Truncate fractional seconds beyond 6 digits (Python strptime limit)
        head, frac = s_norm.split(".", 1)
        frac_digits = ""
        for c in frac:
            if c.isdigit():
                frac_digits += c
            else:
                break
        rest = frac[len(frac_digits):]
        if len(frac_digits) > 6:
            frac_digits = frac_digits[:6]
        s_norm = f"{head}.{frac_digits}{rest}"
    for fmt in _TIME_FORMATS:
        try:
            dt = datetime.strptime(s_norm, fmt)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Last resort: ISO 8601 fromisoformat
    try:
        dt = datetime.fromisoformat(s_norm)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def to_epoch(dt: Optional[datetime]) -> int:
    if not dt:
        return 0
    try:
        return int(dt.timestamp())
    except (OverflowError, OSError):
        return 0


def to_iso(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ────────────────────────────────────────────────────────────────────────────
# CSV iteration helper — UTF-8-BOM-tolerant + size-bounded
# ────────────────────────────────────────────────────────────────────────────

def iter_csv(path: Path, max_rows: int = 200_000) -> Iterator[Dict[str, str]]:
    """Yield each row of a CSV as a dict. Tolerates BOM + bad lines."""
    if not path.exists() or path.stat().st_size < 50:
        return
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            rdr = csv.DictReader(f)
            for i, row in enumerate(rdr):
                if i >= max_rows:
                    log.info("CSV %s exceeded %d rows; truncating", path.name, max_rows)
                    return
                yield row
    except Exception as e:
        log.warning("Could not iterate CSV %s: %s", path, e)


def trunc(value: Any, n: int = 500) -> str:
    s = "" if value is None else str(value)
    return s[:n - 1] + "…" if len(s) > n else s
