"""
Native Chrome/Edge/Firefox browser-history parser.

Replaces Hindsight (which crashes in its bundled Rich library when stdout is piped).
Uses Python's stdlib sqlite3 to read History/Cookies/Downloads/etc. directly from
the browser profile and writes deterministic CSV output our investigation engine
can consume.

Why bypass Hindsight?
  Hindsight is a PyInstaller bundle of Python+Rich. When run as a subprocess with
  capture_output=True on Windows, Rich's legacy Win32 renderer tries to encode
  Unicode characters (▼ etc.) to cp1252 and crashes. We've tried NO_COLOR=1,
  PYTHONIOENCODING=utf-8, chcp 65001 redirection, and DEVNULL — Rich still
  crashes inside its __exit__ buffer flush. Native Python sqlite3 is faster,
  zero-dependency, and gives us full control over the output schema.

What we extract per profile:
  * urls.csv     — full URL visit history with timestamps (from History.urls)
  * downloads.csv — download history with target paths (from History.downloads)
  * search.csv   — search-query terms (from History.keyword_search_terms)
  * cookies.csv  — cookies with host + name (from Cookies.cookies — values redacted)
  * logins.csv   — saved login origin URLs (from Login Data — passwords redacted)
"""

from __future__ import annotations

import csv
import logging
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("dfir.browser")

# Chromium WebKit timestamps are microseconds since 1601-01-01 UTC
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _chrome_ts(ts: Optional[int]) -> str:
    """Convert a Chromium timestamp (us since 1601) to ISO string."""
    if not ts:
        return ""
    try:
        return (_CHROME_EPOCH + timedelta(microseconds=int(ts))).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError):
        return ""


@dataclass
class BrowserParseResult:
    profile_path: Path
    output_dir: Path
    csvs: List[Path] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def _safe_copy_to_temp(src: Path) -> Optional[Path]:
    """Copy a SQLite DB to a temp location so we can open it read-only without
    touching the original (and side-stepping any browser file locks)."""
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(str(src), tmp.name)
        # Also copy WAL/SHM if present (sqlite needs these for some DBs)
        for ext in ("-wal", "-shm"):
            companion = src.with_name(src.name + ext)
            if companion.exists():
                try:
                    shutil.copy2(str(companion), tmp.name + ext)
                except Exception:
                    pass
        return Path(tmp.name)
    except Exception as e:
        log.warning("Could not copy %s: %s", src, e)
        return None


def _open_db_ro(path: Path) -> Optional[sqlite3.Connection]:
    """Open a SQLite DB in read-only mode."""
    try:
        # uri=True lets us pass mode=ro
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        log.warning("Could not open %s as SQLite: %s", path, e)
        return None


def _query_to_csv(conn: sqlite3.Connection, sql: str, headers: List[str],
                  out_path: Path, mapper=None) -> int:
    """Run a query and write rows as CSV. Returns row count."""
    try:
        cur = conn.cursor()
        cur.execute(sql)
    except Exception as e:
        log.warning("Query failed: %s — %s", sql[:60], e)
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for row in cur.fetchall():
            try:
                if mapper:
                    out_row = mapper(row)
                else:
                    out_row = list(row)
                w.writerow(out_row)
                n += 1
            except Exception:
                continue
    return n


# ────────────────────────────────────────────────────────────────────────────
# Chromium-family parsers (Chrome, Edge, Brave, Opera, Vivaldi)
# ────────────────────────────────────────────────────────────────────────────

def _parse_chromium_history(history_db: Path, out_dir: Path) -> Dict[str, int]:
    """Parse Chrome/Edge History sqlite — urls, visits, downloads, searches."""
    counts: Dict[str, int] = {}
    tmp = _safe_copy_to_temp(history_db)
    if not tmp:
        return counts
    try:
        conn = _open_db_ro(tmp)
        if not conn:
            return counts
        try:
            # urls.csv — every URL visited
            counts["urls"] = _query_to_csv(
                conn,
                "SELECT url, title, visit_count, typed_count, last_visit_time, hidden "
                "FROM urls ORDER BY last_visit_time DESC",
                ["url", "title", "visit_count", "typed_count", "last_visit_time", "hidden"],
                out_dir / "urls.csv",
                mapper=lambda r: [r["url"], r["title"] or "", r["visit_count"],
                                  r["typed_count"], _chrome_ts(r["last_visit_time"]),
                                  r["hidden"]],
            )

            # downloads.csv — file downloads with target paths
            counts["downloads"] = _query_to_csv(
                conn,
                "SELECT current_path, target_path, start_time, end_time, "
                "received_bytes, total_bytes, state, danger_type, "
                "interrupt_reason, tab_url, mime_type "
                "FROM downloads ORDER BY start_time DESC",
                ["current_path", "target_path", "start_time", "end_time",
                 "received_bytes", "total_bytes", "state", "danger_type",
                 "interrupt_reason", "tab_url", "mime_type"],
                out_dir / "downloads.csv",
                mapper=lambda r: [r["current_path"], r["target_path"],
                                  _chrome_ts(r["start_time"]),
                                  _chrome_ts(r["end_time"]),
                                  r["received_bytes"], r["total_bytes"],
                                  r["state"], r["danger_type"],
                                  r["interrupt_reason"], r["tab_url"],
                                  r["mime_type"]],
            )

            # search_terms.csv — terms typed into the address bar / search engines
            counts["searches"] = _query_to_csv(
                conn,
                "SELECT k.term, u.url, u.last_visit_time, u.visit_count "
                "FROM keyword_search_terms k "
                "JOIN urls u ON k.url_id = u.id "
                "ORDER BY u.last_visit_time DESC",
                ["term", "url", "last_visit_time", "visit_count"],
                out_dir / "searches.csv",
                mapper=lambda r: [r["term"], r["url"],
                                  _chrome_ts(r["last_visit_time"]),
                                  r["visit_count"]],
            )

            # visits_join.csv — visit-level detail with referrer
            counts["visits"] = _query_to_csv(
                conn,
                "SELECT v.visit_time, u.url, u.title, v.transition, v.from_visit "
                "FROM visits v JOIN urls u ON v.url = u.id "
                "ORDER BY v.visit_time DESC LIMIT 50000",
                ["visit_time", "url", "title", "transition", "from_visit"],
                out_dir / "visits.csv",
                mapper=lambda r: [_chrome_ts(r["visit_time"]), r["url"],
                                  r["title"] or "", r["transition"],
                                  r["from_visit"]],
            )
        finally:
            conn.close()
    finally:
        try:
            tmp.unlink(missing_ok=True)
            for ext in ("-wal", "-shm"):
                Path(str(tmp) + ext).unlink(missing_ok=True)
        except Exception:
            pass
    return counts


def _parse_chromium_cookies(cookies_db: Path, out_dir: Path) -> int:
    """Parse Chrome/Edge Cookies — exports host + name + last_access_utc only.
    Cookie VALUES are intentionally NOT exported (sensitive)."""
    tmp = _safe_copy_to_temp(cookies_db)
    if not tmp:
        return 0
    try:
        conn = _open_db_ro(tmp)
        if not conn:
            return 0
        try:
            # Schema varies between Chromium versions; accept either column name
            return _query_to_csv(
                conn,
                "SELECT host_key, name, path, creation_utc, last_access_utc, "
                "expires_utc, is_secure, is_httponly "
                "FROM cookies ORDER BY last_access_utc DESC",
                ["host", "name", "path", "creation_utc", "last_access_utc",
                 "expires_utc", "is_secure", "is_httponly"],
                out_dir / "cookies.csv",
                mapper=lambda r: [r["host_key"], r["name"], r["path"],
                                  _chrome_ts(r["creation_utc"]),
                                  _chrome_ts(r["last_access_utc"]),
                                  _chrome_ts(r["expires_utc"]),
                                  r["is_secure"], r["is_httponly"]],
            )
        finally:
            conn.close()
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
    return 0


def _parse_chromium_logins(login_db: Path, out_dir: Path) -> int:
    """Parse Chrome/Edge Login Data — origin_url + username only (NO passwords)."""
    tmp = _safe_copy_to_temp(login_db)
    if not tmp:
        return 0
    try:
        conn = _open_db_ro(tmp)
        if not conn:
            return 0
        try:
            return _query_to_csv(
                conn,
                "SELECT origin_url, action_url, username_value, "
                "date_created, date_last_used, times_used "
                "FROM logins ORDER BY date_last_used DESC",
                ["origin_url", "action_url", "username", "date_created",
                 "date_last_used", "times_used"],
                out_dir / "logins.csv",
                mapper=lambda r: [r["origin_url"], r["action_url"],
                                  r["username_value"],
                                  _chrome_ts(r["date_created"]),
                                  _chrome_ts(r["date_last_used"]),
                                  r["times_used"]],
            )
        finally:
            conn.close()
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
    return 0


# ────────────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────────────

def parse_browser_profile(profile_path: Path, out_dir: Path) -> BrowserParseResult:
    """Parse a single Chromium profile directory (Default, Profile 1, etc.).

    Args:
        profile_path: Path to the profile dir (must contain at least History).
        out_dir: Where to write CSVs.
    """
    result = BrowserParseResult(profile_path=profile_path, output_dir=out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    history_db = profile_path / "History"
    if history_db.exists():
        try:
            counts = _parse_chromium_history(history_db, out_dir)
            result.counts.update(counts)
        except Exception as e:
            result.errors.append(f"History: {e}")
    else:
        result.errors.append("History DB not present")

    cookies_db = profile_path / "Network" / "Cookies"
    if not cookies_db.exists():
        cookies_db = profile_path / "Cookies"  # older Chrome layout
    if cookies_db.exists():
        try:
            n = _parse_chromium_cookies(cookies_db, out_dir)
            result.counts["cookies"] = n
        except Exception as e:
            result.errors.append(f"Cookies: {e}")

    login_db = profile_path / "Login Data"
    if login_db.exists():
        try:
            n = _parse_chromium_logins(login_db, out_dir)
            result.counts["logins"] = n
        except Exception as e:
            result.errors.append(f"Login Data: {e}")

    # Collect produced CSVs
    result.csvs = sorted(out_dir.glob("*.csv"))
    return result
