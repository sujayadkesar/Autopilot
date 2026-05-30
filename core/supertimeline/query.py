"""
Supertimeline query API — used by the Workbench GUI.

All public functions return plain Python dicts/lists so the GUI can render
them directly in QTableView / QPlainTextEdit without SQLite dependencies
leaking into the UI layer.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .schema import open_db


def _row_to_dict(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    raw = d.get("raw")
    if raw:
        try:
            d["raw_parsed"] = json.loads(raw)
        except Exception:
            d["raw_parsed"] = None
    return d


class TimelineQuery:
    """Read-only convenience wrapper around the supertimeline DB."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def __enter__(self):
        self._conn = open_db(self.db_path)
        return self

    def __exit__(self, *a):
        if self._conn:
            self._conn.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if not self._conn:
            self._conn = open_db(self.db_path)
        return self._conn

    # ── meta ─────────────────────────────────────────────────────────────

    def event_count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM events")
        return cur.fetchone()[0]

    def time_range(self) -> Tuple[Optional[int], Optional[int]]:
        cur = self.conn.execute("SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events")
        row = cur.fetchone()
        return (row[0], row[1]) if row else (None, None)

    def counts_by_agent(self) -> Dict[str, int]:
        cur = self.conn.execute(
            "SELECT agent, COUNT(*) c FROM events GROUP BY agent ORDER BY c DESC"
        )
        return {r[0]: r[1] for r in cur.fetchall()}

    def counts_by_event_type(self, limit: int = 30) -> Dict[str, int]:
        cur = self.conn.execute(
            "SELECT event_type, COUNT(*) c FROM events "
            "GROUP BY event_type ORDER BY c DESC LIMIT ?", (limit,)
        )
        return {r[0]: r[1] for r in cur.fetchall()}

    def counts_by_severity(self) -> Dict[str, int]:
        cur = self.conn.execute(
            "SELECT severity, COUNT(*) c FROM events "
            "WHERE severity IS NOT NULL GROUP BY severity ORDER BY c DESC"
        )
        return {r[0]: r[1] for r in cur.fetchall()}

    # ── time histogram for the slider density chart ──────────────────────

    def histogram(self, bin_seconds: int = 3600,
                  agents: Optional[List[str]] = None) -> List[Tuple[int, int]]:
        """Return [(bin_start_epoch, count), ...] across the whole timeline."""
        sql = (
            "SELECT (ts_epoch / ?) * ? AS bin, COUNT(*) FROM events "
            "WHERE ts_epoch > 0 "
        )
        params: List[Any] = [bin_seconds, bin_seconds]
        if agents:
            ph = ",".join("?" * len(agents))
            sql += f"AND agent IN ({ph}) "
            params.extend(agents)
        sql += "GROUP BY bin ORDER BY bin"
        cur = self.conn.execute(sql, params)
        return [(r[0], r[1]) for r in cur.fetchall()]

    # ── window / range query ─────────────────────────────────────────────

    def window(self, start_epoch: int, end_epoch: int,
               agents: Optional[List[str]] = None,
               event_types: Optional[List[str]] = None,
               severities: Optional[List[str]] = None,
               limit: int = 5000) -> List[Dict[str, Any]]:
        sql = ("SELECT * FROM events WHERE ts_epoch BETWEEN ? AND ? ")
        params: List[Any] = [start_epoch, end_epoch]
        if agents:
            sql += f"AND agent IN ({','.join('?' * len(agents))}) "
            params.extend(agents)
        if event_types:
            sql += f"AND event_type IN ({','.join('?' * len(event_types))}) "
            params.extend(event_types)
        if severities:
            sql += f"AND severity IN ({','.join('?' * len(severities))}) "
            params.extend(severities)
        sql += "ORDER BY ts_epoch ASC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(sql, params)
        return [_row_to_dict(r) for r in cur.fetchall()]

    # ── pivot: every event mentioning a value (filename / hash / IP / user) ──

    def pivot(self, value: str, limit: int = 2000) -> List[Dict[str, Any]]:
        """Return every event where `value` appears in actor/target/summary/raw."""
        if not value:
            return []
        v = value.strip()
        if not v:
            return []
        # Try FTS first (fast); fall back to LIKE
        try:
            sql = ("SELECT events.* FROM events_fts JOIN events "
                   "ON events_fts.rowid = events.id "
                   "WHERE events_fts MATCH ? "
                   "ORDER BY ts_epoch ASC LIMIT ?")
            cur = self.conn.execute(sql, (f'"{v}"', limit))
            rows = cur.fetchall()
            if rows:
                return [_row_to_dict(r) for r in rows]
        except sqlite3.OperationalError:
            pass
        like = f"%{v}%"
        cur = self.conn.execute(
            "SELECT * FROM events WHERE "
            "actor LIKE ? OR target LIKE ? OR summary LIKE ? OR raw LIKE ? "
            "ORDER BY ts_epoch ASC LIMIT ?",
            (like, like, like, like, limit),
        )
        return [_row_to_dict(r) for r in cur.fetchall()]

    # ── distinct values for filter UI ────────────────────────────────────

    def distinct(self, column: str) -> List[str]:
        if column not in {"agent", "event_type", "severity"}:
            raise ValueError(f"Bad column: {column}")
        cur = self.conn.execute(
            f"SELECT DISTINCT {column} FROM events "
            f"WHERE {column} IS NOT NULL ORDER BY {column}"
        )
        return [r[0] for r in cur.fetchall() if r[0]]

    # ── bookmarks ────────────────────────────────────────────────────────

    def bookmark(self, event_id: int, note: str, tag: str, case_ref: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO bookmarks (event_id, note, tag, case_ref) "
            "VALUES (?, ?, ?, ?)", (event_id, note, tag, case_ref),
        )
        self.conn.commit()
        return cur.lastrowid or 0

    def remove_bookmark(self, bookmark_id: int) -> None:
        self.conn.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
        self.conn.commit()

    def list_bookmarks(self, case_ref: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = ("SELECT b.id, b.event_id, b.note, b.tag, b.case_ref, b.created_at, "
               "       e.ts_utc, e.agent, e.event_type, e.actor, e.target, e.summary "
               "FROM bookmarks b LEFT JOIN events e ON b.event_id = e.id ")
        params: List[Any] = []
        if case_ref:
            sql += "WHERE b.case_ref = ? "
            params.append(case_ref)
        sql += "ORDER BY e.ts_epoch ASC, b.created_at ASC"
        cur = self.conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def epoch_to_iso(epoch: int) -> str:
        try:
            return datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, ValueError, OSError):
            return ""
