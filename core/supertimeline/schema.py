"""
Supertimeline SQLite schema.

One table = one fact. Every artefact-derived event is normalised into a row
with: timestamp, agent, source-CSV, event-type, actor, target, severity,
summary, raw-JSON. Indexed on timestamp / actor / target / event_type so the
workbench can pivot any of them in milliseconds even with 1M+ rows.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc        TEXT    NOT NULL,
    ts_epoch      INTEGER NOT NULL,
    agent         TEXT    NOT NULL,
    source        TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    actor         TEXT,
    target        TEXT,
    severity      TEXT,
    summary       TEXT,
    raw           TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_actor     ON events(actor);
CREATE INDEX IF NOT EXISTS idx_events_target    ON events(target);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_agent     ON events(agent);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);

CREATE TABLE IF NOT EXISTS bookmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER REFERENCES events(id),
    note        TEXT,
    tag         TEXT,
    case_ref    TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bookmarks_tag    ON bookmarks(tag);
CREATE INDEX IF NOT EXISTS idx_bookmarks_event  ON bookmarks(event_id);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Search-friendly virtual FTS5 table (best-effort; if FTS5 isn't compiled
-- in the SQLite build we'll fall back to LIKE queries against `events.raw`).
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    summary, actor, target, raw,
    content='events', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_fts_ai AFTER INSERT ON events BEGIN
  INSERT INTO events_fts(rowid, summary, actor, target, raw)
    VALUES (new.id, new.summary, COALESCE(new.actor,''),
            COALESCE(new.target,''), COALESCE(new.raw,''));
END;
"""


def open_db(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the supertimeline DB and ensure schema is applied."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    # Performance: WAL mode + larger page cache = fast bulk inserts
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-50000")  # ~50 MB
    conn.executescript(SCHEMA)
    # FTS is best-effort
    try:
        conn.executescript(FTS_SCHEMA)
    except sqlite3.OperationalError:
        pass
    conn.commit()
    return conn


def reset_events(conn: sqlite3.Connection) -> None:
    """Wipe the events + FTS tables (kept bookmarks). Used on re-ingestion."""
    conn.execute("DELETE FROM events")
    try:
        conn.execute("DELETE FROM events_fts")
    except sqlite3.OperationalError:
        pass
    conn.commit()
