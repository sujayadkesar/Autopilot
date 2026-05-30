"""USN Journal → file-create / file-rename / file-delete events."""
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from .common import Event, iter_csv, parse_time, to_epoch, to_iso, register, trunc


@register
def ingest_usn_journal(parsed_dir: Path) -> Iterator[Event]:
    csv_path = parsed_dir / "usn_lnk_mru" / "usn_journal" / "usnjrnl.csv"
    if not csv_path.exists():
        return
    for row in iter_csv(csv_path, max_rows=500_000):
        ts = parse_time(row.get("UpdateTimestamp") or row.get("Timestamp"))
        if not ts:
            continue
        reason = (row.get("UpdateReasons") or row.get("Reason") or "").strip()
        et = "fs_change"
        sev = "INFO"
        rl = reason.lower()
        if "filecreate" in rl or "namecreate" in rl:
            et = "file_create"
        elif "filedelete" in rl or "namedelete" in rl:
            et = "file_delete"; sev = "LOW"
        elif "rename" in rl:
            et = "file_rename"
        elif "datatruncation" in rl or "extend" in rl:
            et = "file_modify"
        target = (row.get("Name") or row.get("FileName") or row.get("FullPath") or "").strip()
        yield Event(
            ts_utc=to_iso(ts), ts_epoch=to_epoch(ts),
            agent="usn_lnk_mru", source="usn_journal/usnjrnl.csv",
            event_type=et, target=target, severity=sev,
            summary=f"{reason}: {target}"[:300],
            raw={"reason": reason, "name": target,
                 "parent_path": row.get("ParentPath", ""),
                 "extension": row.get("Extension", ""),
                 "file_attribs": row.get("FileAttributes", "")},
        )
