"""Prefetch (.pf) → process_execution events. PECmd outputs both summary + timeline CSVs."""
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from .common import Event, iter_csv, parse_time, to_epoch, to_iso, register


@register
def ingest_prefetch(parsed_dir: Path) -> Iterator[Event]:
    pf_dir = parsed_dir / "prefetch_amcache_mft" / "prefetch"
    if not pf_dir.exists():
        return

    # Timeline CSV (one row per run timestamp)
    for tl in pf_dir.glob("*Timeline*.csv"):
        for row in iter_csv(tl):
            ts = parse_time(row.get("RunTime") or row.get("LastRunTime"))
            if not ts:
                continue
            exe = row.get("ExecutableName") or row.get("SourceFilename") or ""
            yield Event(
                ts_utc=to_iso(ts), ts_epoch=to_epoch(ts),
                agent="prefetch_amcache_mft", source=f"prefetch/{tl.name}",
                event_type="process_execution", target=exe, severity="INFO",
                summary=f"Prefetch run: {exe}",
                raw={k: v for k, v in row.items() if k and v},
            )

    # Output CSV (summary, with up to 8 LastRun timestamps per binary)
    for f in pf_dir.glob("*Output.csv"):
        if "Timeline" in f.name:
            continue
        for row in iter_csv(f):
            exe = row.get("ExecutableName") or row.get("SourceFilename") or ""
            for col in ("LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2",
                        "PreviousRun3", "PreviousRun4", "PreviousRun5", "PreviousRun6"):
                ts = parse_time(row.get(col))
                if not ts:
                    continue
                yield Event(
                    ts_utc=to_iso(ts), ts_epoch=to_epoch(ts),
                    agent="prefetch_amcache_mft", source=f"prefetch/{f.name}",
                    event_type="process_execution", target=exe, severity="INFO",
                    summary=f"Prefetch {col}: {exe}",
                    raw={"executable": exe, "run_count": row.get("RunCount", ""),
                         "files_loaded": (row.get("FilesLoaded", "") or "")[:300]},
                )
