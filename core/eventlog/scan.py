"""
scan.py — orchestrate the deterministic event-log analysis layer.

Reads the EvtxECmd CSVs produced by the event_logs agent, normalizes each row
(parsing the JSON Payload), and runs the PowerShell / process-chain / logon-session
/ IOC analyzers. Returns InvestigationFinding objects for the engine to fold in.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Dict, Iterator, List

log = logging.getLogger("dfir.eventlog.scan")

# Only retain events the analyzers actually use (bounds memory on huge Security logs)
_RELEVANT_EIDS = {
    4624, 4625, 4648, 4672, 4720, 4722, 4728, 4732, 4738, 4740,
    4698, 4702, 7045, 7034, 1102, 1100, 104, 4103, 4104, 4688,
    # Sysmon space
    1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25,
}
_MAX_EVENTS = 200_000

# csv field-size: event payloads (esp. 4104) can be very large
csv.field_size_limit(10 * 1024 * 1024)


def _to_int(v) -> int:
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return -1


def _parse_payload(raw: str) -> Dict:
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def iter_events(parsed_dir: Path) -> Iterator[Dict]:
    """Yield normalized event dicts from all event_logs CSVs."""
    ev_dir = parsed_dir / "event_logs"
    if not ev_dir.exists():
        return
    count = 0
    for csv_path in ev_dir.rglob("*.csv"):
        if csv_path.name == "hayabusa_results.csv":
            continue
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace", newline="") as f:
                for row in csv.DictReader(f):
                    eid = _to_int(row.get("EventId", row.get("Event Id", "")))
                    if eid not in _RELEVANT_EIDS:
                        continue
                    yield {
                        "eid": eid,
                        "time": row.get("TimeCreated", "") or "",
                        "channel": row.get("Channel", "") or "",
                        "computer": row.get("Computer", "") or "",
                        "provider": row.get("Provider", "") or "",
                        "map_desc": row.get("MapDescription", "") or "",
                        "username": row.get("UserName", "") or "",
                        "payload": _parse_payload(row.get("Payload", "")),
                        "source": csv_path.name,
                    }
                    count += 1
                    if count >= _MAX_EVENTS:
                        log.warning("Event cap %d reached — truncating analysis", _MAX_EVENTS)
                        return
        except Exception as e:
            log.warning("event CSV read %s: %s", csv_path.name, e)


def scan_event_logs(parsed_dir: Path) -> List:
    """Run all event-log analyzers and return their findings."""
    parsed_dir = Path(parsed_dir)
    events = list(iter_events(parsed_dir))
    if not events:
        return []
    log.info("Event-log layer: %d relevant event(s) loaded", len(events))

    from .powershell import analyze_powershell
    from .chains import analyze_chains
    from .sessions import analyze_sessions
    from .ioc import extract_iocs

    findings: List = []
    for fn in (analyze_powershell, analyze_chains, analyze_sessions):
        try:
            findings.extend(fn(events))
        except Exception as e:
            log.warning("%s failed: %s", fn.__name__, e)
    try:
        ioc_findings, ioc_dict = extract_iocs(events)
        findings.extend(ioc_findings)
        # Persist extracted IOCs for the Phase-5 roll-up
        try:
            (parsed_dir / "event_logs").mkdir(parents=True, exist_ok=True)
            (parsed_dir / "event_logs" / "extracted_iocs.json").write_text(
                json.dumps(ioc_dict, indent=2), encoding="utf-8")
        except Exception:
            pass
    except Exception as e:
        log.warning("extract_iocs failed: %s", e)

    return findings
