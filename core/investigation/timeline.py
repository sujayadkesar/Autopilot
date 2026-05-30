"""
Timeline correlation engine.

After the deterministic InvestigationEngine produces findings, this module
walks every finding's `timeline` entries and groups them into "chains" — events
that occurred within a configurable time window of each other. Cross-agent
correlations like:

    USN write to mimikatz.exe at 14:02:14
    Prefetch first-run of mimikatz.exe at 14:02:18
    EVTX 4688 process create  at 14:02:19
    EVTX 4648 explicit creds  at 14:02:21

…become a single high-confidence chain finding showing the credential-theft
sequence happened in a 7-second window.

The chain detector is purely temporal — it doesn't claim semantic links, only
co-occurrence. The narrative interpretation is left to the analyst (or to a
later LLM pass if enabled).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from .engine import EvidenceSnippet, InvestigationFinding


@dataclass
class TimelineEvent:
    timestamp: datetime
    finding_index: int      # which finding this came from
    finding_title: str
    finding_severity: str
    description: str        # the per-event description from finding.timeline
    category: str

    def __lt__(self, other: "TimelineEvent") -> bool:
        return self.timestamp < other.timestamp


def correlate(findings: List[InvestigationFinding],
              window_seconds: int = 120,
              min_chain_size: int = 3) -> List[InvestigationFinding]:
    """
    Build chain-findings from temporally co-located events across findings.

    Args:
      findings: the list of deterministic findings to correlate
      window_seconds: maximum gap between consecutive events in a chain
      min_chain_size: a chain must have at least this many events to be reported
    """
    events: List[TimelineEvent] = []
    for i, f in enumerate(findings):
        for ts, desc in (f.timeline or []):
            if isinstance(ts, datetime):
                events.append(TimelineEvent(
                    timestamp=ts,
                    finding_index=i,
                    finding_title=f.title,
                    finding_severity=f.severity,
                    description=desc,
                    category=f.category,
                ))

    if len(events) < min_chain_size:
        return []

    events.sort()

    # Greedy chain assembly
    chains: List[List[TimelineEvent]] = []
    current: List[TimelineEvent] = []
    win = timedelta(seconds=window_seconds)

    for evt in events:
        if not current:
            current = [evt]
            continue
        if evt.timestamp - current[-1].timestamp <= win:
            current.append(evt)
        else:
            if len(current) >= min_chain_size:
                chains.append(current)
            current = [evt]
    if current and len(current) >= min_chain_size:
        chains.append(current)

    if not chains:
        return []

    # Convert each chain into a finding with all its events as evidence
    out: List[InvestigationFinding] = []
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for chain in chains:
        # Chain severity = max severity of any event in the chain
        chain_sev = "INFO"
        for evt in chain:
            if sev_rank.get(evt.finding_severity, 99) < sev_rank.get(chain_sev, 99):
                chain_sev = evt.finding_severity

        cats_seen = sorted({evt.category for evt in chain})
        first = chain[0].timestamp
        last = chain[-1].timestamp
        span = (last - first).total_seconds()

        ev_rows = [[
            evt.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            evt.finding_severity,
            evt.category,
            evt.description[:120],
        ] for evt in chain]

        out.append(InvestigationFinding(
            category="timeline_chain",
            title=(f"Correlated event chain: {len(chain)} events in {span:.0f}s "
                   f"across {len(cats_seen)} module(s) ({', '.join(cats_seen)})"),
            severity=chain_sev,
            summary=(f"{len(chain)} forensic events occurred within {window_seconds}s of "
                     f"each other, spanning {span:.0f}s total. This temporal clustering "
                     f"often indicates a single attacker action that touched multiple artefact types."),
            detail=("This finding is produced by the timeline correlator: an automation pass "
                    "that groups events by their proximity in time. The events below come from "
                    "the underlying findings (each one is already evidence-cited there). "
                    "Use the chain to reconstruct the activity sequence — typical patterns: "
                    "USN write → Prefetch first-run → 4688 process create → 4648 explicit creds "
                    "(credential theft pattern)."),
            evidence=[EvidenceSnippet(
                title=f"Chain events ({first} → {last})",
                source="timeline-correlation",
                headers=["timestamp", "severity", "category", "description"],
                rows=ev_rows,
                highlight={"severity"},
            )],
            iocs=[],
            timeline=[(evt.timestamp, evt.description) for evt in chain],
        ))
    return out
