"""
core.eventlog — EventHawk-style deterministic event-log analysis.

Consumes the EvtxECmd CSVs already produced by the event_logs agent and adds a
detection layer beyond Hayabusa's Sigma matches:

  * attack_map  — event-ID → MITRE ATT&CK technique table + tagging
  * powershell  — 4103/4104 scriptblock reassembly + deobfuscation
  * chains      — process-ancestry attack chains (4688 / Sysmon 1)
  * sessions    — logon-session (LUID) reconstruction + anomalies
  * ioc         — regex IOC extraction from event payloads
  * scan        — orchestrates the above into InvestigationFinding objects

Everything is deterministic and runs without the LLM.
"""

from .scan import scan_event_logs
from .attack_map import ATTACK_BY_EID, attack_for_eid

__all__ = ["scan_event_logs", "ATTACK_BY_EID", "attack_for_eid"]
