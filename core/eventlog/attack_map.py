"""
attack_map.py — Windows Event ID → MITRE ATT&CK technique mapping.

A curated, conservative mapping used to tag event-derived findings with technique
IDs (feeds the report's ATT&CK pills and the Navigator-layer export). Mapping a
raw event ID is inherently coarse; the technique reflects the most common reason
an analyst cares about that event, not a guarantee of malicious intent.
"""

from __future__ import annotations

from typing import Dict, List

# Security / System / PowerShell channel event IDs
ATTACK_BY_EID: Dict[int, List[str]] = {
    # Authentication / logon
    4624: ["T1078"],            # Valid Accounts (successful logon)
    4625: ["T1110"],            # Brute Force (failed logon)
    4648: ["T1078", "T1550"],   # Explicit-cred logon / pass-the-*
    4768: ["T1558"],            # Kerberos TGT request (AS-REP / golden)
    4769: ["T1558.003"],        # Kerberoasting (service ticket)
    4771: ["T1110"],            # Kerberos pre-auth failed
    4776: ["T1110"],            # NTLM credential validation
    4672: ["T1078.003"],        # Special privileges (admin logon)
    # Account management
    4720: ["T1136"],            # Create account
    4722: ["T1098"],            # Account enabled
    4728: ["T1098"],            # Added to global group
    4732: ["T1098"],            # Added to local group (admins)
    4738: ["T1098"],            # Account changed
    4740: ["T1531"],            # Account lockout
    # Service / driver
    7045: ["T1543.003"],        # New service install
    7034: ["T1543.003"],        # Service crashed (possible abuse)
    # Scheduled tasks
    4698: ["T1053.005"],        # Scheduled task created
    4702: ["T1053.005"],        # Scheduled task updated
    # Process creation
    4688: ["T1059"],            # New process (command interpreter)
    # PowerShell
    4103: ["T1059.001"],        # PS module logging
    4104: ["T1059.001", "T1027"],  # PS scriptblock (often obfuscated)
    # Log tampering
    1102: ["T1070.001"],        # Security log cleared
    1100: ["T1070"],            # Event logging service shut down
    104:  ["T1070.001"],        # System/other log cleared
    # Defender
    1116: ["T1059"],            # Defender malware detected
    1117: ["T1059"],            # Defender action taken
    # WMI
    5861: ["T1546.003"],        # WMI permanent event subscription
    # BITS
    3:    ["T1071"],            # (Sysmon network) — see sysmon map below
}

# Sysmon channel uses its own small event-ID space; keep separate to avoid
# colliding with Security-channel IDs of the same number.
SYSMON_ATTACK_BY_EID: Dict[int, List[str]] = {
    1:  ["T1059"],              # Process create
    3:  ["T1071"],              # Network connection
    7:  ["T1574.002"],         # Image/DLL load (sideloading)
    8:  ["T1055"],              # CreateRemoteThread (injection)
    10: ["T1003.001"],         # ProcessAccess (LSASS read)
    11: ["T1105"],              # File create
    12: ["T1112"],              # Registry create/delete
    13: ["T1112"],              # Registry value set
    15: ["T1564.004"],         # Alternate Data Stream created
    22: ["T1071.004"],         # DNS query
    23: ["T1070.004"],         # File delete (archived)
    25: ["T1055"],             # Process tampering
}


def attack_for_eid(eid: int, channel: str = "") -> List[str]:
    """Return ATT&CK technique IDs for an event ID, channel-aware for Sysmon."""
    if "sysmon" in (channel or "").lower():
        return SYSMON_ATTACK_BY_EID.get(eid, [])
    return ATTACK_BY_EID.get(eid, [])
