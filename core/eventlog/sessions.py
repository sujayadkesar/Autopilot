"""
sessions.py — logon-session analysis from 4624/4625.

Flags remote-interactive (RDP) logons, network logons from non-local addresses,
NewCredentials logons (runas / overpass-the-hash), and brute-force bursts of 4625
failures. Logon types: 2=Interactive, 3=Network, 4=Batch, 5=Service,
7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive(RDP),
11=CachedInteractive.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Dict, List

_LOGON_TYPE_NAME = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive(RDP)", "11": "CachedInteractive",
}


def _is_external(ip: str) -> bool:
    if not ip or ip in ("-", "::1", "127.0.0.1") or ip.startswith("fe80"):
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_unspecified)
    except ValueError:
        return False


def analyze_sessions(events: List[Dict]):
    from ..investigation.engine import EvidenceSnippet, InvestigationFinding

    findings = []
    rdp_rows, net_ext_rows, newcred_rows = [], [], []
    fail_counter: Counter = Counter()

    for ev in events:
        eid = ev.get("eid")
        pl = ev.get("payload", {}) or {}
        if eid == 4625:
            user = pl.get("TargetUserName", "?")
            ip = pl.get("IpAddress", "-")
            fail_counter[(user, ip)] += 1
            continue
        if eid != 4624:
            continue
        lt = str(pl.get("LogonType", ""))
        user = pl.get("TargetUserName", "")
        if user.lower().endswith("$") or user.upper() in ("SYSTEM", "ANONYMOUS LOGON", ""):
            continue  # skip machine/system noise
        ip = pl.get("IpAddress", "-")
        wks = pl.get("WorkstationName", "")
        ltname = _LOGON_TYPE_NAME.get(lt, lt)
        t = ev.get("time", "")[:19]
        if lt == "10":
            rdp_rows.append([t, user, ip, wks, ltname])
        elif lt == "9":
            newcred_rows.append([t, user, ip, wks, ltname])
        elif lt in ("3", "8") and _is_external(ip):
            net_ext_rows.append([t, user, ip, wks, ltname])

    if rdp_rows:
        findings.append(InvestigationFinding(
            category="lateral_movement",
            title=f"{len(rdp_rows)} RDP (RemoteInteractive) logon(s) recorded",
            severity="HIGH" if any(_is_external(r[2]) for r in rdp_rows) else "MEDIUM",
            summary="Remote-desktop logons were recorded in the Security log.",
            detail="Type-10 logons indicate interactive RDP sessions. Review the source "
                   "addresses and accounts, particularly any external IPs.",
            evidence=[EvidenceSnippet(
                title="RDP logons (EID 4624, LogonType 10)", source="eventlog/security/4624",
                headers=["Time", "User", "Source IP", "Workstation", "Type"],
                rows=rdp_rows[:30], highlight={"Source IP", "User"})],
            attack=["T1021.001"],
        ))

    if net_ext_rows:
        findings.append(InvestigationFinding(
            category="lateral_movement",
            title=f"{len(net_ext_rows)} network logon(s) from external address(es)",
            severity="HIGH",
            summary="Network logons originated from non-private (external) IP addresses.",
            detail="Type-3/8 logons from routable external addresses can indicate inbound "
                   "remote access or exposed services. Cleartext (type 8) is especially notable.",
            evidence=[EvidenceSnippet(
                title="External network logons", source="eventlog/security/4624",
                headers=["Time", "User", "Source IP", "Workstation", "Type"],
                rows=net_ext_rows[:30], highlight={"Source IP"})],
            attack=["T1078", "T1021"],
        ))

    if newcred_rows:
        findings.append(InvestigationFinding(
            category="credential_theft",
            title=f"{len(newcred_rows)} NewCredentials (type 9) logon(s)",
            severity="MEDIUM",
            summary="Type-9 logons (runas /netonly) can indicate credential reuse or overpass-the-hash.",
            detail="NewCredentials logons present alternate credentials to the network while "
                   "keeping the local identity. Correlate with the accounts and times shown.",
            evidence=[EvidenceSnippet(
                title="NewCredentials logons", source="eventlog/security/4624",
                headers=["Time", "User", "Source IP", "Workstation", "Type"],
                rows=newcred_rows[:30], highlight={"User"})],
            attack=["T1550"],
        ))

    brute = [(u, ip, c) for (u, ip), c in fail_counter.items() if c >= 10]
    if brute:
        brute.sort(key=lambda x: x[2], reverse=True)
        findings.append(InvestigationFinding(
            category="credential_theft",
            title=f"Possible brute-force: {len(brute)} account/source pair(s) with ≥10 failures",
            severity="HIGH",
            summary="Repeated failed logons (EID 4625) suggest password-guessing activity.",
            detail="Each row is an account/source-IP pair and its failed-logon count. High "
                   "counts against one account, or one source IP across many accounts, indicate "
                   "brute-force or password-spraying.",
            evidence=[EvidenceSnippet(
                title="Failed-logon concentrations (EID 4625)", source="eventlog/security/4625",
                headers=["Account", "Source IP", "Failures"],
                rows=[[u, ip, str(c)] for u, ip, c in brute[:30]],
                highlight={"Failures"})],
            attack=["T1110"],
        ))

    return findings
