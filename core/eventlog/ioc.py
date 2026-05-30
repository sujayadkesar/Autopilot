"""
ioc.py — extract indicators of compromise from event payloads.

Field-targeted extraction (rather than scanning every payload byte) keeps noise
low: network destinations from Sysmon 3/22, hashes from Sysmon file events, and
URLs/IPs from command lines and script blocks.
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Dict, List, Tuple

_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b(?:SHA256|SHA1|MD5|IMPHASH)=([0-9a-fA-F]{32,64})", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

_BENIGN_DOMAINS = (
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "msftconnecttest.com", "office.com", "live.com", "bing.com", "msn.com",
    "digicert.com", "verisign.com", "akamai", "azureedge.net", "windows.net",
)


def _external_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_unspecified or a.is_reserved)
    except ValueError:
        return False


def _benign_domain(d: str) -> bool:
    dl = d.lower()
    return any(b in dl for b in _BENIGN_DOMAINS)


def extract_iocs(events: List[Dict]) -> Tuple[List, Dict[str, List[str]]]:
    """Return (findings, ioc_dict) where ioc_dict maps type → sorted list."""
    from ..investigation.engine import EvidenceSnippet, InvestigationFinding

    ips: "OrderedDict[str, None]" = OrderedDict()
    domains: "OrderedDict[str, None]" = OrderedDict()
    urls: "OrderedDict[str, None]" = OrderedDict()
    hashes: "OrderedDict[str, None]" = OrderedDict()

    for ev in events:
        pl = ev.get("payload", {}) or {}
        # Network destinations
        for k in ("DestinationIp", "DestinationIP"):
            v = pl.get(k)
            if v and _external_ip(str(v)):
                ips[str(v)] = None
        for k in ("DestinationHostname", "QueryName"):
            v = pl.get(k)
            if v and "." in str(v) and not _benign_domain(str(v)):
                domains[str(v).lower().rstrip(".")] = None
        # Hashes
        hv = pl.get("Hashes") or ""
        for m in _HASH_RE.finditer(str(hv)):
            hashes[m.group(1).lower()] = None
        # URLs / IPs / hashes embedded in command lines & script blocks
        for k in ("CommandLine", "ProcessCommandLine", "ScriptBlockText", "ParentCommandLine"):
            text = str(pl.get(k) or "")
            if not text:
                continue
            for m in _URL_RE.finditer(text):
                urls[m.group(0).rstrip(".,);")] = None
            for m in _IPV4_RE.finditer(text):
                if _external_ip(m.group(0)):
                    ips[m.group(0)] = None
            for m in _HASH_RE.finditer(text):
                hashes[m.group(1).lower()] = None

    ioc_dict = {
        "ip": list(ips), "domain": list(domains),
        "url": list(urls), "hash": list(hashes),
    }
    total = sum(len(v) for v in ioc_dict.values())
    if total == 0:
        return [], ioc_dict

    rows = []
    for typ, vals in ioc_dict.items():
        for v in vals[:40]:
            rows.append([typ, v])

    findings = [InvestigationFinding(
        category="ioc_extraction",
        title=f"{total} indicator(s) of compromise extracted from event logs",
        severity="INFO",
        summary="Network destinations, URLs, and hashes were auto-extracted from event payloads.",
        detail="These indicators were parsed from Sysmon network/file events and from "
               "command-line/script-block fields. Benign Microsoft destinations are excluded. "
               "Use them to pivot across other artifacts and threat-intel sources.",
        evidence=[EvidenceSnippet(
            title="Extracted indicators", source="eventlog/ioc",
            headers=["Type", "Indicator"], rows=rows[:120], highlight={"Indicator"})],
        iocs=[f"{t}:{v}" for t, vals in ioc_dict.items() for v in vals[:40]],
    )]
    return findings, ioc_dict
