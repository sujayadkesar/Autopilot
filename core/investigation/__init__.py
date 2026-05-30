"""Deterministic forensic investigation engine — automation-first, no LLM."""
from .engine import InvestigationEngine, InvestigationFinding, EvidenceSnippet
from .indicators import KNOWN_CLOUD_DOMAINS, KNOWN_FILESHARING_DOMAINS, KNOWN_HACKTOOLS
from .profiles import CaseProfile, KeywordPrompt, PROFILES, get_profile, list_profiles
from .keyword_search import (
    KeywordHit, search_keywords, hits_to_findings, _normalize_keywords,
)

__all__ = [
    "InvestigationEngine",
    "InvestigationFinding",
    "EvidenceSnippet",
    "KNOWN_CLOUD_DOMAINS",
    "KNOWN_FILESHARING_DOMAINS",
    "KNOWN_HACKTOOLS",
    "CaseProfile",
    "KeywordPrompt",
    "PROFILES",
    "get_profile",
    "list_profiles",
    "KeywordHit",
    "search_keywords",
    "hits_to_findings",
]
