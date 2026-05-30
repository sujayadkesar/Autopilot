"""
AgentRegistry — auto-discovers agents under agents/<name>/manifest.yaml.
Agents are loaded lazily (manifest only on cold start, full import on first use).
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

import yaml

from .base_agent import BaseAgent

log = logging.getLogger("dfir.registry")

_AGENTS_DIR = Path(__file__).parent.parent / "agents"


def _load_manifests() -> Dict[str, dict]:
    manifests: Dict[str, dict] = {}
    for manifest_path in sorted(_AGENTS_DIR.glob("*/manifest.yaml")):
        agent_name = manifest_path.parent.name
        if agent_name.startswith("_"):
            continue
        try:
            with open(manifest_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            data["_dir"] = manifest_path.parent
            data["_name"] = agent_name
            manifests[agent_name] = data
        except Exception as e:
            log.warning("Could not load manifest for %s: %s", agent_name, e)
    return manifests


_manifests: Optional[Dict[str, dict]] = None
_agent_classes: Dict[str, Type[BaseAgent]] = {}


def get_all_manifests() -> Dict[str, dict]:
    global _manifests
    if _manifests is None:
        _manifests = _load_manifests()
    return _manifests


def get_agent_class(name: str) -> Type[BaseAgent]:
    if name in _agent_classes:
        return _agent_classes[name]
    manifests = get_all_manifests()
    if name not in manifests:
        raise KeyError(f"Agent '{name}' not found. Available: {list(manifests.keys())}")
    try:
        module = importlib.import_module(f"agents.{name}.agent")
        cls = getattr(module, "Agent")
        _agent_classes[name] = cls
        return cls
    except Exception as e:
        raise ImportError(f"Could not load agent '{name}': {e}") from e


def load_enabled(enabled: List[str]) -> List[BaseAgent]:
    agents: List[BaseAgent] = []
    for name in enabled:
        try:
            cls = get_agent_class(name)
            agents.append(cls())
        except Exception as e:
            log.error("Failed to load agent '%s': %s", name, e)
    return agents


def list_agents() -> List[dict]:
    """Return a list of agent metadata dicts for display."""
    result = []
    for name, manifest in get_all_manifests().items():
        result.append({
            "name": name,
            "display_name": manifest.get("display_name", name),
            "description": manifest.get("description", ""),
            "version": manifest.get("version", "1.0"),
            "enabled_by_default": manifest.get("enabled_by_default", True),
        })
    return result
