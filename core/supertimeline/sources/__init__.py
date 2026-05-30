"""
Per-artefact ingesters that transform parsed CSVs/JSONLs into supertimeline events.

Each ingester is a callable: `ingest(parsed_dir: Path) -> Iterator[Event]`.
They are registered in INGESTERS so the orchestrator can iterate cheaply.
"""

from .common import Event, INGESTERS, register, ingest_all

# Import each module — each one calls @register on import to add itself.
from . import (  # noqa: F401  pylint: disable=unused-import
    usn_journal,
    prefetch,
    amcache,
    mft,
    lnk_recent,
    mru,
    registry_artifacts,
    browser,
    event_logs,
    pca_launches,
    scheduled_tasks,
    wer_crashes,
    shellbags,
    jumplists,
)

__all__ = ["Event", "INGESTERS", "register", "ingest_all"]
