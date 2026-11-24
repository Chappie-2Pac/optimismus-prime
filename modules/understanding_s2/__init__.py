"""W3-S2 self-describing scope and append-only event-stream evidence."""

from .event_stream import (
    EventStreamArtifact,
    EventStreamBuilder,
    EventStreamConflict,
    EventStreamError,
    EventStreamStore,
    verify_event_stream_artifact,
)
from .scope import (
    ScanScope,
    ScopeArtifact,
    ScopeArtifactConflict,
    ScopeArtifactError,
    ScopeArtifactStore,
    ScopeProvenance,
    verify_scope_artifact,
)

__all__ = [
    "EventStreamArtifact",
    "EventStreamBuilder",
    "EventStreamConflict",
    "EventStreamError",
    "EventStreamStore",
    "ScanScope",
    "ScopeArtifact",
    "ScopeArtifactConflict",
    "ScopeArtifactError",
    "ScopeArtifactStore",
    "ScopeProvenance",
    "verify_event_stream_artifact",
    "verify_scope_artifact",
]
