"""W3-S0 read-only project-understanding harness.

This package is deliberately disjoint from the Prime runtime.  It registers
approved source scopes, scans them without following links or starting
processes, and emits hash-bound observations into an explicit output domain.
"""

from .model import (
    Coverage,
    DeniedEntry,
    FileRecord,
    ProjectProfile,
    ScanEvent,
    ScanResult,
    SourceManifest,
    SourceSpec,
)
from .registry import UnderstandingRegistry
from .scanner import ReadOnlyScanner

__all__ = [
    "Coverage",
    "DeniedEntry",
    "FileRecord",
    "ProjectProfile",
    "ReadOnlyScanner",
    "ScanEvent",
    "ScanResult",
    "SourceManifest",
    "SourceSpec",
    "UnderstandingRegistry",
]
