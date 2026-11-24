"""W4-S0 bounded small-loop evidence verification."""

from .authority import configure_trusted_authority, freeze_trusted_authorities
from .models import VerificationResult, W4EvidenceError, W4IncompatibleSource
from .tool_circuit import verify_tool_trace
from .verifier import verify_small_loop_bundle
from .w25_compat import canonical_attempt_state_hash, canonical_hash, canonical_json, reconstruct_receipt_hashes

__all__ = [
    "VerificationResult",
    "configure_trusted_authority",
    "freeze_trusted_authorities",
    "W4EvidenceError",
    "W4IncompatibleSource",
    "canonical_attempt_state_hash",
    "canonical_hash",
    "canonical_json",
    "reconstruct_receipt_hashes",
    "verify_small_loop_bundle",
    "verify_tool_trace",
]
