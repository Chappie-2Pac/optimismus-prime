"""Pure S25AF source-span content closure.

This support boundary evaluates an inline source and an ordered set of exact
Unicode half-open slices.  It deliberately does not read a path or reuse the
Chappie producer/cleaner: a positive result is only a self-consistent,
read-only content-span witness.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


HARNESS_SCHEMA = "s25af.source-span-closure.v1"
OBSERVATION_MODE = "TEST_ONLY"
CANONICALIZATION = "UTF8_CODEPOINT_HALF_OPEN_EXACT_V1"
CLOSURE_SCOPE = "SOURCE_SPAN_CONTENT_CLOSURE_ONLY"

SOURCE_SPAN_CLOSED = "SOURCE_SPAN_CLOSED"
SOURCE_SPAN_GAP = "SOURCE_SPAN_GAP"
SOURCE_SPAN_OVERLAP_INVALID = "SOURCE_SPAN_OVERLAP_INVALID"
SOURCE_SPAN_TEXT_MISMATCH = "SOURCE_SPAN_TEXT_MISMATCH"
SOURCE_SPAN_HASH_MISMATCH = "SOURCE_SPAN_HASH_MISMATCH"
SOURCE_SPAN_INDEX_INVALID = "SOURCE_SPAN_INDEX_INVALID"
INPUT_INVALID = "INPUT_INVALID"

PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

_HASH64 = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ZERO_HASH = "0" * 64

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 10_000
MAX_CONTAINER_ITEMS = 512
MAX_STRING = 65_536
MAX_SOURCE_CHARS = 65_536
MAX_CHUNKS = 256
MAX_INTEGER = 2**63 - 1

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "source",
        "chunks",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "source_id",
        "source_sha256",
        "chunk_total",
        "coverage_start",
        "coverage_end",
        "max_overlap_chars",
        "closure_digest",
    }
)
_SOURCE_KEYS = frozenset({"source_id", "source_text", "source_sha256"})
_CHUNK_KEYS = frozenset(
    {"source_id", "source_sha256", "chunk_index", "chunk_total", "char_start", "char_end", "text"}
)
_INTERVAL_KEYS = frozenset({"chunk_index", "char_start", "char_end", "overlap_from_previous"})
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "closure_scope",
        "source_id",
        "source_sha256",
        "chunk_total",
        "coverage_start",
        "coverage_end",
        "max_overlap_chars",
        "intervals",
        "closure_digest",
        "production_status",
        "authority_claim",
    }
)
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _source_hash(source_text: str) -> str:
    return hashlib.sha256(source_text.encode("utf-8")).hexdigest()


def _parse(value: dict[str, Any] | bytes | str) -> Any:
    if type(value) is dict:
        return value
    if type(value) is bytes:
        if len(value) > MAX_INPUT_BYTES:
            raise ValueError("input too large")
        return json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_INPUT_BYTES:
            raise ValueError("input too large")
        return json.loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    raise TypeError("case must be a built-in dict, JSON bytes or JSON string")


def _snapshot(value: Any, *, depth: int = 0, active: set[int] | None = None, budget: list[int] | None = None) -> Any:
    if depth > MAX_DEPTH:
        raise ValueError("value too deep")
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_NODES:
        raise ValueError("value too large")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_INTEGER:
            raise ValueError("integer out of range")
        return value
    if type(value) is str:
        if len(value) > MAX_STRING or any("\ud800" <= char <= "\udfff" for char in value):
            raise ValueError("unsafe string")
        return value
    if type(value) not in (dict, list):
        raise ValueError("unsupported value")
    if active is None:
        active = set()
    marker = id(value)
    if marker in active:
        raise ValueError("recursive value")
    active.add(marker)
    try:
        if type(value) is dict:
            if len(value) > MAX_CONTAINER_ITEMS:
                raise ValueError("mapping too large")
            result: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str or len(key) > 256 or key in result:
                    raise ValueError("invalid mapping key")
                result[key] = _snapshot(item, depth=depth + 1, active=active, budget=budget)
            return result
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("sequence too large")
        return [_snapshot(item, depth=depth + 1, active=active, budget=budget) for item in value]
    finally:
        active.remove(marker)


def _exact(value: Any, keys: frozenset[str]) -> bool:
    return type(value) is dict and set(value) == set(keys)


def _hash(value: Any) -> bool:
    return type(value) is str and _HASH64.fullmatch(value) is not None


def _integer(value: Any, *, minimum: int | None = None, maximum: int | None = None) -> bool:
    if type(value) is not int:
        return False
    return (minimum is None or value >= minimum) and (maximum is None or value <= maximum)


def _text(value: Any, *, maximum: int = MAX_STRING) -> bool:
    return (
        type(value) is str
        and len(value) <= maximum
        and not any("\ud800" <= char <= "\udfff" for char in value)
    )


def _source_id(value: Any) -> bool:
    return type(value) is str and _SOURCE_ID.fullmatch(value) is not None


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    source_id: str = "",
    source_sha256: str = _ZERO_HASH,
    chunk_total: int = 0,
    coverage_start: int = 0,
    coverage_end: int = 0,
    max_overlap_chars: int = 0,
    intervals: list[dict[str, int]] | None = None,
    closure_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVATION_MODE,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "closure_scope": CLOSURE_SCOPE,
        "source_id": source_id if _source_id(source_id) else "",
        "source_sha256": source_sha256 if _hash(source_sha256) else _ZERO_HASH,
        "chunk_total": chunk_total if _integer(chunk_total, minimum=0, maximum=MAX_CHUNKS) else 0,
        "coverage_start": coverage_start if _integer(coverage_start, minimum=0, maximum=MAX_SOURCE_CHARS) else 0,
        "coverage_end": coverage_end if _integer(coverage_end, minimum=0, maximum=MAX_SOURCE_CHARS) else 0,
        "max_overlap_chars": max_overlap_chars
        if _integer(max_overlap_chars, minimum=0, maximum=MAX_SOURCE_CHARS)
        else 0,
        "intervals": [
            {
                "chunk_index": item["chunk_index"],
                "char_start": item["char_start"],
                "char_end": item["char_end"],
                "overlap_from_previous": item["overlap_from_previous"],
            }
            for item in (intervals or [])
        ],
        "closure_digest": closure_digest if _hash(closure_digest) else _ZERO_HASH,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(
    reason: str,
    *,
    classification: str,
    source_id: str = "",
    source_sha256: str = _ZERO_HASH,
    chunk_total: int = 0,
    coverage_start: int = 0,
    coverage_end: int = 0,
    max_overlap_chars: int = 0,
    intervals: list[dict[str, int]] | None = None,
    closure_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return _result(
        classification,
        TEST_BLOCKED,
        HOLD,
        reason,
        source_id=source_id,
        source_sha256=source_sha256,
        chunk_total=chunk_total,
        coverage_start=coverage_start,
        coverage_end=coverage_end,
        max_overlap_chars=max_overlap_chars,
        intervals=intervals,
        closure_digest=closure_digest,
    )


def _closure_preimage(
    source_id: str,
    source_sha256: str,
    coverage_start: int,
    coverage_end: int,
    max_overlap_chars: int,
    chunks: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "w5.s25af.source-span-closure-witness.v1",
        "closure_scope": CLOSURE_SCOPE,
        "source_id": source_id,
        "source_sha256": source_sha256,
        "coverage_start": coverage_start,
        "coverage_end": coverage_end,
        "max_overlap_chars": max_overlap_chars,
        "chunks": [
            {
                "chunk_index": chunk["chunk_index"],
                "chunk_total": chunk["chunk_total"],
                "char_start": chunk["char_start"],
                "char_end": chunk["char_end"],
                "text": chunk["text"],
            }
            for chunk in chunks
        ],
    }


def _intervals(chunks: list[dict[str, Any]]) -> list[dict[str, int]]:
    intervals: list[dict[str, int]] = []
    previous_end: int | None = None
    for chunk in chunks:
        start = chunk["char_start"]
        end = chunk["char_end"]
        overlap = 0 if previous_end is None else max(0, previous_end - start)
        intervals.append(
            {
                "chunk_index": chunk["chunk_index"],
                "char_start": start,
                "char_end": end,
                "overlap_from_previous": overlap,
            }
        )
        previous_end = end
    return intervals


def _evaluate(case: dict[str, Any] | bytes | str) -> dict[str, Any]:
    try:
        snapshot = _snapshot(_parse(case))
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")
    if not _exact(snapshot, _TOP_LEVEL):
        return _invalid("CASE_SCHEMA_NOT_EXACT")
    if (
        snapshot.get("schema_version") != HARNESS_SCHEMA
        or snapshot.get("observation_mode") != OBSERVATION_MODE
        or snapshot.get("canonicalization") != CANONICALIZATION
    ):
        return _invalid("CASE_PROFILE_INVALID")
    try:
        expected_input_digest = input_digest(snapshot)
    except Exception:
        return _invalid("CASE_DIGEST_UNREADABLE")
    if not _hash(snapshot.get("input_digest")) or snapshot["input_digest"] != expected_input_digest:
        return _invalid("CASE_DIGEST_DRIFT")

    expected = snapshot.get("expected")
    source = snapshot.get("source")
    chunks = snapshot.get("chunks")
    if not _exact(expected, _EXPECTED_KEYS) or not _exact(source, _SOURCE_KEYS) or type(chunks) is not list:
        return _invalid("CASE_CHILD_SCHEMA_INVALID")
    if not _source_id(source.get("source_id")) or not _hash(source.get("source_sha256")):
        return _invalid("SOURCE_PROFILE_INVALID")
    if not _text(source.get("source_text"), maximum=MAX_SOURCE_CHARS) or source["source_text"] == "":
        return _invalid("SOURCE_TEXT_INVALID")
    source_id = source["source_id"]
    source_text = source["source_text"]
    source_hash = source["source_sha256"]
    if _source_hash(source_text) != source_hash:
        return _blocked(
            "SOURCE_HASH_MISMATCH",
            classification=SOURCE_SPAN_HASH_MISMATCH,
            source_id=source_id,
            source_sha256=source_hash,
        )

    expected_fields = (
        expected.get("source_id"),
        expected.get("source_sha256"),
        expected.get("chunk_total"),
        expected.get("coverage_start"),
        expected.get("coverage_end"),
        expected.get("max_overlap_chars"),
        expected.get("closure_digest"),
    )
    if (
        expected_fields[0] != source_id
        or expected_fields[1] != source_hash
        or not _integer(expected_fields[2], minimum=1, maximum=MAX_CHUNKS)
        or not _integer(expected_fields[3], minimum=0, maximum=MAX_SOURCE_CHARS)
        or not _integer(expected_fields[4], minimum=0, maximum=MAX_SOURCE_CHARS)
        or not _integer(expected_fields[5], minimum=0, maximum=MAX_SOURCE_CHARS)
        or not _hash(expected_fields[6])
    ):
        return _invalid("EXPECTED_BINDING_INVALID")
    chunk_total = expected_fields[2]
    coverage_start = expected_fields[3]
    coverage_end = expected_fields[4]
    max_overlap_chars = expected_fields[5]
    expected_closure_digest = expected_fields[6]
    if (
        coverage_start != 0
        or coverage_end != len(source_text)
        or chunk_total != len(chunks)
        or len(chunks) == 0
        or len(chunks) > MAX_CHUNKS
    ):
        return _blocked(
            "CHUNK_COUNT_OR_COVERAGE_INVALID",
            classification=SOURCE_SPAN_INDEX_INVALID,
            source_id=source_id,
            source_sha256=source_hash,
            chunk_total=chunk_total,
            coverage_start=coverage_start,
            coverage_end=coverage_end,
            max_overlap_chars=max_overlap_chars,
        )

    normalized_chunks: list[dict[str, Any]] = []
    for chunk in chunks:
        if not _exact(chunk, _CHUNK_KEYS):
            return _invalid("CHUNK_SCHEMA_INVALID")
        if chunk.get("source_id") != source_id or chunk.get("source_sha256") != source_hash:
            return _blocked(
                "CHUNK_SOURCE_BINDING_MISMATCH",
                classification=SOURCE_SPAN_HASH_MISMATCH,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )
        if (
            not _integer(chunk.get("chunk_index"), minimum=1, maximum=MAX_CHUNKS)
            or not _integer(chunk.get("chunk_total"), minimum=1, maximum=MAX_CHUNKS)
            or not _integer(chunk.get("char_start"), minimum=0, maximum=MAX_SOURCE_CHARS)
            or not _integer(chunk.get("char_end"), minimum=0, maximum=MAX_SOURCE_CHARS)
            or not _text(chunk.get("text"))
        ):
            return _blocked(
                "CHUNK_INDEX_OR_BOUNDS_INVALID",
                classification=SOURCE_SPAN_INDEX_INVALID,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )
        normalized_chunks.append(
            {
                "source_id": chunk["source_id"],
                "source_sha256": chunk["source_sha256"],
                "chunk_index": chunk["chunk_index"],
                "chunk_total": chunk["chunk_total"],
                "char_start": chunk["char_start"],
                "char_end": chunk["char_end"],
                "text": chunk["text"],
            }
        )

    for position, chunk in enumerate(normalized_chunks, start=1):
        if chunk["chunk_index"] != position or chunk["chunk_total"] != chunk_total:
            return _blocked(
                "CHUNK_INDEX_SEQUENCE_INVALID",
                classification=SOURCE_SPAN_INDEX_INVALID,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )
        if not (0 <= chunk["char_start"] < chunk["char_end"] <= len(source_text)):
            return _blocked(
                "CHUNK_BOUNDS_INVALID",
                classification=SOURCE_SPAN_INDEX_INVALID,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )

    for chunk in normalized_chunks:
        if source_text[chunk["char_start"] : chunk["char_end"]] != chunk["text"]:
            return _blocked(
                "CHUNK_TEXT_MISMATCH",
                classification=SOURCE_SPAN_TEXT_MISMATCH,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )

    if normalized_chunks[0]["char_start"] != coverage_start or normalized_chunks[-1]["char_end"] != coverage_end:
        return _blocked(
            "COVERAGE_GAP",
            classification=SOURCE_SPAN_GAP,
            source_id=source_id,
            source_sha256=source_hash,
            chunk_total=chunk_total,
            coverage_start=coverage_start,
            coverage_end=coverage_end,
            max_overlap_chars=max_overlap_chars,
        )

    for previous, current in zip(normalized_chunks, normalized_chunks[1:]):
        if current["char_start"] > previous["char_end"]:
            return _blocked(
                "COVERAGE_GAP",
                classification=SOURCE_SPAN_GAP,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )
        overlap = max(0, previous["char_end"] - current["char_start"])
        if current["char_start"] <= previous["char_start"] or current["char_end"] <= previous["char_end"]:
            return _blocked(
                "OVERLAP_ORDER_INVALID",
                classification=SOURCE_SPAN_OVERLAP_INVALID,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )
        if overlap > max_overlap_chars:
            return _blocked(
                "OVERLAP_LIMIT_EXCEEDED",
                classification=SOURCE_SPAN_OVERLAP_INVALID,
                source_id=source_id,
                source_sha256=source_hash,
                chunk_total=chunk_total,
                coverage_start=coverage_start,
                coverage_end=coverage_end,
                max_overlap_chars=max_overlap_chars,
            )

    intervals = _intervals(normalized_chunks)
    actual_closure_digest = _digest(
        _closure_preimage(
            source_id,
            source_hash,
            coverage_start,
            coverage_end,
            max_overlap_chars,
            normalized_chunks,
        )
    )
    if expected_closure_digest != actual_closure_digest:
        return _invalid("CLOSURE_DIGEST_DRIFT")
    return _result(
        SOURCE_SPAN_CLOSED,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "SELF_CONSISTENT_INLINE_SOURCE_SPAN_CLOSURE",
        source_id=source_id,
        source_sha256=source_hash,
        chunk_total=chunk_total,
        coverage_start=coverage_start,
        coverage_end=coverage_end,
        max_overlap_chars=max_overlap_chars,
        intervals=intervals,
        closure_digest=actual_closure_digest,
    )


def evaluate_source_span_closure(case: dict[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic, self-consistency-only source-span witness."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def input_digest(case: dict[str, Any]) -> str:
    """Return the canonical digest of a case without its outer digest field."""

    snapshot = _snapshot(case)
    if type(snapshot) is not dict:
        raise ValueError("case must be a built-in dict")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


__all__ = [
    "CANONICALIZATION",
    "CLOSURE_SCOPE",
    "DESIGN_ONLY",
    "HARNESS_SCHEMA",
    "HOLD",
    "INPUT_INVALID",
    "MAX_CHUNKS",
    "NOT_CLAIMED",
    "OBSERVATION_MODE",
    "PRODUCTION_NOT_AUTHORIZED",
    "PROPOSAL_ONLY",
    "RESULT_KEYS",
    "SOURCE_SPAN_CLOSED",
    "SOURCE_SPAN_GAP",
    "SOURCE_SPAN_HASH_MISMATCH",
    "SOURCE_SPAN_INDEX_INVALID",
    "SOURCE_SPAN_OVERLAP_INVALID",
    "SOURCE_SPAN_TEXT_MISMATCH",
    "TEST_BLOCKED",
    "evaluate_source_span_closure",
    "input_digest",
]
