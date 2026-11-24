"""Independent inline fixtures for the W5-S25AF source-span boundary."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25af_source_span_closure as s25af  # noqa: E402


_SOURCE_TEXT = "Alpha β🙂.\r\nGamma e\u0301ta.\nhttps://example.invalid/path\nOmega."
_SOURCE_ID = "fixture.unicode-overlap"
_MANUAL_SOURCE_ID = "fixture.manual-golden"
_MANUAL_SOURCE_HASH = "da0ecd65db3179ccf531d2a45f8ab743e574f430898dddac8bc584aec884d909"
_MANUAL_CLOSURE_DIGEST = "907c2031150a5927d678da26f9a6f8d284ea7f98f1791e29818e9d94365f5b7c"
_MANUAL_INPUT_DIGEST = "2ec8a52d56853f1d9524247e5b75df04b41523200450862a65f9cbe3c52a0dd3"


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _source_hash(source_text: str) -> str:
    return hashlib.sha256(source_text.encode("utf-8")).hexdigest()


def _closure_digest(
    source_id: str,
    source_sha256: str,
    coverage_start: int,
    coverage_end: int,
    max_overlap_chars: int,
    chunks: list[dict[str, object]],
) -> str:
    return _digest(
        {
            "schema": "w5.s25af.source-span-closure-witness.v1",
            "closure_scope": "SOURCE_SPAN_CONTENT_CLOSURE_ONLY",
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
    )


@lru_cache(maxsize=None)
def _cached_case(variant: str) -> dict[str, object]:
    if variant == "no_overlap":
        ranges = ((0, len(_SOURCE_TEXT) // 2), (len(_SOURCE_TEXT) // 2, len(_SOURCE_TEXT)))
        max_overlap = 0
    elif variant == "overlap_limit":
        split = len(_SOURCE_TEXT) // 2
        ranges = ((0, split + 2), (split, len(_SOURCE_TEXT)))
        max_overlap = 2
    elif variant == "three_chunks":
        first = len(_SOURCE_TEXT) // 3
        second = (2 * len(_SOURCE_TEXT)) // 3
        ranges = ((0, first + 1), (first - 1, second + 1), (second - 1, len(_SOURCE_TEXT)))
        max_overlap = 2
    else:
        raise ValueError(f"unknown S25AF fixture: {variant!r}")

    source_sha256 = _source_hash(_SOURCE_TEXT)
    total = len(ranges)
    chunks = [
        {
            "source_id": _SOURCE_ID,
            "source_sha256": source_sha256,
            "chunk_index": index,
            "chunk_total": total,
            "char_start": start,
            "char_end": end,
            "text": _SOURCE_TEXT[start:end],
        }
        for index, (start, end) in enumerate(ranges, start=1)
    ]
    case: dict[str, object] = {
        "schema_version": "s25af.source-span-closure.v1",
        "observation_mode": "TEST_ONLY",
        "canonicalization": "UTF8_CODEPOINT_HALF_OPEN_EXACT_V1",
        "expected": {
            "source_id": _SOURCE_ID,
            "source_sha256": source_sha256,
            "chunk_total": total,
            "coverage_start": 0,
            "coverage_end": len(_SOURCE_TEXT),
            "max_overlap_chars": max_overlap,
            "closure_digest": _closure_digest(
                _SOURCE_ID,
                source_sha256,
                0,
                len(_SOURCE_TEXT),
                max_overlap,
                chunks,
            ),
        },
        "source": {
            "source_id": _SOURCE_ID,
            "source_text": _SOURCE_TEXT,
            "source_sha256": source_sha256,
        },
        "chunks": chunks,
        "input_digest": "",
    }
    case["input_digest"] = _digest({key: value for key, value in case.items() if key != "input_digest"})
    return case


@lru_cache(maxsize=None)
def _manual_golden_case() -> dict[str, object]:
    """Return a literal golden case with independently fixed digests."""

    chunks = [
        {
            "source_id": _MANUAL_SOURCE_ID,
            "source_sha256": _MANUAL_SOURCE_HASH,
            "chunk_index": 1,
            "chunk_total": 4,
            "char_start": 0,
            "char_end": 11,
            "text": "Alpha β🙂.\r\n",
        },
        {
            "source_id": _MANUAL_SOURCE_ID,
            "source_sha256": _MANUAL_SOURCE_HASH,
            "chunk_index": 2,
            "chunk_total": 4,
            "char_start": 11,
            "char_end": 23,
            "text": "Gamma e\u0301ta.\n",
        },
        {
            "source_id": _MANUAL_SOURCE_ID,
            "source_sha256": _MANUAL_SOURCE_HASH,
            "chunk_index": 3,
            "chunk_total": 4,
            "char_start": 23,
            "char_end": 52,
            "text": "https://example.invalid/path\n",
        },
        {
            "source_id": _MANUAL_SOURCE_ID,
            "source_sha256": _MANUAL_SOURCE_HASH,
            "chunk_index": 4,
            "chunk_total": 4,
            "char_start": 52,
            "char_end": 58,
            "text": "Omega.",
        },
    ]
    return {
        "schema_version": "s25af.source-span-closure.v1",
        "observation_mode": "TEST_ONLY",
        "canonicalization": "UTF8_CODEPOINT_HALF_OPEN_EXACT_V1",
        "expected": {
            "source_id": _MANUAL_SOURCE_ID,
            "source_sha256": _MANUAL_SOURCE_HASH,
            "chunk_total": 4,
            "coverage_start": 0,
            "coverage_end": 58,
            "max_overlap_chars": 0,
            "closure_digest": _MANUAL_CLOSURE_DIGEST,
        },
        "source": {
            "source_id": _MANUAL_SOURCE_ID,
            "source_text": _SOURCE_TEXT,
            "source_sha256": _MANUAL_SOURCE_HASH,
        },
        "chunks": chunks,
        "input_digest": _MANUAL_INPUT_DIGEST,
    }


def build_positive_s25af_case(variant: str = "no_overlap") -> dict[str, object]:
    """Return a fresh positive fixture made without the support oracle."""

    if variant == "manual_golden":
        return deepcopy(_manual_golden_case())
    return deepcopy(_cached_case(variant))


class W5S25AFFixtureFoundationTests(unittest.TestCase):
    def test_positive_variants_are_unpatched_and_distinct(self) -> None:
        cases = {
            name: build_positive_s25af_case(name)
            for name in ("no_overlap", "overlap_limit", "three_chunks", "manual_golden")
        }
        outputs = {name: s25af.evaluate_source_span_closure(case) for name, case in cases.items()}
        self.assertEqual({output["classification"] for output in outputs.values()}, {"SOURCE_SPAN_CLOSED"})
        self.assertEqual({output["status"] for output in outputs.values()}, {"PROPOSAL_ONLY"})
        self.assertEqual(len({case["input_digest"] for case in cases.values()}), 4)
        self.assertEqual(len({output["closure_digest"] for output in outputs.values()}), 4)

    def test_literal_golden_digest_and_offsets_are_independent(self) -> None:
        case = build_positive_s25af_case("manual_golden")
        self.assertEqual(case["input_digest"], _MANUAL_INPUT_DIGEST)
        self.assertEqual(case["expected"]["closure_digest"], _MANUAL_CLOSURE_DIGEST)
        self.assertEqual(s25af.evaluate_source_span_closure(case)["classification"], "SOURCE_SPAN_CLOSED")

    def test_fixture_contains_unicode_whitespace_and_uri_as_opaque_content(self) -> None:
        case = build_positive_s25af_case("three_chunks")
        self.assertIn("β🙂", case["source"]["source_text"])
        self.assertIn("\r\n", case["source"]["source_text"])
        self.assertIn("https://example.invalid/path", case["source"]["source_text"])
        self.assertIn("e\u0301", case["source"]["source_text"])
        self.assertEqual(s25af.evaluate_source_span_closure(case)["classification"], "SOURCE_SPAN_CLOSED")

    def test_unknown_fixture_is_rejected_before_construction(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25af_case("unknown")


if __name__ == "__main__":
    unittest.main()
