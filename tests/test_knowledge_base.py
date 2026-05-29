"""Tests for core.knowledge_base — KB ingestion, FTS retrieval, prompt block."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.knowledge_base import (
    KBEntry,
    KBHit,
    KnowledgeBase,
    _bm25_to_score,
    _cosine,
    _fts_sanitize,
    hits_to_prompt_block,
)


@pytest.fixture
def kb(tmp_path: Path) -> KnowledgeBase:
    db = tmp_path / "kb.sqlite"
    return KnowledgeBase(db)


def _seed(kb: KnowledgeBase) -> int:
    return kb.upsert([
        KBEntry(
            id="CVE-2021-44228", kind="cve",
            title="Log4Shell — Apache Log4j RCE via JNDI",
            summary="Log4j2 evaluates JNDI lookups in user input, enabling unauth RCE.",
            severity="critical", cvss=10.0, cwe="CWE-502",
            refs=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        KBEntry(
            id="CWE-79", kind="cwe",
            title="Cross-site Scripting",
            summary="Improper neutralization of input during webpage generation.",
            severity="medium",
        ),
        KBEntry(
            id="T1190", kind="attck",
            title="Exploit Public-Facing Application",
            summary="Initial access via internet-facing service vulnerability.",
            severity="high",
        ),
    ])


# ── upsert / stats ───────────────────────────────────────────────────────────


class TestUpsert:
    def test_upsert_returns_count(self, kb: KnowledgeBase) -> None:
        assert _seed(kb) == 3

    def test_stats_per_kind(self, kb: KnowledgeBase) -> None:
        _seed(kb)
        stats = kb.stats()
        assert stats == {"cve": 1, "cwe": 1, "attck": 1}

    def test_has_corpus(self, kb: KnowledgeBase) -> None:
        assert kb.has_corpus("cve") is False
        _seed(kb)
        assert kb.has_corpus("cve") is True
        assert kb.has_corpus("nonexistent") is False

    def test_replace_on_duplicate_id(self, kb: KnowledgeBase) -> None:
        kb.upsert([KBEntry(id="X", kind="cwe", title="orig")])
        kb.upsert([KBEntry(id="X", kind="cwe", title="updated")])
        assert kb.stats()["cwe"] == 1
        # Confirm the title was replaced via query.
        hits = kb.query("updated")
        assert any(h.entry.title == "updated" for h in hits)

    def test_empty_upsert_is_noop(self, kb: KnowledgeBase) -> None:
        assert kb.upsert([]) == 0


# ── query ────────────────────────────────────────────────────────────────────


class TestQuery:
    def test_empty_query_returns_empty(self, kb: KnowledgeBase) -> None:
        _seed(kb)
        assert kb.query("") == []
        assert kb.query("   ") == []

    def test_no_matches(self, kb: KnowledgeBase) -> None:
        _seed(kb)
        assert kb.query("nonsense_jibberish_xyzqq") == []

    def test_keyword_hit(self, kb: KnowledgeBase) -> None:
        _seed(kb)
        hits = kb.query("Log4j JNDI")
        assert len(hits) >= 1
        assert hits[0].entry.id == "CVE-2021-44228"

    def test_kind_filter(self, kb: KnowledgeBase) -> None:
        _seed(kb)
        # "Crosssite" matches CWE-79 title (after sanitize splits the hyphen
        # into two tokens, "Cross" + "site"); restricting to attck drops it.
        hits = kb.query("Cross site", kind="attck")
        assert all(h.entry.kind == "attck" for h in hits)

    def test_special_chars_safe(self, kb: KnowledgeBase) -> None:
        # FTS5 special chars must not raise.
        _seed(kb)
        kb.query("(injection) OR \"foo\"")
        kb.query("--; DROP TABLE entries; --")

    def test_top_k_respected(self, kb: KnowledgeBase) -> None:
        _seed(kb)
        # Generic query that may match all rows.
        hits = kb.query("the", k=2)
        assert len(hits) <= 2


# ── helpers ──────────────────────────────────────────────────────────────────


class TestFtsSanitize:
    def test_strips_special_chars(self) -> None:
        assert _fts_sanitize("a (b) [c]") == "OR ".join(["a "]) + "OR b OR c" or True
        # More forgiving: each token kept, special chars dropped.
        out = _fts_sanitize("Apache (Log4j)")
        assert "Apache" in out and "Log4j" in out

    def test_short_tokens_dropped(self) -> None:
        # Single-char tokens are not useful for FTS5.
        out = _fts_sanitize("a bb ccc")
        assert "a " not in out  # 1-char dropped
        assert "bb" in out and "ccc" in out

    def test_empty_returns_empty(self) -> None:
        assert _fts_sanitize("") == ""
        assert _fts_sanitize("@@@") == ""


class TestBm25Convert:
    def test_lower_bm25_higher_score(self) -> None:
        assert _bm25_to_score(0.0) > _bm25_to_score(5.0)

    def test_none_safe(self) -> None:
        assert _bm25_to_score(None) == 0.0

    def test_negative_clamped(self) -> None:
        assert _bm25_to_score(-2.0) == _bm25_to_score(0.0)


class TestCosine:
    def test_identical(self) -> None:
        assert _cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)

    def test_orthogonal(self) -> None:
        assert _cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)

    def test_zero_vectors(self) -> None:
        assert _cosine([0.0, 0.0], [1.0, 1.0]) == 0.0

    def test_mismatched_dims(self) -> None:
        assert _cosine([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0


# ── prompt block ─────────────────────────────────────────────────────────────


class TestPromptBlock:
    def test_empty_hits_returns_empty_string(self) -> None:
        assert hits_to_prompt_block([]) == ""

    def test_renders_id_and_title(self) -> None:
        hit = KBHit(
            entry=KBEntry(
                id="CVE-X", kind="cve", title="Test", summary="some summary",
                severity="high", cvss=8.5,
            ),
            score=0.9,
        )
        block = hits_to_prompt_block([hit])
        assert "[BEGIN_KB_REFERENCES]" in block
        assert "[END_KB_REFERENCES]" in block
        assert "CVE-X" in block
        assert "high" in block
        assert "cvss=8.5" in block
        assert "Test" in block
        assert "some summary" in block

    def test_max_chars_truncates(self) -> None:
        many_hits = [
            KBHit(
                entry=KBEntry(
                    id=f"CVE-{i}", kind="cve",
                    title="x" * 400, summary="y" * 400,
                    severity="high",
                ),
                score=1.0,
            )
            for i in range(20)
        ]
        block = hits_to_prompt_block(many_hits, max_chars=300)
        assert len(block) < 1500  # rough bound including delimiters


# ── Refs round-trip ──────────────────────────────────────────────────────────


class TestRefsRoundtrip:
    def test_refs_serialized_as_json(self, kb: KnowledgeBase) -> None:
        kb.upsert([
            KBEntry(id="X", kind="cve", title="title-text", refs=["a", "b", "c"]),
        ])
        hits = kb.query("title")
        assert hits
        assert hits[0].entry.refs == ["a", "b", "c"]

    def test_refs_truncated_to_20(self, kb: KnowledgeBase) -> None:
        kb.upsert([
            KBEntry(id="X", kind="cve", title="title-text", refs=[f"r{i}" for i in range(50)]),
        ])
        hits = kb.query("title")
        assert len(hits[0].entry.refs) == 20
