"""Tests for VisualTriage (A3) — covers parsing, host matching, skip paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.agents.visual_triage import VisualTriage, VisualEnrichment
from core.memory import Finding, PentestMemory


# ── helpers ──────────────────────────────────────────────────────────────────


def _finding(id_: str, target: str, tool: str = "nuclei", desc: str = "orig desc") -> Finding:
    return Finding(
        id=id_,
        severity="medium",
        title="Some web finding",
        description=desc,
        evidence="raw",
        tool=tool,
        target=target,
        timestamp="2026-01-01T00:00:00Z",
    )


def _client_with_provider(supports_vision: bool = True, response: str = "") -> MagicMock:
    client = MagicMock()
    provider = MagicMock()
    provider.supports_vision = MagicMock(return_value=supports_vision)
    provider.generate_with_images = AsyncMock(return_value={"response": response})
    client.provider = provider
    return client


@pytest.fixture
def memory() -> PentestMemory:
    return PentestMemory("https://example.com")


@pytest.fixture
def screenshot_file(tmp_path: Path) -> str:
    p = tmp_path / "shot.png"
    # 1x1 transparent PNG.
    p.write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\x00\x01"
        b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    return str(p)


# ── parser ───────────────────────────────────────────────────────────────────


class TestParseResponse:
    def test_valid_json(self) -> None:
        raw = '{"page_type": "login", "supports_finding": true, "enriched_description": "x", "confidence": 80, "visible_indicators": ["a","b"]}'
        out = VisualTriage._parse_response(raw)
        assert out["page_type"] == "login"
        assert out["confidence"] == 80

    def test_garbage_returns_none(self) -> None:
        assert VisualTriage._parse_response("not json at all") is None

    def test_extracts_from_surrounding_text(self) -> None:
        raw = "Some preamble.\n{\"page_type\": \"error\"}\nThanks."
        out = VisualTriage._parse_response(raw)
        assert out["page_type"] == "error"

    def test_empty(self) -> None:
        assert VisualTriage._parse_response("") is None
        assert VisualTriage._parse_response(None) is None  # type: ignore[arg-type]


# ── _best_finding_for_url ────────────────────────────────────────────────────


class TestHostMatching:
    def test_exact_host_match(self, base_config: Dict[str, Any], memory: PentestMemory) -> None:
        memory.add_finding(_finding("a", "https://example.com/login"))
        memory.add_finding(_finding("b", "https://other.com/"))

        triage = VisualTriage(base_config, _client_with_provider(), memory)
        f = triage._best_finding_for_url("https://example.com/admin")
        assert f is not None and f.id == "a"

    def test_returns_none_when_no_findings(self, base_config: Dict[str, Any], memory: PentestMemory) -> None:
        triage = VisualTriage(base_config, _client_with_provider(), memory)
        assert triage._best_finding_for_url("https://x.com/") is None

    def test_falls_back_to_first_web_finding(self, base_config: Dict[str, Any], memory: PentestMemory) -> None:
        memory.add_finding(_finding("a", "10.0.0.1", tool="nmap"))
        memory.add_finding(_finding("b", "10.0.0.2", tool="httpx"))

        triage = VisualTriage(base_config, _client_with_provider(), memory)
        # No host overlap with 10.0.0.x — fallback to first httpx/nuclei finding.
        f = triage._best_finding_for_url("https://noplace.invalid/")
        assert f is not None and f.id == "b"

    def test_empty_url(self, base_config: Dict[str, Any], memory: PentestMemory) -> None:
        memory.add_finding(_finding("a", "https://example.com/"))
        triage = VisualTriage(base_config, _client_with_provider(), memory)
        assert triage._best_finding_for_url("") is None


# ── triage_findings flow ─────────────────────────────────────────────────────


class TestTriageFlow:
    @pytest.mark.asyncio
    async def test_skips_when_no_vision_support(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _client_with_provider(supports_vision=False)
        triage = VisualTriage(base_config, client, memory)

        out = await triage.triage_findings()
        assert out["enrichments"] == []
        assert "vision" in (out["skipped_reason"] or "").lower()
        client.provider.generate_with_images.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_when_no_screenshots(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _client_with_provider()
        triage = VisualTriage(base_config, client, memory)

        out = await triage.triage_findings()
        assert out["enrichments"] == []
        assert "no screenshots" in (out["skipped_reason"] or "").lower()

    @pytest.mark.asyncio
    async def test_full_flow_enriches_finding(
        self,
        base_config: Dict[str, Any],
        memory: PentestMemory,
        screenshot_file: str,
    ) -> None:
        # Stage a finding + a screenshot record.
        memory.add_finding(_finding("a", "https://example.com/admin", tool="nuclei", desc="nuclei said something"))
        # tool_results is keyed by step id in production; emulate the structure.
        memory.tool_results = [{
            "parsed": {"screenshots": [{"url": "https://example.com/admin", "path": screenshot_file}]}
        }]

        client = _client_with_provider(
            response='{"page_type":"admin_panel","supports_finding":true,"enriched_description":"admin login form visible","confidence":80,"visible_indicators":["login form","django logo"]}'
        )
        triage = VisualTriage(base_config, client, memory)

        out = await triage.triage_findings()
        assert out["skipped_reason"] is None
        assert len(out["enrichments"]) == 1

        e = out["enrichments"][0]
        assert e.page_type == "admin_panel"
        assert e.supports_finding is True
        assert e.confidence == 80
        # Finding mutated in place.
        f = memory.findings[0]
        assert "Visual Triage" in f.description
        assert "admin_panel" in f.description
        assert "screenshot:" in (f.raw_evidence or "")

    @pytest.mark.asyncio
    async def test_skips_when_image_missing(
        self, base_config: Dict[str, Any], memory: PentestMemory, tmp_path: Path
    ) -> None:
        memory.add_finding(_finding("a", "https://example.com/", tool="nuclei"))
        memory.tool_results = [{
            "parsed": {"screenshots": [{"url": "https://example.com/", "path": str(tmp_path / "missing.png")}]}
        }]

        client = _client_with_provider(response='{"page_type":"x"}')
        triage = VisualTriage(base_config, client, memory)
        out = await triage.triage_findings()
        # Nothing enriched because file doesn't exist.
        assert out["enrichments"] == []
        client.provider.generate_with_images.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_garbage_response_drops_enrichment(
        self,
        base_config: Dict[str, Any],
        memory: PentestMemory,
        screenshot_file: str,
    ) -> None:
        memory.add_finding(_finding("a", "https://example.com/", tool="nuclei"))
        memory.tool_results = [{
            "parsed": {"screenshots": [{"url": "https://example.com/", "path": screenshot_file}]}
        }]

        client = _client_with_provider(response="completely unparseable")
        triage = VisualTriage(base_config, client, memory)
        out = await triage.triage_findings()
        assert out["enrichments"] == []


# ── VisualEnrichment shape ───────────────────────────────────────────────────


class TestEnrichmentShape:
    def test_dataclass_fields(self) -> None:
        e = VisualEnrichment(
            finding_id="x",
            image_path="/tmp/x.png",
            page_type="login",
            supports_finding=False,
            enriched_description="d",
            confidence=70,
            visible_indicators=["i"],
        )
        assert e.confidence == 70
        assert e.visible_indicators == ["i"]
