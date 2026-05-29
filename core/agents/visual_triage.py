"""
Visual Triage agent (A3).

Pairs each captured screenshot with the closest finding (by host + URL)
and asks a vision-capable provider to describe what's actually visible.
The enrichment is appended to the finding's description so reporters
include image-grounded language without losing the original tool output.

Wired as a workflow analysis step type via ``agent: visual``. Skipped
silently when the active provider has no vision support — the textual
analyst path already ran, so no findings are lost.

Public entry point: ``VisualTriage.triage_findings()``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.agent import BaseAgent
from core.memory import Finding, PentestMemory
from utils.sanitize import wrap_untrusted

from ai.prompt_templates.visual_triage import (
    VISUAL_TRIAGE_PROMPT,
    VISUAL_TRIAGE_SYSTEM_PROMPT,
)


@dataclass
class VisualEnrichment:
    """One image-grounded enrichment record."""

    finding_id: str
    image_path: str
    page_type: str
    supports_finding: bool
    enriched_description: str
    confidence: int
    visible_indicators: List[str] = field(default_factory=list)


class VisualTriage(BaseAgent):
    """Vision-LLM finding enricher."""

    name_prefix = "VisualTriage"

    def __init__(self, config: Dict[str, Any], gemini_client, memory: PentestMemory):
        super().__init__("VisualTriage", config, gemini_client, memory)

    async def execute(self, **kwargs) -> Dict[str, Any]:  # pragma: no cover
        return await self.triage_findings()

    async def triage_findings(self) -> Dict[str, Any]:
        """Walk the memory, locate ``screenshots`` blob in any tool result,
        match each shot to a finding by host overlap, and enrich.

        Returns:
            ``{"enrichments": [VisualEnrichment...], "skipped_reason": str|None}``
        """
        provider = self._active_provider()
        if provider is None or not getattr(provider, "supports_vision", lambda: False)():
            return {
                "enrichments": [],
                "skipped_reason": "active provider has no vision support",
            }

        screenshots = self._collect_screenshots()
        if not screenshots:
            return {"enrichments": [], "skipped_reason": "no screenshots in memory"}

        enrichments: List[VisualEnrichment] = []
        for shot in screenshots:
            url = shot.get("url", "")
            path = shot.get("path", "")
            if not path or not Path(path).exists():
                continue

            finding = self._best_finding_for_url(url)
            if finding is None:
                continue

            try:
                enrichment = await self._enrich_one(provider, finding, url, path)
            except Exception as e:
                self.logger.warning(f"Visual triage call failed for {url}: {e}")
                continue

            if enrichment is None:
                continue

            self._apply_enrichment(finding, enrichment)
            enrichments.append(enrichment)

        return {"enrichments": enrichments, "skipped_reason": None}

    # ── helpers ──────────────────────────────────────────────────────────────

    def _active_provider(self):
        """Get the underlying provider out of the GeminiClient wrapper.

        ``GeminiClient`` is misnamed — it's the central provider switch.
        ``.provider`` is the active concrete provider instance; on older
        versions it's the model itself. We probe both.
        """
        client = self.gemini
        for attr in ("provider", "active_provider", "_provider"):
            obj = getattr(client, attr, None)
            if obj is not None and hasattr(obj, "supports_vision"):
                return obj
        # Fallback — the client itself may implement supports_vision.
        if hasattr(client, "supports_vision"):
            return client
        return None

    def _collect_screenshots(self) -> List[Dict[str, str]]:
        """Pull every ``screenshots`` blob out of memory's tool results.

        The screenshot tool emits ``parsed.screenshots = [{url, path}]``;
        we deduplicate by URL since httpx + nuclei may both feed the same
        list.
        """
        seen: Dict[str, Dict[str, str]] = {}
        # Prefer in-memory tool_results when available; fall back to executions.
        sources = []
        for attr in ("tool_results", "results"):
            v = getattr(self.memory, attr, None)
            if v:
                sources.append(v)

        for src in sources:
            try:
                iterable = src.values() if isinstance(src, dict) else src
            except Exception:
                continue
            for entry in iterable:
                parsed = (entry or {}).get("parsed", {}) if isinstance(entry, dict) else {}
                shots = parsed.get("screenshots") or []
                for shot in shots:
                    if not isinstance(shot, dict):
                        continue
                    url = shot.get("url") or ""
                    if url and url not in seen:
                        seen[url] = shot
        return list(seen.values())

    def _best_finding_for_url(self, url: str) -> Optional[Finding]:
        """Closest finding by URL host overlap.

        Web findings carry ``target`` ≈ the URL itself or the host. We
        score on host equality first, falling back to substring match. If
        nothing matches, return None — the screenshot is dropped (still
        on disk for the report's appendix).
        """
        if not self.memory.findings or not url:
            return None

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        host = host.lower()

        # Pass 1 — exact host match in finding.target.
        for f in self.memory.findings:
            try:
                ftarget = (f.target or "").lower()
                fhost = urlparse(ftarget).hostname or ftarget
            except Exception:
                fhost = (f.target or "").lower()
            if host and (host == fhost or host in fhost or fhost in host):
                return f

        # Pass 2 — first finding from a web tool (httpx/nuclei/whatweb).
        for f in self.memory.findings:
            if f.tool in {"httpx", "nuclei", "whatweb", "wpscan", "nikto"}:
                return f
        return None

    async def _enrich_one(
        self,
        provider,
        finding: Finding,
        url: str,
        image_path: str,
    ) -> Optional[VisualEnrichment]:
        prompt = VISUAL_TRIAGE_PROMPT.format(
            url=url,
            tool=finding.tool,
            title=finding.title,
            severity=finding.severity,
            evidence=wrap_untrusted(finding.evidence or finding.description),
        )

        result = await provider.generate_with_images(
            prompt=prompt,
            images=[{"path": image_path}],
            system_prompt=VISUAL_TRIAGE_SYSTEM_PROMPT,
        )
        text = (result or {}).get("response", "")
        parsed = self._parse_response(text)
        if parsed is None:
            return None

        return VisualEnrichment(
            finding_id=finding.id,
            image_path=image_path,
            page_type=parsed.get("page_type", "unknown"),
            supports_finding=bool(parsed.get("supports_finding", False)),
            enriched_description=parsed.get("enriched_description", "")[:1500],
            confidence=int(parsed.get("confidence", 0) or 0),
            visible_indicators=[
                str(x)[:120] for x in (parsed.get("visible_indicators") or [])
            ][:8],
        )

    @staticmethod
    def _parse_response(response: str) -> Optional[Dict[str, Any]]:
        """Pull the JSON object out of the vision response. Return None
        when no valid object is found — caller drops the enrichment."""
        m = re.search(r"\{[\s\S]*\}", response or "")
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _apply_enrichment(finding: Finding, enrichment: VisualEnrichment) -> None:
        """Append the visual description to the finding without losing
        the original. Reporters render the full description as-is."""
        suffix = (
            f"\n\n[Visual Triage — page_type={enrichment.page_type}, "
            f"supports={'yes' if enrichment.supports_finding else 'no'}, "
            f"conf={enrichment.confidence}]\n"
            f"{enrichment.enriched_description}"
        )
        if enrichment.visible_indicators:
            suffix += "\nIndicators: " + "; ".join(enrichment.visible_indicators)
        finding.description = (finding.description or "") + suffix
        # Stash the image path on raw_evidence for the report's appendix.
        finding.raw_evidence = (finding.raw_evidence or "") + f"\nscreenshot: {enrichment.image_path}"
