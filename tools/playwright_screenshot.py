"""
Playwright Screenshot tool — A3 vision input source.

Uses ``playwright`` (chromium) headless to capture full-page PNGs of every
URL surfaced upstream by httpx / subfinder / nuclei. Output PNGs land
under ``./reports/screenshots/<session>/<host>.png`` and are emitted in
``parsed.screenshots`` so the analyst's ``visual_triage`` sub-step can
consume them.

Why a tool wrapper rather than a direct call from the analyst: the same
contract (``BaseTool``) gives us streaming/timeout/skip-on-missing for
free, plus the wrapper plugs into existing workflows just like any
other recon step (depends_on / DAG scheduling / risk gating).

Risk class: ``active`` — fetches the URL and renders it. Same blast
radius as a regular HTTP GET, no payload injection.

This wrapper does NOT shell out to a CLI. It still pretends to (via
``get_command`` returning a stub) so the BaseTool contract holds, but the
real work happens in ``execute_async``. We override ``execute`` to skip
the subprocess machinery.
"""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from tools.base_tool import BaseTool


_DEFAULT_TIMEOUT_MS = 15_000


class PlaywrightScreenshotTool(BaseTool):
    """Headless Chromium screenshotter."""

    def __init__(self, config: Dict[str, Any]):
        # Skip the parent's installed-check based on PATH — playwright is a
        # python lib, not a CLI. We do our own check below.
        self.config = config
        from utils.logger import get_logger
        self.logger = get_logger(config)
        self.tool_name = "playwright_screenshot"
        self.is_available = self._check_playwright()

    def _check_playwright(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            self.logger.info(
                "playwright not installed — screenshot tool will skip. "
                "Install with: pip install playwright && python -m playwright install chromium"
            )
            return False

    def _check_installation(self) -> bool:  # pragma: no cover — overridden init
        return self._check_playwright()

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Stub — execute() is overridden; the BaseTool contract still
        requires this method to exist."""
        return ["playwright", "screenshot", target]

    def parse_output(self, output: str) -> Dict[str, Any]:
        """No-op — execute() returns parsed dict directly."""
        return {}

    async def execute(
        self,
        target: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Capture a screenshot of ``target`` (and any URLs in ``urls`` kwarg).

        kwargs:
          urls:       additional URLs to capture in the same browser context
          out_dir:    override default screenshots directory
          full_page:  capture entire page (default True)
          timeout:    per-page timeout in ms
        """
        if not self.is_available:
            return {
                "success": False, "skipped": True, "tool": self.tool_name,
                "error": "playwright not installed",
                "raw_output": "", "command": "", "exit_code": -1,
                "duration": 0.0, "parsed": {"screenshots": []},
            }

        urls: List[str] = list(kwargs.get("urls") or [])
        if target and target not in urls:
            urls.insert(0, target)
        urls = [u for u in urls if _looks_like_url(u)]
        if not urls:
            return {
                "success": False, "skipped": True, "tool": self.tool_name,
                "error": "no URL targets supplied",
                "raw_output": "", "command": "", "exit_code": -1,
                "duration": 0.0, "parsed": {"screenshots": []},
            }

        out_dir = Path(kwargs.get("out_dir") or self._default_out_dir())
        out_dir.mkdir(parents=True, exist_ok=True)
        timeout = int(kwargs.get("timeout") or _DEFAULT_TIMEOUT_MS)
        full_page = bool(kwargs.get("full_page", True))

        start = datetime.utcnow()
        screenshots = await self._capture_all(urls, out_dir, timeout, full_page, stream_callback)
        duration = (datetime.utcnow() - start).total_seconds()

        success = any(s.get("path") for s in screenshots)
        return {
            "success": success,
            "skipped": False,
            "tool": self.tool_name,
            "command": f"playwright_screenshot urls={len(urls)} out={out_dir}",
            "raw_output": "\n".join(
                f"{s['url']} -> {s.get('path') or s.get('error', 'fail')}"
                for s in screenshots
            ),
            "exit_code": 0 if success else 1,
            "duration": duration,
            "timestamp": start.isoformat(),
            "parsed": {"screenshots": screenshots, "out_dir": str(out_dir)},
        }

    # ── internals ────────────────────────────────────────────────────────────

    async def _capture_all(
        self,
        urls: List[str],
        out_dir: Path,
        timeout: int,
        full_page: bool,
        stream_callback: Optional[Callable[[str], None]],
    ) -> List[Dict[str, Any]]:
        from playwright.async_api import async_playwright  # type: ignore

        results: List[Dict[str, Any]] = []
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Guardian-CLI/4 (security testing; +authorized engagement)",
                )
                for url in urls:
                    safe_name = _safe_filename(url) + ".png"
                    out_path = out_dir / safe_name
                    page = await context.new_page()
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=timeout)
                        await page.screenshot(path=str(out_path), full_page=full_page)
                        results.append({"url": url, "path": str(out_path)})
                        if stream_callback:
                            stream_callback(f"[+] captured {url} -> {out_path.name}")
                    except Exception as e:
                        results.append({"url": url, "error": str(e)[:200]})
                        if stream_callback:
                            stream_callback(f"[-] failed {url}: {e}")
                    finally:
                        await page.close()
                await context.close()
            finally:
                await browser.close()
        return results

    def _default_out_dir(self) -> Path:
        base = Path(self.config.get("output", {}).get("save_path", "./reports"))
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return base / "screenshots" / ts


# ── helpers ──────────────────────────────────────────────────────────────────


def _looks_like_url(s: str) -> bool:
    if not s:
        return False
    try:
        p = urlparse(s)
    except Exception:
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


def _safe_filename(url: str) -> str:
    """Map URL to a flat filename. Stable + readable; collisions fine."""
    p = urlparse(url)
    host = (p.hostname or "unknown").replace(":", "_")
    path = (p.path or "/").strip("/").replace("/", "__") or "root"
    base = f"{host}__{path}"
    return base[:80].replace(".", "_")
