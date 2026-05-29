"""Tests for tools.base_tool result-dict shape and ANSI sanitization."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict, List

import pytest

from tools.base_tool import BaseTool


class _EchoTool(BaseTool):
    """Test tool that runs a portable subprocess for shape verification."""

    def __init__(self, config: Dict[str, Any], argv: List[str]) -> None:
        self._argv = argv
        super().__init__(config)
        # Force is_available regardless of tool_name auto-derive.
        self.is_available = True

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        return self._argv

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"echoed": output.strip()}


@pytest.fixture
def python_exe() -> str:
    return sys.executable


class TestResultShape:
    @pytest.mark.asyncio
    async def test_success_keys_present(
        self, base_config: Dict[str, Any], python_exe: str
    ) -> None:
        tool = _EchoTool(
            base_config,
            [python_exe, "-c", "print('hello-world')"],
        )
        result = await tool.execute("example.com")
        for key in (
            "success", "tool", "target", "command", "exit_code",
            "duration", "raw_output", "error", "parsed",
        ):
            assert key in result, f"missing key {key}"
        assert result["success"] is True
        assert "hello-world" in result["raw_output"]
        assert result["parsed"] == {"echoed": "hello-world"}

    @pytest.mark.asyncio
    async def test_skipped_when_unavailable(self, base_config: Dict[str, Any]) -> None:
        tool = _EchoTool(base_config, ["python", "-c", "pass"])
        tool.is_available = False
        result = await tool.execute("example.com")
        assert result["success"] is False
        assert result["skipped"] is True
        assert result["parsed"] == {}

    @pytest.mark.asyncio
    async def test_strips_ansi_from_raw_output(
        self, base_config: Dict[str, Any], python_exe: str
    ) -> None:
        # Tool emits ANSI red text; sanitization must strip the escapes.
        snippet = (
            "import sys; sys.stdout.write('\\x1b[31mRED\\x1b[0m clean\\n')"
        )
        tool = _EchoTool(base_config, [python_exe, "-c", snippet])
        result = await tool.execute("example.com")
        assert result["success"] is True
        assert "\x1b" not in result["raw_output"]
        assert "RED clean" in result["raw_output"]
