"""
Tier-1 unit eval: replay golden fixtures through each tool's parser.

Adding a new fixture requires zero code — drop two files under
``evals/fixtures/<tool>/<case>.{input.txt,expected.json}`` and this
module picks them up automatically.

Fixtures are intentionally minimal: they only assert keys that must
match, so a tool wrapper adding new fields to its parsed output won't
break old fixtures.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict

import pytest

from evals.fixtures_loader import Fixture, assert_subset, discover_fixtures


_FIXTURES = discover_fixtures()


def _load_tool(tool_name: str):
    """Resolve tool class from the registry without going through ToolAgent."""
    from core.tool_agent import TOOL_REGISTRY

    spec = TOOL_REGISTRY.get(tool_name)
    if spec is None:
        pytest.skip(f"tool {tool_name} not in registry")
    module_path, class_name = spec.split(":")
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


@pytest.mark.parametrize(
    "fixture",
    _FIXTURES,
    ids=[f.id for f in _FIXTURES],
)
def test_parser_fixture(fixture: Fixture) -> None:
    """Golden parser test — parsed output must contain expected keys/values."""
    tool_cls = _load_tool(fixture.tool)
    # Construct with empty config; parsers must not depend on config to read
    # their own stdout. ``is_available`` is irrelevant here.
    tool = tool_cls.__new__(tool_cls)
    tool.config = {}
    tool.tool_name = fixture.tool
    actual = tool.parse_output(fixture.raw_output)
    assert_subset(actual, fixture.expected)
