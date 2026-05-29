"""
Fixture replay loader.

A fixture is a pair of files in a sibling subdirectory:

  evals/fixtures/<tool_name>/<case_name>.input.txt    — raw tool stdout
  evals/fixtures/<tool_name>/<case_name>.expected.json — expected parsed dict

Adding a fixture for a new tool is the path of least resistance for
expanding eval coverage. ``test_parser_fixtures.py`` parametrises over
every fixture pair and asserts ``BaseTool.parse_output`` produces the
expected structure.

The expected JSON only needs to specify keys that *must* match — extra
keys in actual output are ignored (forward-compatible).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


@dataclass
class Fixture:
    tool: str
    case: str
    raw_output: str
    expected: Dict[str, Any]

    @property
    def id(self) -> str:
        return f"{self.tool}::{self.case}"


def discover_fixtures(root: Path = FIXTURES_ROOT) -> List[Fixture]:
    """Walk ``evals/fixtures/`` and return every (input, expected) pair."""
    fixtures: List[Fixture] = []
    if not root.exists():
        return fixtures
    for tool_dir in sorted(root.iterdir()):
        if not tool_dir.is_dir():
            continue
        for input_file in sorted(tool_dir.glob("*.input.txt")):
            case = input_file.name[: -len(".input.txt")]
            expected_file = tool_dir / f"{case}.expected.json"
            if not expected_file.exists():
                continue
            fixtures.append(
                Fixture(
                    tool=tool_dir.name,
                    case=case,
                    raw_output=input_file.read_text(encoding="utf-8"),
                    expected=json.loads(expected_file.read_text(encoding="utf-8")),
                )
            )
    return fixtures


def assert_subset(actual: Any, expected: Any, path: str = "") -> None:
    """Assert that every key/value in ``expected`` appears in ``actual``.

    Lists are compared positionally; dicts recursively. Anything else
    must equal exactly. Raises ``AssertionError`` with the failing path
    on mismatch — pytest renders the path so debugging fixtures stays
    cheap.
    """
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise AssertionError(f"{path}: expected dict, got {type(actual).__name__}")
        for k, v in expected.items():
            if k not in actual:
                raise AssertionError(f"{path}.{k}: missing from actual")
            assert_subset(actual[k], v, path=f"{path}.{k}")
        return
    if isinstance(expected, list):
        if not isinstance(actual, list):
            raise AssertionError(f"{path}: expected list, got {type(actual).__name__}")
        if len(actual) < len(expected):
            raise AssertionError(
                f"{path}: actual list shorter ({len(actual)}) than expected ({len(expected)})"
            )
        for i, item in enumerate(expected):
            assert_subset(actual[i], item, path=f"{path}[{i}]")
        return
    if actual != expected:
        raise AssertionError(f"{path}: expected {expected!r}, got {actual!r}")
