"""Shared pytest fixtures."""

from __future__ import annotations

from typing import Any, Dict

import pytest


@pytest.fixture
def base_config() -> Dict[str, Any]:
    """Minimal config dict accepted by the validator + tools."""
    return {
        "scope": {
            "blacklist": [],  # exercise hardcoded defaults too
            "require_scope_file": False,
            "max_targets": 100,
        },
        "pentest": {"tool_timeout": 5, "safe_mode": True},
        "logging": {"enabled": False, "level": "ERROR", "log_ai_decisions": False},
        "output": {"save_path": "./reports", "format": "markdown"},
    }
