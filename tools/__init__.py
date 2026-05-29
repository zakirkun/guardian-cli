"""Tools package for Guardian.

Tool wrapper classes are loaded lazily by ``core.tool_agent`` via the
``TOOL_REGISTRY`` (module:Class strings). Importing this package no longer
imports any concrete tool, so ``guardian --help`` does not pay the cost of
20 wrapper imports + 20 ``shutil.which`` calls.

Concrete classes remain importable by their submodule path:
    from tools.nmap import NmapTool
"""

from .base_tool import BaseTool

__all__ = ["BaseTool"]
