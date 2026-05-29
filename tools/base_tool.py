"""
Base class for all pentest tool wrappers.
Supports:
  - Graceful skip when tool is not installed (returns skipped result, never crashes)
  - Real-time streaming of subprocess output to a Rich console
  - Target is always the exact value passed in (no hallucination)
"""

import asyncio
import subprocess
import shutil
from typing import Dict, Any, Optional, List, Callable, Awaitable
from pathlib import Path
from datetime import datetime
from abc import ABC, abstractmethod

from utils.logger import get_logger
from utils.sanitize import strip_control_chars


class BaseTool(ABC):
    """Base class for external penetration testing tools"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.tool_name = self.__class__.__name__.replace("Tool", "").lower()

        # Check if tool is installed — always a property, never raises
        self.is_available = self._check_installation()
        if not self.is_available:
            self.logger.warning(
                f"Tool {self.tool_name} is not installed or not in PATH"
            )

    @abstractmethod
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build command line for the tool. Must use `target` exactly as supplied."""
        pass

    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        pass

    async def execute(
        self,
        target: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute the tool against a target.

        Args:
            target:          Exact target string as supplied by the user.
            stream_callback: Optional sync callback called with each output line
                             for real-time display (e.g. Rich console.print).

        Returns:
            Dict with parsed results, raw output, exit_code, duration and
            success/error keys.  NEVER raises; returns success=False on failure
            so callers can gracefully skip.
        """
        # ── Availability check ────────────────────────────────────────────────
        if not self.is_available:
            msg = f"Tool '{self.tool_name}' is not installed or not in PATH — skipping step"
            self.logger.warning(msg)
            return self._skipped_result(target, msg)

        # ── Build command ─────────────────────────────────────────────────────
        command = self.get_command(target, **kwargs)

        self.logger.info(f"Executing: {' '.join(command)}")

        # ── Stream callback announcement ──────────────────────────────────────
        if stream_callback:
            stream_callback(f"\n[bold cyan]$ {' '.join(command)}[/bold cyan]")

        timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        start_time = datetime.now()

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # ── Real-time streaming ───────────────────────────────────────────
            lines: List[str] = []
            err_lines: List[str] = []

            if stream_callback:
                # Read stdout line-by-line while also draining stderr at the end
                async def _read_stdout():
                    async for raw in process.stdout:
                        line = raw.decode("utf-8", errors="replace").rstrip()
                        lines.append(line)
                        stream_callback(line)

                async def _read_stderr():
                    async for raw in process.stderr:
                        line = raw.decode("utf-8", errors="replace").rstrip()
                        err_lines.append(line)
                        # Show stderr in dim style
                        stream_callback(f"[dim red]{line}[/dim red]")

                try:
                    await asyncio.wait_for(
                        asyncio.gather(_read_stdout(), _read_stderr()),
                        timeout=timeout,
                    )
                    await process.wait()
                except asyncio.TimeoutError:
                    process.kill()
                    raise asyncio.TimeoutError(
                        f"Tool {self.tool_name} timed out after {timeout}s"
                    )
            else:
                # Buffered mode — no streaming
                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        process.communicate(), timeout=timeout
                    )
                    lines = stdout_bytes.decode("utf-8", errors="replace").splitlines()
                    err_lines = stderr_bytes.decode("utf-8", errors="replace").splitlines()
                except asyncio.TimeoutError:
                    process.kill()
                    raise asyncio.TimeoutError(
                        f"Tool {self.tool_name} timed out after {timeout}s"
                    )

            duration = (datetime.now() - start_time).total_seconds()
            # Strip ANSI / control chars before storing or feeding to the LLM —
            # an attacker-controlled tool output cannot inject terminal escape
            # codes or smuggle control bytes through to the prompt.
            output_text = strip_control_chars("\n".join(lines))
            error_text = strip_control_chars("\n".join(err_lines))

            # ── Parse & return ────────────────────────────────────────────────
            parsed = self.parse_output(output_text)

            result = {
                "success": True,
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(command),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": output_text,
                "error": error_text if error_text else None,
                "parsed": parsed,
            }

            self.logger.info(f"Tool {self.tool_name} completed in {duration:.2f}s")
            return result

        except asyncio.TimeoutError as e:
            self.logger.error(str(e))
            return self._error_result(target, " ".join(command), str(e))
        except FileNotFoundError:
            msg = (
                f"Tool binary '{command[0]}' not found — "
                "make sure it is installed and in PATH"
            )
            self.logger.error(msg)
            return self._skipped_result(target, msg)
        except PermissionError as e:
            msg = f"Permission denied running '{command[0]}': {e}"
            self.logger.error(msg)
            return self._error_result(target, " ".join(command), msg)
        except Exception as e:
            self.logger.error(f"Tool {self.tool_name} failed: {e}")
            return self._error_result(target, " ".join(command), str(e))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _skipped_result(self, target: str, reason: str) -> Dict[str, Any]:
        """Return a structured 'skipped' result so callers never need to crash."""
        return {
            "success": False,
            "skipped": True,
            "tool": self.tool_name,
            "target": target,
            "command": "",
            "exit_code": -1,
            "duration": 0.0,
            "raw_output": f"[SKIPPED] {reason}",
            "error": reason,
            "parsed": {},
        }

    def _error_result(self, target: str, command: str, error: str) -> Dict[str, Any]:
        """Return a structured error result."""
        return {
            "success": False,
            "skipped": False,
            "tool": self.tool_name,
            "target": target,
            "command": command,
            "exit_code": -1,
            "duration": 0.0,
            "raw_output": "",
            "error": error,
            "parsed": {},
        }

    def _check_installation(self) -> bool:
        """Check if tool binary is installed and in PATH"""
        return shutil.which(self.tool_name) is not None

    def get_version(self) -> Optional[str]:
        """Get tool version if available"""
        try:
            result = subprocess.run(
                [self.tool_name, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() or result.stderr.strip()
        except Exception:
            return None
