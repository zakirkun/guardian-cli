"""
Audit logging system for Guardian
Tracks all AI decisions and security-relevant actions
"""

import logging
import logging.handlers
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional
from rich.logging import RichHandler


# Default rotation policy: 10 MB per file × 5 generations = 50 MB ceiling.
# Long engagements that previously grew guardian.log unbounded now wrap.
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_BACKUP_COUNT = 5


class _SafeStreamHandler(logging.StreamHandler):
    """
    A StreamHandler that encodes log messages with errors='replace'.
    Prevents UnicodeEncodeError on Windows consoles (cp1252) when AI responses
    contain Unicode characters such as ≤ (U+2264).
    """

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            stream = self.stream
            # Encode to the stream's encoding, replacing unencodable chars
            encoding = getattr(stream, "encoding", "utf-8") or "utf-8"
            safe_msg = msg.encode(encoding, errors="replace").decode(encoding)
            stream.write(safe_msg + self.terminator)
            self.flush()
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


class AuditLogger:
    """Specialized logger for security audit trails"""

    def __init__(
        self,
        log_path: str = "./logs/guardian.log",
        level: str = "INFO",
        max_bytes: int = _DEFAULT_MAX_BYTES,
        backup_count: int = _DEFAULT_BACKUP_COUNT,
    ):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Separate audit log for AI decisions — keeps the main log focused on
        # operational events; AI decision audit can be rotated independently
        # at a different cadence if compliance requires.
        self.audit_path = self.log_path.parent / "ai_audit.log"

        # Create logger
        self.logger = logging.getLogger("guardian")
        self.logger.setLevel(getattr(logging, level.upper()))

        # Avoid duplicate handlers if get_logger() is called multiple times
        if self.logger.handlers:
            return

        # Main log: rotating file handler bounded by size.
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)

        # Console handler – Rich for pretty output, wrapped in our safe encoder
        console_handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
        )
        console_handler.setLevel(getattr(logging, level.upper()))

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        # Dedicated audit logger for AI decisions. Same rotation policy;
        # writes structured JSON one record per line for easy ingestion.
        self.audit_logger = logging.getLogger("guardian.audit")
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False  # don't double-log via parent.
        if not self.audit_logger.handlers:
            audit_handler = logging.handlers.RotatingFileHandler(
                self.audit_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            audit_handler.setFormatter(logging.Formatter("%(message)s"))
            self.audit_logger.addHandler(audit_handler)
    
    def log_ai_decision(self, agent: str, decision: str, reasoning: str, context: Dict[str, Any]):
        """Log AI agent decisions for audit trail.

        Records go to BOTH the main log (one-line summary) and the dedicated
        ``ai_audit.log`` (full JSON per record). Splitting the audit log makes
        long engagements rotate independently and gives compliance a single
        machine-parseable file to ingest.
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "ai_decision",
            "agent": agent,
            "decision": decision,
            "reasoning": reasoning,
            "context": context,
        }
        # Console: first non-empty line only, stripped of special Unicode
        first_line = next(
            (l.strip() for l in decision.splitlines() if l.strip()), decision[:120]
        )[:120]
        safe_line = first_line.encode("ascii", errors="replace").decode("ascii")
        self.logger.info(f"AI Decision [{agent}]: {safe_line}")
        # Dedicated audit sink — one JSON record per line for ingestion.
        self.audit_logger.info(json.dumps(entry, ensure_ascii=False))
    
    def log_tool_execution(self, tool: str, args: Dict[str, Any], result: Optional[str] = None):
        """Log tool execution for audit trail"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "tool_execution",
            "tool": tool,
            "arguments": args,
            "result_preview": result[:200] if result else None
        }
        self.logger.info(f"Tool Executed: {tool}")
        self.logger.debug(f"Tool Details: {json.dumps(entry, indent=2)}")
    
    def log_security_event(self, event_type: str, severity: str, details: str):
        """Log security-relevant events"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "security_event",
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        if severity == "CRITICAL":
            self.logger.critical(f"Security Event [{event_type}]: {details}")
        elif severity == "HIGH":
            self.logger.error(f"Security Event [{event_type}]: {details}")
        elif severity == "MEDIUM":
            self.logger.warning(f"Security Event [{event_type}]: {details}")
        else:
            self.logger.info(f"Security Event [{event_type}]: {details}")
    
    def info(self, message: str):
        """Standard info logging"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Standard warning logging"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Standard error logging"""
        self.logger.error(message)
    
    def debug(self, message: str):
        """Standard debug logging"""
        self.logger.debug(message)


# Global logger instance
_logger: Optional[AuditLogger] = None


def get_logger(config: Optional[Dict[str, Any]] = None) -> AuditLogger:
    """Get or create the global logger instance"""
    global _logger

    if _logger is None:
        if config and "logging" in config:
            log_config = config["logging"]
            _logger = AuditLogger(
                log_path=log_config.get("path", "./logs/guardian.log"),
                level=log_config.get("level", "INFO"),
                max_bytes=log_config.get("max_bytes", _DEFAULT_MAX_BYTES),
                backup_count=log_config.get("backup_count", _DEFAULT_BACKUP_COUNT),
            )
        else:
            _logger = AuditLogger()

    return _logger
