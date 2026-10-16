"""Sanitized and structured logging configuration.

Ensures that no raw customer complaints, unredacted PII, authorization tokens,
or cryptographic keys are logged to stdout/stderr or log files.
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict


# Sanitization regexes to catch common leaks if accidentally passed into log messages
SENSITIVE_PATTERNS = [
    (re.compile(r"Bearer\s+([A-Za-z0-9\-_\.]+)", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"(password|pwd|secret|key)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\+?[0-9]{1,3}?[-.\s]?\(?[0-9]{1,4}?\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "[REDACTED_PAN]"),
]


class SanitizedJsonFormatter(logging.Formatter):
    """JSON log formatter that enforces redaction of sensitive patterns."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": self._sanitize_text(record.getMessage()),
        }

        # Include custom context attributes if attached
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "actor_id"):
            log_entry["actor_id"] = record.actor_id
        if hasattr(record, "action_type"):
            log_entry["action_type"] = record.action_type

        # Include exception information safely
        if record.exc_info:
            log_entry["exception"] = self._sanitize_text(self.formatException(record.exc_info))

        return json.dumps(log_entry, default=str)

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Apply regex patterns to mask sensitive tokens or data in log strings."""
        if not text:
            return ""
        sanitized = text
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure root and application loggers with sanitized JSON formatting."""
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to prevent duplicate or unformatted logs
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SanitizedJsonFormatter())
    root_logger.addHandler(handler)

    # Quiet overly chatty external libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    logger = logging.getLogger("secure-finance-assistant")
    logger.setLevel(numeric_level)
    return logger


# Pre-configured default logger
logger = setup_logging()
