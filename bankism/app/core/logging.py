"""Structured logging with automated redaction of sensitive credentials and PII."""

import json
import logging
import re
import sys
from typing import Any

# Regex patterns for sensitive data masking
REDACTION_PATTERNS = [
    # API keys / Bearer tokens
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (
        re.compile(
            r"(api[_-]?key[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-]{8,}([\"']?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_API_KEY]\2",
    ),
    (
        re.compile(
            r"(secret[_-]?key[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-]{8,}([\"']?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\2",
    ),
    # Credit card-like 16 digit numbers
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "[REDACTED_CARD]"),
    # Bank Account numbers (e.g. ACC-12345678 or 8-12 digits)
    (re.compile(r"(ACC-)\d{4,12}", re.IGNORECASE), r"\1[REDACTED_ACC]"),
    (
        re.compile(
            r"(account_number[\"']?\s*[:=]\s*[\"']?)\d{6,16}([\"']?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_ACCOUNT]\2",
    ),
]


def redact_sensitive_text(text: str) -> str:
    """Mask credentials, tokens, account numbers, and card numbers from strings."""
    if not isinstance(text, str):
        return text
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_sensitive_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively mask sensitive values in nested dictionaries."""
    sensitive_keys = {
        "password",
        "secret",
        "token",
        "api_key",
        "secret_key",
        "authorization",
        "card_number",
        "cvv",
        "execution_token",
    }
    cleaned: dict[str, Any] = {}
    for k, v in data.items():
        if any(sk in k.lower() for sk in sensitive_keys):
            cleaned[k] = "[REDACTED]"
        elif isinstance(v, dict):
            cleaned[k] = redact_sensitive_dict(v)
        elif isinstance(v, list):
            cleaned[k] = [
                redact_sensitive_dict(item)
                if isinstance(item, dict)
                else redact_sensitive_text(str(item))
                if isinstance(item, str)
                else item
                for item in v
            ]
        elif isinstance(v, str):
            cleaned[k] = redact_sensitive_text(v)
        else:
            cleaned[k] = v
    return cleaned


class RedactingJsonFormatter(logging.Formatter):
    """Custom JSON formatter that sanitizes log records before emission."""

    def format(self, record: logging.LogRecord) -> str:
        base_message = record.getMessage()
        sanitized_message = redact_sensitive_text(base_message)

        log_payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitized_message,
        }

        # Include custom extra attributes if present
        for key in ("request_id", "verdict", "risk_score", "threat_category", "operation"):
            if hasattr(record, key):
                log_payload[key] = getattr(record, key)

        if record.exc_info:
            # Mask sensitive lines in traceback
            log_payload["exception"] = redact_sensitive_text(self.formatException(record.exc_info))

        return json.dumps(log_payload)


def setup_logger(name: str = "bankism", level: int = logging.INFO) -> logging.Logger:
    """Configure and return application logger with redaction formatter."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = RedactingJsonFormatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False

    return logger


logger = setup_logger()
