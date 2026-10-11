"""FastAPI dependency injection providers for security contexts and services."""

import time
from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from bankism.app.banking.mock_executor import MockBankingExecutor, mock_executor
from bankism.app.core.config import get_settings
from bankism.app.services.analysis_service import AnalysisService, analysis_service
from bankism.app.services.audit_service import AuditService, audit_service

# In-memory rate limiting tracking: client_ip -> list of timestamps
_RATE_LIMIT_STORE: dict[str, list[float]] = {}


def get_current_principal(
    x_principal_id: Annotated[str | None, Header(alias="X-Principal-ID")] = None,
) -> str:
    """Extract authenticated principal identifier from server-controlled header.

    Defaults to 'user_alice' for demonstration and testing purposes.
    """
    return x_principal_id or "user_alice"


def get_analysis_service() -> AnalysisService:
    """Provide singleton analysis service."""
    return analysis_service


def get_audit_service() -> AuditService:
    """Provide singleton audit service."""
    return audit_service


def get_banking_executor() -> MockBankingExecutor:
    """Provide singleton mock banking executor."""
    return mock_executor


def check_rate_limit(request: Request) -> None:
    """Simple sliding-window rate limiter per client IP."""
    settings = get_settings()
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    window_start = now - 60.0

    if client_ip not in _RATE_LIMIT_STORE:
        _RATE_LIMIT_STORE[client_ip] = []

    # Clean old timestamps
    _RATE_LIMIT_STORE[client_ip] = [t for t in _RATE_LIMIT_STORE[client_ip] if t > window_start]

    # Periodic cleanup of inactive IPs to bound memory usage
    if len(_RATE_LIMIT_STORE) > 500:
        stale_ips = [ip for ip, timestamps in _RATE_LIMIT_STORE.items() if not timestamps]
        for ip in stale_ips:
            _RATE_LIMIT_STORE.pop(ip, None)

    if len(_RATE_LIMIT_STORE[client_ip]) >= settings.rate_limit_per_minute:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before submitting additional requests.",
        )

    _RATE_LIMIT_STORE[client_ip].append(now)
