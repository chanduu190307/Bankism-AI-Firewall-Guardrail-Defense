"""Thread-safe audit trail service recording security events and defense metrics."""

import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

from bankism.app.core.logging import redact_sensitive_dict
from bankism.app.schemas.requests import AuditLogRecord

MAX_AUDIT_CAPACITY = 2000


class AuditService:
    """Thread-safe in-memory audit log and metrics accumulator."""

    def __init__(self, max_capacity: int = MAX_AUDIT_CAPACITY) -> None:
        self._records: deque[AuditLogRecord] = deque(maxlen=max_capacity)
        self._lock = threading.Lock()
        self._total_requests = 0
        self._verdict_counts: dict[str, int] = {"APPROVE": 0, "BLOCK": 0, "REVIEW": 0}
        self._category_counts: dict[str, int] = {}

    def log_event(
        self,
        request_id: str,
        operation: str,
        account_id: str | None,
        recipient_id: str | None,
        amount: float | None,
        risk_score: int,
        risk_level: str,
        verdict: str,
        threat_category: str,
        threat_signals: list[str],
        executed: bool,
        reason: str,
    ) -> AuditLogRecord:
        """Appends a sanitized security event record to the audit stream."""
        raw_dict = {
            "account_id": account_id,
            "recipient_id": recipient_id,
        }
        sanitized = redact_sensitive_dict(raw_dict)

        record = AuditLogRecord(
            audit_id=f"aud-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            operation=operation,
            account_id=sanitized.get("account_id"),
            recipient_id=sanitized.get("recipient_id"),
            amount=amount,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            threat_category=threat_category,
            threat_signals=threat_signals,
            executed=executed,
            reason=reason,
        )

        with self._lock:
            self._records.append(record)
            self._total_requests += 1
            self._verdict_counts[verdict] = self._verdict_counts.get(verdict, 0) + 1
            self._category_counts[threat_category] = (
                self._category_counts.get(threat_category, 0) + 1
            )

        return record

    def get_logs(self, limit: int = 50, offset: int = 0) -> list[AuditLogRecord]:
        """Fetch audit logs in reverse chronological order."""
        with self._lock:
            items = list(self._records)
            items.reverse()
            return items[offset : offset + limit]

    def get_metrics(self) -> dict[str, Any]:
        """Compute live telemetry metrics."""
        with self._lock:
            return {
                "total_inspected_requests": self._total_requests,
                "verdict_distribution": dict(self._verdict_counts),
                "threat_distribution": dict(self._category_counts),
                "recorded_audit_entries": len(self._records),
            }

    def clear(self) -> None:
        """Reset audit logs for clean test runs."""
        with self._lock:
            self._records.clear()
            self._total_requests = 0
            self._verdict_counts = {"APPROVE": 0, "BLOCK": 0, "REVIEW": 0}
            self._category_counts.clear()


audit_service = AuditService()
