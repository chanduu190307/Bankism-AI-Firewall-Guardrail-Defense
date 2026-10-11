"""Orchestration service coordinating firewall inspection and audit logging."""

import logging

from bankism.app.firewall.pipeline import FirewallPipeline
from bankism.app.schemas.requests import FirewallAnalyzeRequest
from bankism.app.schemas.verdicts import FirewallVerdict
from bankism.app.services.audit_service import AuditService, audit_service

logger = logging.getLogger("bankism.service.analysis")


class AnalysisService:
    """Coordinates incoming request inspection with audit record keeping."""

    def __init__(
        self,
        pipeline: FirewallPipeline | None = None,
        auditor: AuditService | None = None,
    ) -> None:
        self.pipeline = pipeline or FirewallPipeline()
        self.auditor = auditor or audit_service

    async def analyze(self, request: FirewallAnalyzeRequest) -> FirewallVerdict:
        """Inspects request using firewall pipeline and records structured audit trail."""
        verdict = await self.pipeline.inspect(request)

        # Audit event recording
        self.auditor.log_event(
            request_id=verdict.request_id,
            operation=request.operation.value,
            account_id=request.account_id,
            recipient_id=request.recipient_id,
            amount=request.amount,
            risk_score=verdict.risk_score,
            risk_level=verdict.risk_level.value,
            verdict=verdict.verdict.value,
            threat_category=verdict.threat_category.value,
            threat_signals=verdict.threat_signals,
            executed=False,  # Analyze endpoint NEVER executes
            reason=verdict.reason,
        )

        return verdict


analysis_service = AnalysisService()
