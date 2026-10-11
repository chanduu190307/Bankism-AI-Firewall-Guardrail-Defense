"""FastAPI route handlers for Bankism AI Firewall and Mock Banking API."""

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from bankism.app.api.dependencies import (
    check_rate_limit,
    get_analysis_service,
    get_audit_service,
    get_banking_executor,
    get_current_principal,
)
from bankism.app.banking.authorization import authorize_banking_action
from bankism.app.banking.mock_executor import MockBankingExecutor
from bankism.app.banking.validator import validate_banking_transaction
from bankism.app.core.config import get_settings
from bankism.app.core.errors import (
    AccountNotFoundError,
    AuthorizationError,
    DuplicateTransactionError,
    InsufficientFundsError,
    InvalidExecutionTokenError,
    InvalidTransactionError,
)
from bankism.app.schemas.requests import (
    AuditLogRecord,
    BankingExecuteRequest,
    BankingExecutionResponse,
    FirewallAnalyzeRequest,
    HealthResponse,
)
from bankism.app.schemas.verdicts import FirewallVerdict, Verdict
from bankism.app.services.analysis_service import AnalysisService
from bankism.app.services.audit_service import AuditService

router = APIRouter(prefix="/api/v1", tags=["Firewall & Banking"])
_APP_START_TIME = time.time()


@router.post(
    "/firewall/analyze",
    response_model=FirewallVerdict,
    summary="Analyze Customer Request for Adversarial Injections and Policy Violations",
    description=(
        "Inspects untrusted input and returns a security verdict. "
        "Never executes banking operations."
    ),
    dependencies=[Depends(check_rate_limit)],
)
async def analyze_request(
    request: FirewallAnalyzeRequest,
    analysis_svc: Annotated[AnalysisService, Depends(get_analysis_service)],
) -> FirewallVerdict:
    """Pass untrusted natural language request through the Bankism firewall pipeline."""
    return await analysis_svc.analyze(request)


@router.post(
    "/banking/execute",
    response_model=BankingExecutionResponse,
    summary="Execute Authorized Banking Operation",
    description=(
        "Executes a validated, authorized banking operation through the mock core. "
        "Enforces server-side firewall inspection, schema validation, ownership checks, "
        "and double-spending protection."
    ),
    dependencies=[Depends(check_rate_limit)],
)
async def execute_banking_operation(
    request: BankingExecuteRequest,
    principal: Annotated[str, Depends(get_current_principal)],
    analysis_svc: Annotated[AnalysisService, Depends(get_analysis_service)],
    executor: Annotated[MockBankingExecutor, Depends(get_banking_executor)],
    auditor: Annotated[AuditService, Depends(get_audit_service)],
) -> BankingExecutionResponse:
    """Executes banking operation with strict multi-stage defensive boundary enforcement."""
    # 1. Independent Authoritative Firewall Inspection if raw prompt provided
    if request.raw_prompt:
        analyze_req = FirewallAnalyzeRequest(
            request_id=request.request_id,
            text=request.raw_prompt,
            operation=request.operation,
            account_id=request.account_id,
            recipient_id=request.recipient_id,
            amount=request.amount,
            memo=request.memo,
        )
        verdict = await analysis_svc.analyze(analyze_req)
        if verdict.verdict != Verdict.APPROVE or not verdict.action_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "EXECUTION_DENIED",
                    "verdict": verdict.verdict.value,
                    "reason": f"Firewall blocked transaction: {verdict.reason}",
                    "threat_category": verdict.threat_category.value,
                    "risk_score": verdict.risk_score,
                },
            )

    # 2. Financial and Structural Transaction Validation
    try:
        validate_banking_transaction(request)
    except InvalidTransactionError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_TRANSACTION", "message": err.message},
        ) from err

    # 3. Server-Controlled Authorization and Whitelisting Check
    try:
        authorize_banking_action(
            principal_id=principal,
            account_id=request.account_id,
            operation=request.operation,
            recipient_id=request.recipient_id,
            client_supplied_role=request.client_role,
        )
    except AuthorizationError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "AUTHORIZATION_DENIED", "message": err.message},
        ) from err

    # 4. Atomic Execution in Mock Banking Core
    try:
        response = await executor.execute(request)

        # Audit log successful execution
        auditor.log_event(
            request_id=request.request_id,
            operation=request.operation.value,
            account_id=request.account_id,
            recipient_id=request.recipient_id,
            amount=request.amount,
            risk_score=0,
            risk_level="LOW",
            verdict="APPROVE",
            threat_category="NONE",
            threat_signals=[],
            executed=True,
            reason=f"Executed transaction {response.transaction_id} successfully.",
        )

        return response

    except InvalidExecutionTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "INVALID_EXECUTION_TOKEN", "message": err.message},
        ) from err
    except DuplicateTransactionError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "IDEMPOTENCY_CONFLICT", "message": err.message},
        ) from err
    except InsufficientFundsError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INSUFFICIENT_FUNDS", "message": err.message},
        ) from err
    except AccountNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "ACCOUNT_NOT_FOUND", "message": err.message},
        ) from err



@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application Health and Liveness Probe",
    description=(
        "Returns minimal service health information without exposing configuration secrets."
    ),
)
async def get_health() -> HealthResponse:
    """Returns application health metadata."""
    settings = get_settings()
    uptime = time.time() - _APP_START_TIME
    return HealthResponse(
        status="HEALTHY",
        version=settings.app_version,
        service=settings.app_name,
        classifier_status=f"ONLINE ({settings.ai_provider.upper()})",
        uptime_seconds=round(uptime, 2),
    )


@router.get(
    "/audit/logs",
    response_model=list[AuditLogRecord],
    summary="Query Sanitized Security Audit Log Stream",
)
async def query_audit_logs(
    limit: Annotated[int, Query(ge=1, le=200, description="Max logs to return (1-200)")] = 50,
    offset: Annotated[int, Query(ge=0, description="Offset index for pagination")] = 0,
    auditor: Annotated[AuditService, Depends(get_audit_service)] = None,  # type: ignore[assignment]
) -> list[AuditLogRecord]:
    """Retrieve sanitized security inspection events."""
    return auditor.get_logs(limit=limit, offset=offset)



@router.get(
    "/metrics",
    response_model=dict[str, Any],
    summary="Query Real-Time Firewall Security Metrics",
)
async def query_metrics(
    auditor: Annotated[AuditService, Depends(get_audit_service)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Return aggregated defense telemetry metrics."""
    return auditor.get_metrics()
