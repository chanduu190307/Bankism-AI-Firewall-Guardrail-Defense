import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from bankism.app.core.errors import (
    AccountNotFoundError,
    DuplicateTransactionError,
    InsufficientFundsError,
    InvalidExecutionTokenError,
)
from bankism.app.core.security import verify_execution_token
from bankism.app.schemas.requests import (
    BankingExecuteRequest,
    BankingExecutionResponse,
    BankingOperation,
    TransactionStatus,
)

# Initial synthetic ledger balances
DEFAULT_BALANCES: dict[str, float] = {
    "ACC-1001": 5000.00,
    "ACC-2002": 2500.00,
    "ACC-3003": 10000.00,
    "ACC-SAFE-CHARITY": 500.00,
}


class MockBankingExecutor:
    """Simulated banking core with atomic locking and idempotency protection."""

    def __init__(self) -> None:
        self._balances: dict[str, float] = dict(DEFAULT_BALANCES)
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()
        self._idempotency_cache: dict[str, tuple[dict[str, Any], BankingExecutionResponse]] = {}

    def _get_account_lock(self, account_id: str) -> asyncio.Lock:
        if account_id not in self._locks:
            self._locks[account_id] = asyncio.Lock()
        return self._locks[account_id]

    @staticmethod
    def _extract_transaction_params(request: BankingExecuteRequest) -> dict[str, Any]:
        """Extract canonical parameters for idempotency validation."""
        return {
            "op": request.operation.value,
            "acc": request.account_id,
            "rec": request.recipient_id,
            "amt": request.amount,
        }

    def reset(self) -> None:
        """Reset ledger state to defaults for clean test execution."""
        self._balances = dict(DEFAULT_BALANCES)
        self._idempotency_cache.clear()

    async def get_balance(self, account_id: str) -> float:
        """Read current synthetic balance."""
        if account_id not in self._balances:
            raise AccountNotFoundError(f"Account '{account_id}' does not exist.")
        return self._balances[account_id]

    async def execute(
        self,
        request: BankingExecuteRequest,
        verify_token: bool = True,
    ) -> BankingExecutionResponse:
        """Atomically executes a validated and authorized banking transaction.

        Guarantees:
        1. Cryptographic token verification binding operation, accounts, amount, and prompt.
        2. Idempotent replay protection with parameter conflict detection.
        3. Atomic balance updates preventing race conditions and double spending.
        """
        current_params = self._extract_transaction_params(request)

        # 1. Check idempotency cache first
        if request.idempotency_key and request.idempotency_key in self._idempotency_cache:
            cached_params, cached_response = self._idempotency_cache[request.idempotency_key]
            if cached_params != current_params:
                raise DuplicateTransactionError(
                    f"Idempotency key '{request.idempotency_key}' was previously used "
                    f"with conflicting transaction parameters."
                )
            return cached_response

        # 2. Verify single-use execution token
        if verify_token:
            if not request.execution_token:
                raise InvalidExecutionTokenError(
                    "Execution token is required to execute banking operations."
                )

            verify_execution_token(
                token=request.execution_token,
                expected_operation=request.operation.value,
                expected_account_id=request.account_id,
                expected_recipient_id=request.recipient_id,
                expected_amount=request.amount,
                expected_text=request.raw_prompt,
            )

        # 3. Handle Balance Inquiry
        if request.operation == BankingOperation.BALANCE_INQUIRY:
            balance = await self.get_balance(request.account_id)
            response = BankingExecutionResponse(
                transaction_id=f"TXN-{uuid.uuid4().hex[:10].upper()}",
                status=TransactionStatus.COMPLETED,
                operation=request.operation,
                source_account=request.account_id,
                recipient_account=None,
                amount=None,
                currency="USD",
                previous_balance=balance,
                new_balance=balance,
                message=f"Current available balance for {request.account_id} is ${balance:,.2f}.",
            )
            if request.idempotency_key:
                self._idempotency_cache[request.idempotency_key] = (current_params, response)
            return response


        # 4. Handle Simulated Transfer with atomic double-locking
        if request.operation == BankingOperation.TRANSFER:
            if not request.recipient_id or request.amount is None:
                raise AccountNotFoundError("Recipient and amount are required for transfers.")

            if request.account_id not in self._balances:
                raise AccountNotFoundError(f"Source account '{request.account_id}' not found.")
            if request.recipient_id not in self._balances:
                raise AccountNotFoundError(f"Recipient account '{request.recipient_id}' not found.")

            # Order locks consistently by account ID to prevent deadlocks
            first_acc, second_acc = sorted([request.account_id, request.recipient_id])
            first_lock = self._get_account_lock(first_acc)
            second_lock = self._get_account_lock(second_acc)

            async with first_lock:
                async with second_lock:
                    current_src_bal = self._balances[request.account_id]

                    if current_src_bal < request.amount:
                        raise InsufficientFundsError(
                            f"Account '{request.account_id}' has insufficient balance "
                            f"(${current_src_bal:.2f}) for transfer of ${request.amount:.2f}."
                        )

                    # Atomic state changes
                    new_src_bal = current_src_bal - request.amount
                    self._balances[request.account_id] = round(new_src_bal, 2)
                    self._balances[request.recipient_id] = round(
                        self._balances[request.recipient_id] + request.amount, 2
                    )

                    response = BankingExecutionResponse(
                        transaction_id=f"TXN-{uuid.uuid4().hex[:10].upper()}",
                        status=TransactionStatus.COMPLETED,
                        operation=request.operation,
                        source_account=request.account_id,
                        recipient_account=request.recipient_id,
                        amount=request.amount,
                        currency="USD",
                        previous_balance=round(current_src_bal, 2),
                        new_balance=round(new_src_bal, 2),
                        executed_at=datetime.now(timezone.utc).isoformat(),
                        message=(
                            f"Transferred ${request.amount:.2f} from {request.account_id} "
                            f"to {request.recipient_id} successfully."
                        ),
                    )

                    if request.idempotency_key:
                        self._idempotency_cache[request.idempotency_key] = (
                            current_params,
                            response,
                        )

                    return response

        # Default for non-monetary requests
        return BankingExecutionResponse(
            transaction_id=f"TXN-{uuid.uuid4().hex[:10].upper()}",
            status=TransactionStatus.COMPLETED,
            operation=request.operation,
            source_account=request.account_id,
            recipient_account=None,
            amount=None,
            currency="USD",
            previous_balance=None,
            new_balance=None,
            message="Operation acknowledged.",
        )


# Global singleton instance for application runtime
mock_executor = MockBankingExecutor()
