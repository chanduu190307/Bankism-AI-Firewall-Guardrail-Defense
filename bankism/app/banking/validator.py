"""Validation engine for banking operations, monetary constraints, and account formats."""

import math
import re

from bankism.app.core.config import get_settings
from bankism.app.core.errors import InvalidTransactionError
from bankism.app.schemas.requests import BankingExecuteRequest, BankingOperation

ACCOUNT_REGEX = re.compile(r"^ACC-[A-Z0-9]{3,12}$")


def validate_banking_transaction(request: BankingExecuteRequest) -> None:
    """Validates structural and financial constraints before authorization.

    Raises:
        InvalidTransactionError: If amounts, accounts, or operations violate banking invariants.
    """
    settings = get_settings()

    # 1. Validate Account identifier format
    if not ACCOUNT_REGEX.match(request.account_id):
        raise InvalidTransactionError(
            f"Source account '{request.account_id}' does not match bank format (e.g., ACC-1001)."
        )

    # 2. Validate Operation-specific constraints
    if request.operation == BankingOperation.TRANSFER:
        if not request.recipient_id:
            raise InvalidTransactionError("Recipient account identifier is required for transfers.")

        if not ACCOUNT_REGEX.match(request.recipient_id):
            raise InvalidTransactionError(
                f"Recipient account '{request.recipient_id}' does not match bank format."
            )

        if request.account_id == request.recipient_id:
            raise InvalidTransactionError("Source and recipient accounts cannot be identical.")

        if request.amount is None:
            raise InvalidTransactionError("Transfer amount must be specified.")

        # Check numerical sanity (no NaN, Inf, negative, zero)
        if math.isnan(request.amount) or math.isinf(request.amount) or request.amount <= 0:
            raise InvalidTransactionError("Transfer amount must be a positive, finite number > 0.")

        # Check precision (maximum 2 decimal places for currency)
        if abs(request.amount - round(request.amount, 2)) > 1e-4:
            raise InvalidTransactionError(
                "Transfer amount cannot exceed 2 decimal places of precision."
            )

        # Single transaction ceiling
        if request.amount > settings.max_transaction_limit:
            raise InvalidTransactionError(
                f"Transfer amount ${request.amount:.2f} exceeds maximum single transaction limit "
                f"(${settings.max_transaction_limit:.2f})."
            )

    elif request.operation == BankingOperation.BALANCE_INQUIRY:
        if request.amount is not None and request.amount > 0:
            raise InvalidTransactionError("Balance inquiries must not specify a transfer amount.")

    elif request.operation in (
        BankingOperation.STATEMENT_REQUEST,
        BankingOperation.CUSTOMER_SUPPORT,
    ):
        pass

    else:
        raise InvalidTransactionError(f"Unsupported banking operation: '{request.operation}'.")
