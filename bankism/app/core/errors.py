"""Custom error hierarchy and safe exception mappers for Bankism."""

from typing import Any


class BankismError(Exception):
    """Base exception for all Bankism domain errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class FirewallError(BankismError):
    """Base exception for firewall inspection failures."""


class PromptInjectionDetectedError(FirewallError):
    """Raised when an adversarial prompt injection or jailbreak is detected."""


class PolicyViolationError(FirewallError):
    """Raised when an untrusted input attempts to violate security policy."""


class ExecutionDeniedError(BankismError):
    """Raised when a banking operation is denied by the security boundary."""


class BankingError(BankismError):
    """Base exception for banking transaction execution failures."""


class InvalidTransactionError(BankingError):
    """Raised when transaction data fails schema or domain constraints."""


class AuthenticationError(BankingError):
    """Raised when caller identity cannot be verified."""


class AuthorizationError(BankingError):
    """Raised when caller lacks permission for the requested operation."""


class AccountNotFoundError(BankingError):
    """Raised when the specified source or recipient account does not exist."""


class InsufficientFundsError(BankingError):
    """Raised when an account lacks funds for a transfer."""


class TransactionLimitExceededError(BankingError):
    """Raised when a transfer exceeds the single-transaction ceiling."""


class DuplicateTransactionError(BankingError):
    """Raised when an idempotency key or duplicate transfer is replayed."""


class InvalidExecutionTokenError(BankingError):
    """Raised when an execution token is missing, expired, tampered, or mismatched."""


class ClassifierFailureError(FirewallError):
    """Raised when the AI classifier fails, times out, or returns unparseable content."""
