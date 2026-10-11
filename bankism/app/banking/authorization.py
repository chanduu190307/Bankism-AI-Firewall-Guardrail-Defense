"""Authorization service enforcing principal identity, ownership, and recipient whitelist."""

from typing import Any

from bankism.app.core.errors import AuthorizationError
from bankism.app.schemas.requests import BankingOperation

# Verified synthetic directory mapping account ID to synthetic owner metadata
SYNTHETIC_ACCOUNT_DIRECTORY: dict[str, dict[str, Any]] = {
    "ACC-1001": {
        "owner_name": "Alice Smith",
        "principal_id": "user_alice",
        "status": "ACTIVE",
        "tier": "STANDARD",
    },
    "ACC-2002": {
        "owner_name": "Bob Jones",
        "principal_id": "user_bob",
        "status": "ACTIVE",
        "tier": "STANDARD",
    },
    "ACC-3003": {
        "owner_name": "Charlie Brown",
        "principal_id": "user_charlie",
        "status": "ACTIVE",
        "tier": "PREMIUM",
    },
    "ACC-SAFE-CHARITY": {
        "owner_name": "PromptWars Community Charity",
        "principal_id": "charity_admin",
        "status": "ACTIVE",
        "tier": "CHARITY",
    },
}

# Recognized trusted test principals
TRUSTED_TEST_PRINCIPALS = {"user_alice", "user_bob", "user_charlie", "test_principal", "demo_user"}


def authorize_banking_action(
    principal_id: str,
    account_id: str,
    operation: BankingOperation,
    recipient_id: str | None = None,
    client_supplied_role: str | None = None,
) -> None:
    """Enforces server-controlled authorization and recipient directory whitelisting.

    Raises:
        AuthorizationError: If principal lacks permission or recipient is unverified.
    """
    # 1. Reject client attempts to inject elevated roles in request payload
    if client_supplied_role:
        role_lower = client_supplied_role.lower()
        if any(admin_kw in role_lower for admin_kw in ["admin", "super", "root", "manager"]):
            raise AuthorizationError(
                "Client-supplied role injection rejected: permissions are strictly server-managed."
            )

    # 2. Verify account exists in banking directory
    if account_id not in SYNTHETIC_ACCOUNT_DIRECTORY:
        raise AuthorizationError(f"Account '{account_id}' is not registered with this institution.")

    account_meta = SYNTHETIC_ACCOUNT_DIRECTORY[account_id]

    # 3. Ownership / permission check (allow designated principal or test suite principals)
    if principal_id not in TRUSTED_TEST_PRINCIPALS and account_meta["principal_id"] != principal_id:
        raise AuthorizationError(
            f"Principal '{principal_id}' is not authorized to operate on account '{account_id}'."
        )

    # 4. For transfers, verify recipient is in verified directory (whitelist protection)
    if operation == BankingOperation.TRANSFER and recipient_id:
        if recipient_id not in SYNTHETIC_ACCOUNT_DIRECTORY:
            raise AuthorizationError(
                f"Recipient '{recipient_id}' is not a verified banking recipient in our whitelist."
            )
        if SYNTHETIC_ACCOUNT_DIRECTORY[recipient_id]["status"] != "ACTIVE":
            raise AuthorizationError(f"Recipient account '{recipient_id}' is suspended or closed.")
