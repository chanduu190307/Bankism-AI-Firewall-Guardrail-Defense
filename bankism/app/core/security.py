import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

from bankism.app.core.config import get_settings
from bankism.app.core.errors import InvalidExecutionTokenError

# In-memory store for consumed single-use tokens to prevent replay attacks
# Maps token nonce -> consumption timestamp (protected by thread lock)
_CONSUMED_NONCES: dict[str, float] = {}
_NONCE_LOCK = threading.Lock()


def reset_token_store() -> None:
    """Clear consumed nonces for isolated test execution."""
    with _NONCE_LOCK:
        _CONSUMED_NONCES.clear()


def generate_payload_hash(text: str) -> str:
    """Compute deterministic SHA-256 hash of prompt text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def create_execution_token(
    request_id: str,
    operation: str,
    account_id: str,
    recipient_id: str | None,
    amount: float | None,
    text: str,
    expires_in_seconds: int | None = None,
) -> str:
    """Generate a tamper-proof cryptographic execution token binding request context."""
    settings = get_settings()
    ttl = expires_in_seconds or settings.token_expiration_seconds
    now = time.time()

    payload_dict: dict[str, Any] = {
        "req_id": request_id,
        "op": operation,
        "acc": account_id,
        "rec": recipient_id,
        "amt": amount,
        "hash": generate_payload_hash(text),
        "exp": int(now + ttl),
        "nonce": secrets.token_hex(16),
    }

    payload_json = json.dumps(payload_dict, sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")

    signature = hmac.new(
        key=settings.secret_key.encode("utf-8"),
        msg=payload_b64.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    return f"{payload_b64}.{signature}"


def verify_execution_token(
    token: str,
    expected_operation: str,
    expected_account_id: str,
    expected_recipient_id: str | None,
    expected_amount: float | None,
    expected_text: str | None = None,
) -> dict[str, Any]:
    """Verify cryptographic token integrity, contextual binding, expiration, and replay prevention.

    Raises:
        InvalidExecutionTokenError: If token is malformed, expired, tampered, or mismatched.
    """
    settings = get_settings()
    now = time.time()

    # Clean up expired nonces in registry
    _cleanup_expired_nonces(now)

    if not token or "." not in token:
        raise InvalidExecutionTokenError("Execution token format is invalid or missing.")

    parts = token.split(".", 1)
    payload_b64, signature = parts[0], parts[1]

    # Verify HMAC signature in constant time
    expected_sig = hmac.new(
        key=settings.secret_key.encode("utf-8"),
        msg=payload_b64.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise InvalidExecutionTokenError("Execution token cryptographic signature is invalid.")

    # Decode JSON payload
    try:
        payload_raw = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_raw)
        if not isinstance(payload, dict):
            raise InvalidExecutionTokenError("Execution token payload must be a JSON object.")
    except InvalidExecutionTokenError:
        raise
    except Exception as exc:
        raise InvalidExecutionTokenError("Execution token payload could not be decoded.") from exc

    # Check expiration
    if payload.get("exp", 0) < now:
        raise InvalidExecutionTokenError("Execution token has expired.")

    # Check replay prevention (single use)
    nonce = payload.get("nonce")
    if not nonce:
        raise InvalidExecutionTokenError("Execution token missing unique nonce.")

    with _NONCE_LOCK:
        if nonce in _CONSUMED_NONCES:
            raise InvalidExecutionTokenError(
                "Execution token has already been consumed or has invalid nonce."
            )

    # Contextual binding checks
    if payload.get("op") != expected_operation:
        issued_op = payload.get("op")
        raise InvalidExecutionTokenError(
            f"Token operation mismatch: issued for '{issued_op}', attempted '{expected_operation}'."
        )

    if payload.get("acc") != expected_account_id:
        raise InvalidExecutionTokenError("Token account binding mismatch.")

    if payload.get("rec") != expected_recipient_id:
        raise InvalidExecutionTokenError("Token recipient binding mismatch.")

    # Amount comparison (float precision tolerance 0.001)
    token_amt = payload.get("amt")
    if expected_amount is not None:
        if token_amt is None or abs(float(token_amt) - float(expected_amount)) > 0.001:
            raise InvalidExecutionTokenError("Token transaction amount mismatch.")
    elif token_amt is not None:
        raise InvalidExecutionTokenError("Token specifies amount for non-monetary operation.")

    # If original text provided, verify payload hash
    if expected_text is not None:
        expected_hash = generate_payload_hash(expected_text)
        if payload.get("hash") != expected_hash:
            raise InvalidExecutionTokenError("Token prompt payload hash mismatch.")

    # Atomically claim nonce under lock to eliminate TOCTOU replay race conditions
    with _NONCE_LOCK:
        if nonce in _CONSUMED_NONCES:
            raise InvalidExecutionTokenError(
                "Execution token has already been consumed or has invalid nonce."
            )
        _CONSUMED_NONCES[nonce] = float(payload.get("exp", now + 300))

    return payload


def _cleanup_expired_nonces(now: float) -> None:
    """Prune expired nonces from memory to bound resource usage."""
    with _NONCE_LOCK:
        expired_keys = [k for k, exp in _CONSUMED_NONCES.items() if exp < now]
        for k in expired_keys:
            del _CONSUMED_NONCES[k]

