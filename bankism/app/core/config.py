"""Application configuration and security settings for Bankism."""

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Immutable application settings validated via Pydantic."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General
    app_name: str = "Bankism AI Firewall & Guardrail Defense"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", alias="BANKISM_ENV")
    debug: bool = Field(default=False, alias="BANKISM_DEBUG")
    host: str = Field(default="127.0.0.1", alias="BANKISM_HOST")
    port: int = Field(default=8000, alias="BANKISM_PORT")

    # Cryptography & Token Binding
    secret_key: str = Field(
        default="bankism-secure-hmac-key-32-chars-minimum-token!",
        alias="BANKISM_SECRET_KEY",
    )
    token_expiration_seconds: int = Field(default=300, alias="BANKISM_TOKEN_EXPIRATION_SECONDS")

    # Resource & Request Boundaries
    max_request_bytes: int = Field(default=65536, alias="BANKISM_MAX_REQUEST_BYTES")  # 64 KB
    max_prompt_chars: int = Field(default=4000, alias="BANKISM_MAX_PROMPT_CHARS")
    max_transaction_limit: float = Field(default=1000.0, alias="BANKISM_MAX_TRANSACTION_LIMIT")

    # Risk Score Thresholds (0-100 scale)
    risk_low_max: int = Field(default=24, alias="BANKISM_RISK_LOW_MAX")
    risk_medium_max: int = Field(default=59, alias="BANKISM_RISK_MEDIUM_MAX")
    risk_high_max: int = Field(default=84, alias="BANKISM_RISK_HIGH_MAX")

    # AI Classifier Configuration
    ai_provider: str = Field(default="heuristic", alias="BANKISM_AI_PROVIDER")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-flash", alias="GEMINI_MODEL")
    ai_classifier_timeout_seconds: float = Field(default=2.0, alias="AI_CLASSIFIER_TIMEOUT_SECONDS")
    ai_fail_closed: bool = Field(default=True, alias="AI_FAIL_CLOSED")

    # Rate Limiting
    rate_limit_per_minute: int = Field(default=120, alias="BANKISM_RATE_LIMIT_PER_MINUTE")

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforce strict cryptographic configuration in production mode."""
        if self.environment.lower() == "production":
            default_key = "bankism-secure-hmac-key-32-chars-minimum-token!"
            if not self.secret_key or self.secret_key == default_key or len(self.secret_key) < 32:
                raise ValueError(
                    "Production configuration error: BANKISM_SECRET_KEY must be "
                    "explicitly configured with a secure key of at least 32 characters "
                    "in production environments."
                )

        return self


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton instance of application settings."""
    return Settings()

