"""Application configuration management using Pydantic Settings."""

import os
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Secure Finance Assistant Configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Core Application Settings
    APP_NAME: str = Field(default="secure-finance-assistant", description="Application service name")
    APP_ENV: str = Field(default="production", description="Environment: development, test, or production")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    HOST: str = Field(default="0.0.0.0", description="Bind host")
    PORT: int = Field(default=8000, description="Bind port")
    LOG_LEVEL: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR")
    API_V1_STR: str = Field(default="/api/v1", description="API v1 prefix")

    # Microsoft Entra ID (Azure AD) Authentication Settings
    ENTRA_TENANT_ID: str = Field(
        default="00000000-0000-0000-0000-000000000000",
        description="Azure AD Tenant UUID",
    )
    ENTRA_CLIENT_ID: str = Field(
        default="00000000-0000-0000-0000-000000000000",
        description="Azure AD App Registration Client ID",
    )
    ENTRA_AUDIENCE: str = Field(
        default="api://secure-finance-assistant",
        description="Token audience to validate",
    )
    ENTRA_ISSUER: Optional[str] = Field(
        default=None,
        description="Expected token issuer. If None, derived from ENTRA_TENANT_ID",
    )
    ENTRA_JWKS_CACHE_TTL_SECONDS: int = Field(
        default=86400,
        description="Cache TTL for downloaded Entra ID JWKS public keys",
    )
    AUTH_MOCK_ENABLED: bool = Field(
        default=False,
        description="Enable offline test token verification without live Entra ID call",
    )

    # Database Settings (PostgreSQL)
    POSTGRES_SERVER: str = Field(default="localhost", description="PostgreSQL host")
    POSTGRES_PORT: int = Field(default=5432, description="PostgreSQL port")
    POSTGRES_DB: str = Field(default="secure_banking", description="Database name")
    POSTGRES_USER: str = Field(default="app_audit_writer", description="Database user")
    POSTGRES_PASSWORD: str = Field(default="dev_password_change_in_prod", description="Database password")
    DATABASE_URL: Optional[str] = Field(
        default=None,
        description="Async PostgreSQL connection string. Derived if not supplied.",
    )
    DATABASE_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool size")
    DATABASE_MAX_OVERFLOW: int = Field(default=20, description="SQLAlchemy connection pool max overflow")
    DATABASE_TIMEOUT_SECONDS: int = Field(default=10, description="Database connection timeout")
    AUDIT_STRICT_FAIL_SAFE: bool = Field(
        default=True,
        description="If True, any failure during audit trail persistence aborts API request",
    )

    # Amazon Bedrock Settings
    AWS_REGION: str = Field(default="us-east-1", description="AWS Region for Bedrock & KMS")
    BEDROCK_MODEL_ID: str = Field(
        default="anthropic.claude-3-haiku-20240307-v1:0",
        description="Amazon Bedrock Model identifier",
    )
    BEDROCK_GUARDRAIL_ID: Optional[str] = Field(
        default=None,
        description="Amazon Bedrock Guardrail Identifier",
    )
    BEDROCK_GUARDRAIL_VERSION: str = Field(
        default="1",
        description="Amazon Bedrock Guardrail Version (e.g. 1 or DRAFT)",
    )
    BEDROCK_INVOCATION_TIMEOUT_SECONDS: int = Field(
        default=30,
        description="Timeout for Bedrock API calls",
    )
    BEDROCK_ENDPOINT_URL: Optional[str] = Field(
        default=None,
        description="Optional custom VPC endpoint URL for bedrock-runtime",
    )
    BEDROCK_MOCK_ENABLED: bool = Field(
        default=False,
        description="Mock Bedrock responses for local unit testing without AWS connectivity",
    )

    # Token Vault & Cryptographic Key Management Settings
    TOKEN_VAULT_KEY_PROVIDER: str = Field(
        default="kms",
        description="Key management provider: 'kms' or 'local_envelope'",
    )
    TOKEN_VAULT_KMS_KEY_ARN: Optional[str] = Field(
        default=None,
        description="AWS KMS Key ARN for token encryption",
    )
    TOKEN_VAULT_LOCAL_KEY: Optional[str] = Field(
        default=None,
        description="Base64 32-byte key for local envelope encryption in dev/test",
    )
    TOKEN_VAULT_DEFAULT_EXPIRY_DAYS: int = Field(
        default=90,
        description="Retention lifetime in days for reversible token mappings",
    )

    # Content Safety & Document Retrieval Settings
    MAX_INPUT_TEXT_LENGTH: int = Field(
        default=4000,
        description="Maximum allowed input character length to prevent buffer/DOS attacks",
    )
    PROCEDURE_DOCS_DIRECTORY: str = Field(
        default="data/banking_procedures",
        description="Local path containing approved banking procedure markdown documents",
    )
    ENABLE_PROMPT_INJECTION_FILTER: bool = Field(
        default=True,
        description="Enable application-level prompt injection detection filter",
    )
    ENABLE_OUTPUT_SAFETY_FILTER: bool = Field(
        default=True,
        description="Enable post-model response validation and PII leakage checks",
    )

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, v: Optional[str], info) -> str:
        if v and isinstance(v, str) and len(v.strip()) > 0:
            return v
        data = info.data
        user = data.get("POSTGRES_USER", "app_audit_writer")
        pwd = data.get("POSTGRES_PASSWORD", "dev_password_change_in_prod")
        server = data.get("POSTGRES_SERVER", "localhost")
        port = data.get("POSTGRES_PORT", 5432)
        db = data.get("POSTGRES_DB", "secure_banking")
        return f"postgresql+asyncpg://{user}:{pwd}@{server}:{port}/{db}"

    @field_validator("ENTRA_ISSUER", mode="before")
    @classmethod
    def assemble_entra_issuer(cls, v: Optional[str], info) -> str:
        if v and isinstance(v, str) and len(v.strip()) > 0:
            return v
        tenant_id = info.data.get("ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000000")
        return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


# Singleton configuration instance
settings = Settings()
