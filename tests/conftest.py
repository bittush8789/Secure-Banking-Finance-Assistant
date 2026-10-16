"""Shared pytest fixtures, mock token generators, and test environment configuration."""

import base64
import os
import time
from typing import AsyncGenerator, Dict, List, Optional
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Set test environment variables before importing app components
os.environ["APP_ENV"] = "test"
os.environ["AUTH_MOCK_ENABLED"] = "true"
os.environ["BEDROCK_MOCK_ENABLED"] = "true"
os.environ["TOKEN_VAULT_KEY_PROVIDER"] = "local_envelope"
os.environ["TOKEN_VAULT_LOCAL_KEY"] = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
os.environ["ENTRA_TENANT_ID"] = "11111111-2222-3333-4444-555555555555"
os.environ["ENTRA_AUDIENCE"] = "api://secure-finance-assistant"
os.environ["ENTRA_ISSUER"] = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
os.environ["AUDIT_STRICT_FAIL_SAFE"] = "true"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from app.core.config import settings
from app.core.security import entra_validator
from app.db.database import Base, get_db_session
from app.main import app

# Generate ephemeral RSA keypair for testing Entra ID signatures
_test_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
TEST_PRIVATE_KEY_PEM = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("ascii")

TEST_PUBLIC_KEY_PEM = _test_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")

# Register test public key with entra validator
entra_validator.set_mock_public_key(TEST_PUBLIC_KEY_PEM)


def generate_test_jwt(
    roles: Optional[List[str]] = None,
    tenant_id: Optional[str] = None,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    expires_in_seconds: int = 3600,
    actor_id: str = "test-actor-uuid-12345",
) -> str:
    """Helper to synthesize valid or invalid Entra ID JWT bearer tokens for test scenarios."""
    now = int(time.time())
    payload = {
        "sub": actor_id,
        "oid": actor_id,
        "tid": tenant_id or settings.ENTRA_TENANT_ID,
        "aud": audience or settings.ENTRA_AUDIENCE,
        "iss": issuer or settings.ENTRA_ISSUER,
        "iat": now,
        "nbf": now - 10,
        "exp": now + expires_in_seconds,
        "roles": roles or ["Complaints.Analyst", "Banking.Reader"],
        "preferred_username": "analyst.test@bank-corp.example",
    }
    return jwt.encode(payload, TEST_PRIVATE_KEY_PEM, algorithm="RS256")


@pytest.fixture
def valid_analyst_token() -> str:
    """Token with Complaints.Analyst role."""
    return generate_test_jwt(roles=["Complaints.Analyst"])


@pytest.fixture
def valid_reader_token() -> str:
    """Token with Banking.Reader role."""
    return generate_test_jwt(roles=["Banking.Reader"])


@pytest.fixture
def valid_token_admin_token() -> str:
    """Token with TokenVault.Admin role."""
    return generate_test_jwt(roles=["TokenVault.Admin"])


@pytest.fixture
def valid_audit_viewer_token() -> str:
    """Token with Audit.Viewer role."""
    return generate_test_jwt(roles=["Audit.Viewer"])


@pytest.fixture
def unauthorized_token() -> str:
    """Token without any relevant banking roles."""
    return generate_test_jwt(roles=["Unrelated.Guest"])


@pytest.fixture
def expired_token() -> str:
    """Token that expired in the past."""
    return generate_test_jwt(roles=["Complaints.Analyst"], expires_in_seconds=-3600)


@pytest.fixture
def wrong_tenant_token() -> str:
    """Token issued by a foreign / untrusted tenant."""
    return generate_test_jwt(
        roles=["Complaints.Analyst"],
        tenant_id="99999999-9999-9999-9999-999999999999",
        issuer="https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0",
    )


# In-memory SQLite async test database fixture
test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


@pytest.fixture
async def async_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provides an isolated in-memory test database session."""
    import app.db.models  # noqa: F401
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def client(async_db_session: AsyncSession) -> TestClient:
    """TestClient with database session dependency overridden."""
    async def override_get_db():
        yield async_db_session

    app.dependency_overrides[get_db_session] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
