"""Automated unit tests for Microsoft Entra ID token validation and RBAC."""

import pytest
from app.core.config import settings
from app.core.security import (
    AuthenticatedUser,
    TokenValidationError,
    entra_validator,
)
from tests.conftest import generate_test_jwt


def test_validate_valid_token():
    """Verify that a compliant Entra ID token validates successfully."""
    valid_token = generate_test_jwt(
        roles=["Complaints.Analyst", "Banking.Employee"],
        actor_id="usr-abc-12345",
    )
    user = entra_validator.validate_token(valid_token)

    assert isinstance(user, AuthenticatedUser)
    assert user.actor_id == "usr-abc-12345"
    assert user.has_role("Complaints.Analyst") is True
    assert user.has_role("Admin") is False
    assert user.has_any_role(["Complaints.Analyst", "SecurityAdmin"]) is True


def test_validate_expired_token(expired_token: str):
    """Verify that expired tokens are strictly rejected."""
    with pytest.raises(TokenValidationError) as exc_info:
        entra_validator.validate_token(expired_token)
    assert "expired" in str(exc_info.value).lower()


def test_validate_wrong_tenant_token(wrong_tenant_token: str):
    """Verify that tokens from an unauthorized tenant are rejected for tenant isolation."""
    with pytest.raises(TokenValidationError) as exc_info:
        entra_validator.validate_token(wrong_tenant_token)
    assert "tenant" in str(exc_info.value).lower() or "issuer" in str(exc_info.value).lower()

    # Verify direct tenant ID mismatch when issuer matches
    direct_tenant_mismatch = generate_test_jwt(
        tenant_id="99999999-9999-9999-9999-999999999999",
        issuer=settings.ENTRA_ISSUER,
    )
    with pytest.raises(TokenValidationError) as exc_info_2:
        entra_validator.validate_token(direct_tenant_mismatch)
    assert "tenant" in str(exc_info_2.value).lower()


def test_validate_audience_mismatch():
    """Verify that tokens intended for an external audience are rejected."""
    bad_aud_token = generate_test_jwt(audience="api://different-system")
    with pytest.raises(TokenValidationError) as exc_info:
        entra_validator.validate_token(bad_aud_token)
    assert "audience" in str(exc_info.value).lower()


def test_validate_empty_or_malformed_token():
    """Verify rejection of empty, whitespace, or garbage tokens."""
    with pytest.raises(TokenValidationError):
        entra_validator.validate_token("")

    with pytest.raises(TokenValidationError):
        entra_validator.validate_token("Bearer not-a-valid-jwt-structure")
