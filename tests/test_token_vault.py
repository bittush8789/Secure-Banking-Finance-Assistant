"""Automated unit tests for Token Vault envelope encryption and restricted restoration."""

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import AuthenticatedUser
from app.db.models import TokenRestorationAudit, TokenVaultMapping
from app.services.pii_redaction import PIIEntity
from app.services.token_vault import (
    TokenNotFoundError,
    TokenVaultService,
    UnauthorizedTokenRestorationError,
    token_vault_service,
)


@pytest.mark.asyncio
async def test_store_and_restore_token_authorized(async_db_session: AsyncSession):
    """Test full cycle of token storage and authorized restoration."""
    entities = [
        PIIEntity(
            entity_type="ACCOUNT",
            original_value="9876543210",
            placeholder="{{ACCOUNT_1}}",
            start=0,
            end=10,
        )
    ]

    # 1. Store Reversible Token
    stored_mappings = await token_vault_service.store_reversible_tokens(
        request_id="req-test-001",
        actor_id="actor-test-1",
        entities=entities,
        session=async_db_session,
    )
    assert "{{ACCOUNT_1}}" in stored_mappings
    token_id = stored_mappings["{{ACCOUNT_1}}"]
    assert token_id.startswith("{{ACCOUNT_TOKEN_")

    # 2. Authorized Compliance Officer attempts restoration
    compliance_officer = AuthenticatedUser(
        actor_id="officer-999",
        tenant_id="11111111-2222-3333-4444-555555555555",
        roles=["Compliance.Officer"],
    )

    restored = await token_vault_service.restore_token(
        token_id=token_id,
        user=compliance_officer,
        justification="Legitimate dispute investigation case DISP-2024-001",
        session=async_db_session,
        client_ip="10.0.1.5",
    )

    assert restored["token_id"] == token_id
    assert restored["original_value"] == "9876543210"

    # 3. Verify Restoration Audit Record exists and does NOT contain original value
    audit_query = select(TokenRestorationAudit).where(TokenRestorationAudit.token_id == token_id)
    result = await async_db_session.execute(audit_query)
    audit_rec = result.scalars().first()

    assert audit_rec is not None
    assert audit_rec.actor_id == "officer-999"
    assert audit_rec.outcome == "SUCCESS"
    assert audit_rec.reason == "Legitimate dispute investigation case DISP-2024-001"
    # Ensure plaintext PII is NOT in the audit record table
    assert "9876543210" not in audit_rec.reason


@pytest.mark.asyncio
async def test_restore_token_unauthorized(async_db_session: AsyncSession):
    """Test that unauthorized users are rejected and the denial is audited."""
    entities = [
        PIIEntity(
            entity_type="PERSON",
            original_value="Bruce Wayne",
            placeholder="{{PERSON_1}}",
            start=0,
            end=11,
        )
    ]

    stored_mappings = await token_vault_service.store_reversible_tokens(
        request_id="req-test-002",
        actor_id="actor-test-2",
        entities=entities,
        session=async_db_session,
    )
    token_id = stored_mappings["{{PERSON_1}}"]

    # Unauthorized banking employee attempts restoration
    regular_employee = AuthenticatedUser(
        actor_id="employee-123",
        tenant_id="11111111-2222-3333-4444-555555555555",
        roles=["Banking.Employee"],  # Lacks TokenVault.Admin or Compliance.Officer
    )

    with pytest.raises(UnauthorizedTokenRestorationError) as exc_info:
        await token_vault_service.restore_token(
            token_id=token_id,
            user=regular_employee,
            justification="Curious about customer identity",
            session=async_db_session,
        )

    assert "Actor lacks required" in str(exc_info.value)

    # Verify denial audit was logged
    audit_query = select(TokenRestorationAudit).where(TokenRestorationAudit.token_id == token_id)
    result = await async_db_session.execute(audit_query)
    audit_rec = result.scalars().first()

    assert audit_rec is not None
    assert audit_rec.actor_id == "employee-123"
    assert audit_rec.outcome == "DENIED"


@pytest.mark.asyncio
async def test_restore_nonexistent_token(async_db_session: AsyncSession):
    """Test restoration attempt for non-existent token."""
    compliance_officer = AuthenticatedUser(
        actor_id="officer-999",
        tenant_id="11111111-2222-3333-4444-555555555555",
        roles=["TokenVault.Admin"],
    )

    with pytest.raises(TokenNotFoundError):
        await token_vault_service.restore_token(
            token_id="{{ACCOUNT_TOKEN_nonexistent}}",
            user=compliance_officer,
            justification="Testing missing token",
            session=async_db_session,
        )
