"""Automated unit tests for PostgreSQL audit trail persistence and fail-safe handling."""

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.audit_repository import AuditPersistenceError, AuditRepository
from app.db.models import AuditEvent


@pytest.mark.asyncio
async def test_audit_event_insertion(async_db_session: AsyncSession):
    """Test successful insertion of a sanitized audit event."""
    repo = AuditRepository(async_db_session)
    request_id = str(uuid.uuid4())

    event = await repo.record_event(
        request_id=request_id,
        actor_id="actor-usr-100",
        action_type="COMPLAINT_SUMMARIZE",
        redaction_status="REDACTED",
        guardrail_outcome="PASSED",
        model_invocation_outcome="SUCCESS",
        status="SUCCESS",
        retrieved_document_ids=None,
        sanitized_response_summary="Customer Issue: {{PERSON_1}} fee dispute",
        client_ip="192.168.1.10",
        details={"redacted_count": 2},
    )

    assert event.audit_event_id is not None
    assert event.request_id == request_id
    assert event.actor_id == "actor-usr-100"
    assert event.status == "SUCCESS"

    # Query back
    retrieved = await repo.get_event_by_id(event.audit_event_id)
    assert retrieved is not None
    assert retrieved.request_id == request_id
    assert retrieved.sanitized_response_summary == "Customer Issue: {{PERSON_1}} fee dispute"


@pytest.mark.asyncio
async def test_audit_fail_safe_behavior(monkeypatch, async_db_session: AsyncSession):
    """Verify that database commit errors trigger AuditPersistenceError when strict fail-safe is enabled."""
    repo = AuditRepository(async_db_session)

    # Force commit failure
    async def broken_commit():
        raise RuntimeError("Database disk full or connection dropped")

    monkeypatch.setattr(async_db_session, "commit", broken_commit)

    with pytest.raises(AuditPersistenceError):
        await repo.record_event(
            request_id=str(uuid.uuid4()),
            actor_id="actor-err",
            action_type="COMPLAINT_SUMMARIZE",
            redaction_status="REDACTED",
            guardrail_outcome="PASSED",
            model_invocation_outcome="SUCCESS",
            status="SUCCESS",
        )
