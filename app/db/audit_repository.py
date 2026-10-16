"""Repository for audit trail persistence and restricted token vault access."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.models import AuditEvent, TokenRestorationAudit, TokenVaultMapping


class AuditPersistenceError(Exception):
    """Raised when an audit record fails to persist and fail-safe policy requires abort."""

    pass


class AuditRepository:
    """Handles append-only audit persistence and secure token vault queries."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def record_event(
        self,
        request_id: str,
        actor_id: str,
        action_type: str,
        redaction_status: str,
        guardrail_outcome: str,
        model_invocation_outcome: str,
        status: str,
        retrieved_document_ids: Optional[List[str]] = None,
        sanitized_response_summary: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append an immutable audit event record.

        CRITICAL: Never supply raw complaint text, unredacted PII, or access tokens.
        """
        try:
            event = AuditEvent(
                audit_event_id=uuid.uuid4(),
                request_id=request_id,
                actor_id=actor_id,
                timestamp=datetime.now(timezone.utc),
                action_type=action_type,
                redaction_status=redaction_status,
                retrieved_document_ids=retrieved_document_ids or [],
                guardrail_outcome=guardrail_outcome,
                model_invocation_outcome=model_invocation_outcome,
                sanitized_response_summary=sanitized_response_summary,
                status=status,
                client_ip=client_ip,
                details=details or {},
            )
            self.session.add(event)
            await self.session.commit()
            await self.session.refresh(event)
            return event
        except Exception as exc:
            await self.session.rollback()
            logger.error(
                f"AUDIT_FAILURE: Failed to persist audit record for request_id={request_id}: {str(exc)}",
                extra={"request_id": request_id, "actor_id": actor_id, "action_type": action_type},
            )
            if settings.AUDIT_STRICT_FAIL_SAFE:
                raise AuditPersistenceError(f"Audit log write failed: {str(exc)}") from exc
            raise

    async def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        action_type: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Query audit events with pagination for authorized auditors."""
        query = select(AuditEvent).order_by(desc(AuditEvent.timestamp)).limit(limit).offset(offset)
        if action_type:
            query = query.where(AuditEvent.action_type == action_type)
        if actor_id:
            query = query.where(AuditEvent.actor_id == actor_id)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_event_by_id(self, event_id: uuid.UUID) -> Optional[AuditEvent]:
        """Fetch a specific audit record by UUID."""
        query = select(AuditEvent).where(AuditEvent.audit_event_id == event_id)
        result = await self.session.execute(query)
        return result.scalars().first()

    async def store_token_mapping(
        self,
        token_id: str,
        request_id: str,
        token_type: str,
        encrypted_value: bytes,
        nonce: str,
        auth_tag: str,
        key_identifier: str,
        actor_id: str,
        expires_at: datetime,
    ) -> TokenVaultMapping:
        """Store an encrypted token vault mapping."""
        mapping = TokenVaultMapping(
            token_id=token_id,
            request_id=request_id,
            token_type=token_type,
            encrypted_value=encrypted_value,
            nonce=nonce,
            auth_tag=auth_tag,
            key_identifier=key_identifier,
            actor_id=actor_id,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        self.session.add(mapping)
        await self.session.commit()
        return mapping

    async def get_token_mapping(self, token_id: str) -> Optional[TokenVaultMapping]:
        """Fetch token vault entry by opaque token ID."""
        query = select(TokenVaultMapping).where(TokenVaultMapping.token_id == token_id)
        result = await self.session.execute(query)
        return result.scalars().first()

    async def record_restoration_attempt(
        self,
        token_id: str,
        actor_id: str,
        reason: str,
        outcome: str,
        client_ip: Optional[str] = None,
    ) -> TokenRestorationAudit:
        """Audit every attempt to reverse or de-anonymize a token."""
        record = TokenRestorationAudit(
            restoration_id=uuid.uuid4(),
            token_id=token_id,
            actor_id=actor_id,
            reason=reason,
            timestamp=datetime.now(timezone.utc),
            outcome=outcome,
            client_ip=client_ip,
        )
        self.session.add(record)
        await self.session.commit()
        return record
