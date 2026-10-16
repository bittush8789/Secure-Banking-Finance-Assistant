"""SQLAlchemy database models for append-only audit logs and restricted token vault."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, JSON, LargeBinary, String, Text, Uuid

from app.db.database import Base


class AuditEvent(Base):
    """Append-only audit trail record.

    CRITICAL SECURITY INVARIANT:
    - Never store raw customer complaints, unredacted prompts, access tokens,
      original PII, or vault encryption keys in this table.
    - Application audit writer role has INSERT-only permissions.
    """

    __tablename__ = "audit_events"

    audit_event_id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
        comment="Unique identifier for the audit event",
    )
    request_id = Column(
        String(64),
        nullable=False,
        index=True,
        comment="Correlated HTTP or process request ID",
    )
    actor_id = Column(
        String(128),
        nullable=False,
        index=True,
        comment="Authenticated identity subject or object ID (never plain names)",
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Immutable UTC event timestamp",
    )
    action_type = Column(
        String(64),
        nullable=False,
        comment="Action performed: COMPLAINT_SUMMARIZE, CHAT_ASK, TOKEN_RESTORE, etc.",
    )
    redaction_status = Column(
        String(32),
        nullable=False,
        comment="REDACTED, FAILED, NOT_APPLICABLE, or SKIPPED",
    )
    retrieved_document_ids = Column(
        JSON,
        nullable=True,
        comment="List of referenced procedure document IDs",
    )
    guardrail_outcome = Column(
        String(32),
        nullable=False,
        comment="PASSED, BLOCKED, or INTERVENED",
    )
    model_invocation_outcome = Column(
        String(32),
        nullable=False,
        comment="SUCCESS, SKIPPED, or ERROR",
    )
    sanitized_response_summary = Column(
        Text,
        nullable=True,
        comment="Safe summary or hash reference (guaranteed free of unredacted PII)",
    )
    status = Column(
        String(32),
        nullable=False,
        comment="Overall execution status: SUCCESS or FAILED",
    )
    client_ip = Column(
        String(64),
        nullable=True,
        comment="Client IP address for perimeter forensics",
    )
    details = Column(
        JSON,
        nullable=True,
        comment="Sanitized operational metrics and metadata",
    )


class TokenVaultMapping(Base):
    """Encrypted reversible token vault storage.

    Stores sensitive PII mappings isolated from application text and LLM prompts.
    Original values are encrypted at rest using envelope encryption (KMS or AES-256-GCM).
    """

    __tablename__ = "token_vault_mappings"

    token_id = Column(
        String(128),
        primary_key=True,
        nullable=False,
        comment="Opaque unpredictable token placeholder (e.g. {{ACCOUNT_uuid}})",
    )
    request_id = Column(
        String(64),
        nullable=False,
        index=True,
        comment="Correlating request identifier",
    )
    token_type = Column(
        String(32),
        nullable=False,
        comment="Entity type: PERSON, PHONE, EMAIL, ACCOUNT, CUSTOMER_ID",
    )
    encrypted_value = Column(
        LargeBinary,
        nullable=False,
        comment="Ciphertext bytes of original PII value",
    )
    nonce = Column(
        String(64),
        nullable=False,
        comment="Hex or Base64 initialization vector / nonce",
    )
    auth_tag = Column(
        String(64),
        nullable=False,
        comment="AEAD authentication tag",
    )
    key_identifier = Column(
        String(256),
        nullable=False,
        comment="KMS Key ARN or Key Version ID used for envelope",
    )
    actor_id = Column(
        String(128),
        nullable=False,
        comment="Actor who submitted the payload requiring tokenization",
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Automatic expiration timestamp for data retention lifecycle",
    )


class TokenRestorationAudit(Base):
    """Dedicated audit trail for token de-anonymization / restoration attempts."""

    __tablename__ = "token_restoration_audits"

    restoration_id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    token_id = Column(
        String(128),
        nullable=False,
        index=True,
        comment="Token requested for restoration",
    )
    actor_id = Column(
        String(128),
        nullable=False,
        index=True,
        comment="Authorized actor requesting restoration",
    )
    reason = Column(
        Text,
        nullable=False,
        comment="Business justification / ticket reference for de-anonymization",
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    outcome = Column(
        String(32),
        nullable=False,
        comment="SUCCESS, DENIED, or FAILED",
    )
    client_ip = Column(
        String(64),
        nullable=True,
    )
