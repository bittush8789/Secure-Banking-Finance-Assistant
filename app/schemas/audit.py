"""Pydantic schemas for audit trail querying and reporting."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditEventRead(BaseModel):
    """Safe read representation of an append-only audit event."""

    audit_event_id: uuid.UUID
    request_id: str
    actor_id: str
    timestamp: datetime
    action_type: str
    redaction_status: str
    retrieved_document_ids: Optional[List[str]] = None
    guardrail_outcome: str
    model_invocation_outcome: str
    sanitized_response_summary: Optional[str] = None
    status: str
    client_ip: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    model_config = {
        "from_attributes": True,
    }


class AuditEventListResponse(BaseModel):
    """Paginated collection of audit records."""

    total_count: int = Field(description="Number of records returned in page")
    events: List[AuditEventRead] = Field(description="Audit events")
