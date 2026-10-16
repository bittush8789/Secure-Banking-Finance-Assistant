"""API router for querying append-only audit trail records."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import require_audit_viewer
from app.core.security import AuthenticatedUser
from app.db.audit_repository import AuditRepository
from app.db.database import get_db_session
from app.schemas.audit import AuditEventListResponse, AuditEventRead

router = APIRouter(prefix="/audit", tags=["Compliance & Audit"])


@router.get(
    "/events",
    response_model=AuditEventListResponse,
    summary="List Sanitized Audit Events",
    description="Query append-only audit events with pagination and filtering. Restricted to Audit.Viewer role.",
)
async def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action_type: Optional[str] = Query(default=None),
    actor_id: Optional[str] = Query(default=None),
    current_user: AuthenticatedUser = Depends(require_audit_viewer),
    db: AsyncSession = Depends(get_db_session),
) -> AuditEventListResponse:
    repo = AuditRepository(db)
    events = await repo.list_events(
        limit=limit,
        offset=offset,
        action_type=action_type,
        actor_id=actor_id,
    )
    return AuditEventListResponse(
        total_count=len(events),
        events=[AuditEventRead.model_validate(e) for e in events],
    )


@router.get(
    "/events/{event_id}",
    response_model=AuditEventRead,
    summary="Get Audit Event Details by UUID",
    description="Retrieve full sanitized audit event metadata. Restricted to Audit.Viewer role.",
)
async def get_audit_event(
    event_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(require_audit_viewer),
    db: AsyncSession = Depends(get_db_session),
) -> AuditEventRead:
    repo = AuditRepository(db)
    event = await repo.get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit event '{event_id}' not found.",
        )
    return AuditEventRead.model_validate(event)
