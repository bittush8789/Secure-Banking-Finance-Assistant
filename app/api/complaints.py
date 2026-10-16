"""API router for customer complaint summarization with PII redaction and audit."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_client_ip, require_complaint_analyst
from app.core.logging import logger
from app.core.security import AuthenticatedUser
from app.db.audit_repository import AuditPersistenceError, AuditRepository
from app.db.database import get_db_session
from app.schemas.complaint import ComplaintSummarizeRequest, ComplaintSummarizeResponse
from app.services.bedrock_service import BedrockServiceError, bedrock_service
from app.services.input_guardrails import input_guardrails
from app.services.output_guardrails import output_guardrails
from app.services.pii_redaction import PIIRedactionError, pii_redactor
from app.services.token_vault import TokenVaultError, token_vault_service

router = APIRouter(prefix="/complaints", tags=["Complaints Operations"])


@router.post(
    "/summarize",
    response_model=ComplaintSummarizeResponse,
    summary="Summarize Customer Complaint with PII Redaction",
    description=(
        "Accepts raw complaint text, executes deterministic PII redaction, "
        "invokes Amazon Bedrock with Guardrails, validates output safety, "
        "and logs an append-only audit event in PostgreSQL."
    ),
)
async def summarize_complaint(
    request: Request,
    payload: ComplaintSummarizeRequest,
    current_user: AuthenticatedUser = Depends(require_complaint_analyst),
    db: AsyncSession = Depends(get_db_session),
) -> ComplaintSummarizeResponse:
    request_id = str(uuid.uuid4())
    client_ip = get_client_ip(request)
    repo = AuditRepository(db)

    # 1. Input Security Guardrails Check
    input_check = input_guardrails.evaluate_complaint_input(payload.complaint_text)
    if not input_check.is_safe:
        # Audit the blocked request attempt
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="COMPLAINT_SUMMARIZE",
            redaction_status="SKIPPED",
            guardrail_outcome="BLOCKED",
            model_invocation_outcome="SKIPPED",
            status="FAILED",
            client_ip=client_ip,
            details={"violation_category": input_check.violation_category, "reason": input_check.reason},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input rejected by security guardrails: {input_check.reason}",
        )

    # 2. Deterministic PII Redaction (Occurs BEFORE model invocation)
    try:
        redaction_result = pii_redactor.redact(payload.complaint_text)
    except PIIRedactionError as exc:
        logger.error(f"Redaction failure for request_id={request_id}: {str(exc)}")
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="COMPLAINT_SUMMARIZE",
            redaction_status="FAILED",
            guardrail_outcome="PASSED",
            model_invocation_outcome="SKIPPED",
            status="FAILED",
            client_ip=client_ip,
            details={"error": "PII redaction engine failed closed"},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PII Redaction safety check failed. Model invocation aborted.",
        )

    # 3. Optional Reversible Token Vault Storage (Encrypted at rest)
    if payload.store_reversible_tokens and redaction_result.entities:
        try:
            await token_vault_service.store_reversible_tokens(
                request_id=request_id,
                actor_id=current_user.actor_id,
                entities=redaction_result.entities,
                session=db,
            )
        except TokenVaultError as exc:
            logger.error(f"Token vault encryption failed for request_id={request_id}: {str(exc)}")
            await repo.record_event(
                request_id=request_id,
                actor_id=current_user.actor_id,
                action_type="COMPLAINT_SUMMARIZE",
                redaction_status="REDACTED",
                guardrail_outcome="PASSED",
                model_invocation_outcome="SKIPPED",
                status="FAILED",
                client_ip=client_ip,
                details={"error": "Failed to store encrypted reversible tokens"},
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token vault encryption service unavailable. Aborting operation.",
            )

    # 4. Amazon Bedrock Invocation with Redacted Prompt and Guardrails
    try:
        bedrock_res = bedrock_service.summarize_complaint(redaction_result.redacted_text)
    except BedrockServiceError as exc:
        logger.error(f"Bedrock invocation error for request_id={request_id}: {str(exc)}")
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="COMPLAINT_SUMMARIZE",
            redaction_status="REDACTED",
            guardrail_outcome="ERROR",
            model_invocation_outcome="ERROR",
            status="FAILED",
            client_ip=client_ip,
            details={"error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI inference provider failed to process complaint safely.",
        )

    # Check if Bedrock Guardrails intervened
    guardrail_status = "INTERVENED" if bedrock_res.guardrail_intervened else "PASSED"

    # 5. Output Safety and Policy Guardrails Check
    output_check = output_guardrails.validate_complaint_summary(bedrock_res.text)
    if not output_check.is_safe:
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="COMPLAINT_SUMMARIZE",
            redaction_status="REDACTED",
            guardrail_outcome="BLOCKED",
            model_invocation_outcome="SUCCESS",
            status="FAILED",
            client_ip=client_ip,
            details={"output_violation": output_check.violation_category, "reason": output_check.reason},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Model output violated banking safety policies: {output_check.reason}",
        )

    # 6. Parse structured summary sections
    summary_text = output_check.sanitized_output
    customer_issue = _extract_section(summary_text, "Customer Issue", "Customer reported an issue requiring investigation.")
    requested_resolution = _extract_section(summary_text, "Requested Resolution", "Customer requested review and remediation.")
    suggested_next_steps = _extract_section(summary_text, "Suggested Next Steps", "Follow standard dispute intake guidelines.")

    # 7. Persist Append-Only Sanitized Audit Trail
    # CRITICAL: Record only sanitized summary reference, never raw complaints or tokens
    try:
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="COMPLAINT_SUMMARIZE",
            redaction_status="REDACTED",
            guardrail_outcome=guardrail_status,
            model_invocation_outcome="SUCCESS",
            status="SUCCESS",
            sanitized_response_summary=summary_text[:300] + ("..." if len(summary_text) > 300 else ""),
            client_ip=client_ip,
            details={
                "redacted_entities_count": redaction_result.entity_count,
                "latency_ms": bedrock_res.latency_ms,
                "token_usage": bedrock_res.usage,
                "reversible_tokens_stored": payload.store_reversible_tokens,
            },
        )
    except AuditPersistenceError as exc:
        # Strict fail-safe: if audit log fails, do not return response to client
        logger.critical(f"Audit failure aborting response delivery for request_id={request_id}: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit logging service failure. Response withheld under strict compliance policy.",
        )

    # 8. Return Safe Response
    return ComplaintSummarizeResponse(
        request_id=request_id,
        status="SUCCESS",
        customer_issue=customer_issue,
        requested_resolution=requested_resolution,
        suggested_next_steps=suggested_next_steps,
        sanitized_summary=summary_text,
        redacted_entities_count=redaction_result.entity_count,
        guardrail_status=guardrail_status,
    )


def _extract_section(text: str, header: str, fallback: str) -> str:
    """Helper to parse labeled sections from model summary."""
    import re
    pattern = rf"(?i){header}\s*[:\-]\s*(.*?)(?=(?:Customer Issue|Requested Resolution|Suggested Next Steps|\Z))"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        content = match.group(1).strip()
        if content:
            return content
    return fallback
