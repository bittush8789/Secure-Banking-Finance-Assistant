"""API router for banking procedure question answering."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_client_ip, require_banking_reader
from app.core.logging import logger
from app.core.security import AuthenticatedUser
from app.db.audit_repository import AuditPersistenceError, AuditRepository
from app.db.database import get_db_session
from app.schemas.chat import ChatAskRequest, ChatAskResponse
from app.services.bedrock_service import BedrockServiceError, bedrock_service
from app.services.input_guardrails import input_guardrails
from app.services.output_guardrails import output_guardrails
from app.services.pii_redaction import PIIRedactionError, pii_redactor
from app.services.procedure_retrieval import procedure_retrieval_service

router = APIRouter(prefix="/chat", tags=["Procedure Q&A"])


@router.post(
    "/ask",
    response_model=ChatAskResponse,
    summary="Ask Banking Procedure Question",
    description=(
        "Answers employee questions strictly grounded in approved banking procedures. "
        "Applies input guardrails, treats procedures as untrusted input, applies PII redaction, "
        "invokes Bedrock with Guardrails, and audits referenced documents."
    ),
)
async def ask_procedure_question(
    request: Request,
    payload: ChatAskRequest,
    current_user: AuthenticatedUser = Depends(require_banking_reader),
    db: AsyncSession = Depends(get_db_session),
) -> ChatAskResponse:
    request_id = str(uuid.uuid4())
    client_ip = get_client_ip(request)
    repo = AuditRepository(db)

    # 1. Input Security Checks (injection, malicious, off-topic)
    input_check = input_guardrails.evaluate_chat_question(payload.question)
    if not input_check.is_safe:
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="CHAT_ASK",
            redaction_status="SKIPPED",
            guardrail_outcome="BLOCKED",
            model_invocation_outcome="SKIPPED",
            status="FAILED",
            client_ip=client_ip,
            details={"violation": input_check.violation_category, "reason": input_check.reason},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Question rejected by security policies: {input_check.reason}",
        )

    # 2. Local Document Retrieval
    retrieved_snippets = procedure_retrieval_service.retrieve_relevant(
        query=payload.question,
        topic_filter=payload.procedure_topic_filter,
        top_k=2,
    )
    referenced_doc_ids = [s.doc_id for s in retrieved_snippets]

    # 3. Format retrieved documents as UNTRUSTED context
    untrusted_context = procedure_retrieval_service.format_untrusted_context(retrieved_snippets)

    # 4. Redact potential PII from question if employee entered customer details
    try:
        redaction_res = pii_redactor.redact(payload.question)
    except PIIRedactionError as exc:
        logger.error(f"Redaction failed on chat question: {str(exc)}")
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="CHAT_ASK",
            redaction_status="FAILED",
            guardrail_outcome="PASSED",
            model_invocation_outcome="SKIPPED",
            status="FAILED",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Safety preprocessing failure.",
        )

    # 5. Amazon Bedrock Invocation with Guardrails
    try:
        bedrock_res = bedrock_service.answer_procedure_question(
            sanitized_question=redaction_res.redacted_text,
            untrusted_procedure_context=untrusted_context,
        )
    except BedrockServiceError as exc:
        logger.error(f"Bedrock chat failure for request_id={request_id}: {str(exc)}")
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="CHAT_ASK",
            redaction_status="REDACTED" if redaction_res.entity_count > 0 else "NOT_APPLICABLE",
            retrieved_document_ids=referenced_doc_ids,
            guardrail_outcome="ERROR",
            model_invocation_outcome="ERROR",
            status="FAILED",
            client_ip=client_ip,
            details={"error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI inference provider failed to answer question.",
        )

    guardrail_status = "INTERVENED" if bedrock_res.guardrail_intervened else "PASSED"

    # 6. Post-Model Output Guardrails Check
    output_check = output_guardrails.validate_procedure_answer(bedrock_res.text)
    if not output_check.is_safe:
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="CHAT_ASK",
            redaction_status="REDACTED" if redaction_res.entity_count > 0 else "NOT_APPLICABLE",
            retrieved_document_ids=referenced_doc_ids,
            guardrail_outcome="BLOCKED",
            model_invocation_outcome="SUCCESS",
            status="FAILED",
            client_ip=client_ip,
            details={"output_violation": output_check.violation_category},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Model output violated safety policies: {output_check.reason}",
        )

    # 7. Audit Persistence
    try:
        await repo.record_event(
            request_id=request_id,
            actor_id=current_user.actor_id,
            action_type="CHAT_ASK",
            redaction_status="REDACTED" if redaction_res.entity_count > 0 else "NOT_APPLICABLE",
            retrieved_document_ids=referenced_doc_ids,
            guardrail_outcome=guardrail_status,
            model_invocation_outcome="SUCCESS",
            status="SUCCESS",
            sanitized_response_summary=output_check.sanitized_output[:300],
            client_ip=client_ip,
            details={
                "retrieved_count": len(retrieved_snippets),
                "latency_ms": bedrock_res.latency_ms,
                "token_usage": bedrock_res.usage,
            },
        )
    except AuditPersistenceError as exc:
        logger.critical(f"Audit log failed for request_id={request_id}: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit logging service failure. Response withheld under strict compliance policy.",
        )

    return ChatAskResponse(
        request_id=request_id,
        sanitized_question=redaction_res.redacted_text,
        answer=output_check.sanitized_output,
        referenced_documents=referenced_doc_ids,
        guardrail_status=guardrail_status,
    )
