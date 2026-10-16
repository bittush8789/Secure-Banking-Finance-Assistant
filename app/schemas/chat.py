"""Pydantic schemas for banking procedure question answering."""

from typing import List, Optional
from pydantic import BaseModel, Field


class ChatAskRequest(BaseModel):
    """Input payload for banking procedure question answering."""

    question: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Banking procedure question submitted by employee",
        examples=["What is the procedure for handling duplicate card debits under Regulation E?"],
    )
    procedure_topic_filter: Optional[str] = Field(
        default=None,
        description="Optional procedure category filter (e.g. card_disputes, duplicate_payments)",
    )


class ChatAskResponse(BaseModel):
    """Output payload delivering grounded answer and procedure references."""

    request_id: str = Field(description="Unique correlation ID for audit and logging")
    sanitized_question: str = Field(description="Sanitized and PII-redacted version of the submitted question")
    answer: str = Field(description="Procedure response grounded strictly in approved bank procedure documents")
    referenced_documents: List[str] = Field(
        default_factory=list,
        description="List of approved banking procedure document filenames referenced",
    )
    guardrail_status: str = Field(description="Safety outcome: PASSED or INTERVENED")
