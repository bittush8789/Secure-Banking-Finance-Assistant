"""Pydantic schemas for complaint summarization."""

from typing import Optional
from pydantic import BaseModel, Field


class ComplaintSummarizeRequest(BaseModel):
    """Input payload for customer complaint summarization."""

    complaint_text: str = Field(
        ...,
        min_length=10,
        max_length=4000,
        description="Raw customer complaint text containing potential PII to be redacted before model processing",
        examples=[
            "Customer John Doe (account 1234567890, phone 555-0199) called regarding a duplicate debit of $45.00."
        ],
    )
    complaint_reference_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Optional upstream ticket or dispute ID",
    )
    store_reversible_tokens: bool = Field(
        default=False,
        description="Whether to store encrypted token mappings in the restricted token vault for reversible de-anonymization",
    )


class ComplaintSummarizeResponse(BaseModel):
    """Output payload delivering sanitized summary and processing metadata."""

    request_id: str = Field(description="Unique correlation ID for tracking and audit")
    status: str = Field(description="Processing status: SUCCESS or REJECTED")
    customer_issue: str = Field(description="Identified customer issue without unverified claims")
    requested_resolution: str = Field(description="Explicitly identified desired outcome")
    suggested_next_steps: str = Field(description="Operational procedure recommendations for bank employee")
    sanitized_summary: str = Field(description="Full sanitized summary free of raw customer PII")
    redacted_entities_count: int = Field(description="Number of PII entities identified and masked")
    guardrail_status: str = Field(description="Input/output safety validation status: PASSED or INTERVENED")
