"""Pydantic schemas for restricted token restoration."""

from datetime import datetime
from pydantic import BaseModel, Field


class TokenRestoreRequest(BaseModel):
    """Authorised request to de-anonymize a reversible token."""

    token_id: str = Field(
        ...,
        min_length=5,
        max_length=128,
        description="Opaque token identifier to de-anonymize (e.g. {{ACCOUNT_TOKEN_xxxx}} or UUID)",
        examples=["{{ACCOUNT_TOKEN_1a2b3c4d}}"],
    )
    justification_reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Mandatory business reason / compliance ticket for de-anonymization",
        examples=["Dispute investigation ticket DISP-2024-9918 verified by manager"],
    )


class TokenRestoreResponse(BaseModel):
    """Result of an authorized de-anonymization operation."""

    token_id: str
    token_type: str
    restored_value: str
    restored_at: datetime
    message: str = "Token restored successfully under compliance policy"
