"""Automated unit tests for deterministic PII detection and redaction."""

import pytest
from app.services.pii_redaction import (
    PIIRedactionError,
    PIIRedactor,
    luhn_checksum,
    pii_redactor,
)


def test_luhn_checksum_valid_and_invalid():
    """Verify Luhn algorithm validation for payment card PANs."""
    # Known Luhn valid 16-digit PAN
    assert luhn_checksum("4000000000000002") is True
    # Invalidate check digit
    assert luhn_checksum("4000000000000003") is False
    # Short length (< 13 digits) rejected
    assert luhn_checksum("49927398716") is False
    # Standard Luhn valid 16-digit test card
    assert luhn_checksum("4532015112830366") is True
    # Invalidate one digit
    assert luhn_checksum("4532015112830367") is False


def test_redact_explicit_customer_names():
    """Test detection of names explicitly introduced via supported banking labels."""
    sample_text = (
        "Customer Name: Robert Langdon called regarding his checking account. "
        "The customer stated: Customer: Robert Langdon did not authorize this."
    )
    result = pii_redactor.redact(sample_text)

    # Both occurrences should map to the exact same stable placeholder
    assert "Robert Langdon" not in result.redacted_text
    assert "{{PERSON_1}}" in result.redacted_text
    assert result.entity_count == 2
    assert len(result.placeholder_to_original) == 1
    assert result.placeholder_to_original["{{PERSON_1}}"] == "Robert Langdon"


def test_redact_emails_and_phones():
    """Test detection of emails and phone numbers across formats."""
    sample_text = (
        "Customer contact: alice.smith@finance-corp.test or phone 555-0192. "
        "Alternate mobile is +1-555-0199."
    )
    result = pii_redactor.redact(sample_text)

    assert "alice.smith@finance-corp.test" not in result.redacted_text
    assert "555-0192" not in result.redacted_text
    assert "+1-555-0199" not in result.redacted_text
    assert "{{EMAIL_1}}" in result.redacted_text
    assert "{{PHONE_1}}" in result.redacted_text
    assert "{{PHONE_2}}" in result.redacted_text


def test_redact_accounts_and_customer_ids():
    """Test masking of IBANs, explicit account numbers, and customer IDs."""
    sample_text = (
        "Customer ID: CUST-90184 requested details on Account: 981247192. "
        "Wire transfer was routed to IBAN: GB29XDDD01234567890123."
    )
    result = pii_redactor.redact(sample_text)

    assert "CUST-90184" not in result.redacted_text
    assert "981247192" not in result.redacted_text
    assert "GB29XDDD01234567890123" not in result.redacted_text
    assert "{{CUSTOMER_ID_1}}" in result.redacted_text
    assert "{{ACCOUNT_1}}" in result.redacted_text
    assert "{{ACCOUNT_2}}" in result.redacted_text


def test_placeholder_stability_and_collision_avoidance():
    """Verify that identical entities share tokens and that pre-existing placeholders don't collide."""
    # User input includes an intentional spoofed token {{PERSON_1}}
    malicious_text = (
        "Customer: Jane Doe claims that {{PERSON_1}} took money from Account: 123456789."
    )
    result = pii_redactor.redact(malicious_text)

    assert "Jane Doe" not in result.redacted_text
    # To prevent collision with user's {{PERSON_1}}, the real Jane Doe must be allocated {{PERSON_2}}
    assert result.original_to_placeholder["Jane Doe"] == "{{PERSON_2}}"
    assert "{{PERSON_2}}" in result.redacted_text


def test_failure_closed_on_error(monkeypatch):
    """Verify that any exception during redaction fails closed and raises PIIRedactionError."""
    redactor = PIIRedactor()

    # Mock an unexpected error during regex search
    def broken_search(*args, **kwargs):
        raise RuntimeError("Unexpected memory corruption")

    monkeypatch.setattr(redactor, "_resolve_overlapping_spans", broken_search)

    with pytest.raises(PIIRedactionError) as exc_info:
        redactor.redact("Customer: John Doe")

    assert "PII Redaction failure" in str(exc_info.value)
