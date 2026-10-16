"""Automated unit tests for Amazon Bedrock service and Guardrails integration."""

import pytest
from botocore.exceptions import ClientError
from app.services.bedrock_service import BedrockResponse, BedrockService, BedrockServiceError


def test_bedrock_summarize_complaint_mock():
    """Verify Bedrock complaint summarization in mock mode."""
    service = BedrockService()
    service.mock_enabled = True

    response = service.summarize_complaint("Customer {{PERSON_1}} on Account {{ACCOUNT_1}} reported duplicate fee.")

    assert isinstance(response, BedrockResponse)
    assert response.guardrail_intervened is False
    assert "Customer Issue" in response.text
    assert "Requested Resolution" in response.text
    assert "Suggested Next Steps" in response.text


def test_bedrock_answer_procedure_mock():
    """Verify Bedrock procedural Q&A in mock mode."""
    service = BedrockService()
    service.mock_enabled = True

    response = service.answer_procedure_question(
        sanitized_question="What is the timeframe for Regulation E duplicate claims?",
        untrusted_procedure_context="<approved_procedure_document id='card_disputes.md'>Timeline: 60 days</approved_procedure_document>",
    )

    assert isinstance(response, BedrockResponse)
    assert "PR-CARD-001" in response.text or "60" in response.text


def test_bedrock_handles_client_error(monkeypatch):
    """Verify that AWS ClientError is translated safely into BedrockServiceError."""
    service = BedrockService()
    service.mock_enabled = False

    class MockBotoClient:
        def converse(self, **kwargs):
            raise ClientError(
                error_response={"Error": {"Code": "AccessDeniedException", "Message": "IAM role missing bedrock:InvokeModel"}},
                operation_name="Converse",
            )

    monkeypatch.setattr(service, "_get_client", lambda: MockBotoClient())

    with pytest.raises(BedrockServiceError) as exc_info:
        service.summarize_complaint("Test prompt")

    assert "AccessDeniedException" in str(exc_info.value)
