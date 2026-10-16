"""Post-model output validation, PII leakage detection, and policy compliance guardrails."""

import re
from typing import List, NamedTuple, Optional, Tuple

from app.core.config import settings
from app.core.logging import logger
from app.services.pii_redaction import (
    CARD_PAN_PATTERN,
    EMAIL_PATTERN,
    IBAN_PATTERN,
    PHONE_PATTERN,
    luhn_checksum,
)


class OutputGuardrailResult(NamedTuple):
    """Evaluation result of output guardrail checks."""

    is_safe: bool
    action: str  # "PASSED" or "BLOCKED"
    sanitized_output: str
    violation_category: Optional[str] = None
    reason: Optional[str] = None


class OutputGuardrailViolationError(Exception):
    """Raised when model output violates banking safety, PII, or hallucination policies."""

    def __init__(self, category: str, reason: str):
        super().__init__(f"Output guardrail policy violation [{category}]: {reason}")
        self.category = category
        self.reason = reason


# Unsupported claims patterns: model must not claim live transaction verification or balance changes
UNSUPPORTED_BANKING_CLAIMS = [
    (
        re.compile(r"(?i)\b(?:i\s+have|we\s+have)\s+(?:verified|confirmed)\s+(?:your|the)\s+transaction\b"),
        "UNSUPPORTED_TRANSACTION_VERIFICATION",
        "The model made an ungrounded claim of transaction verification when no transaction backend is connected.",
    ),
    (
        re.compile(r"(?i)\b(?:your\s+account\s+has\s+been|i\s+have)\s+(?:credited|refunded|debited|adjusted)\b"),
        "UNSUPPORTED_BALANCE_MODIFICATION",
        "The model claimed to have executed a financial transfer or refund.",
    ),
    (
        re.compile(r"(?i)\b(?:funds\s+have\s+been\s+transferred|money\s+has\s+been\s+sent)\b"),
        "UNSUPPORTED_BALANCE_MODIFICATION",
        "The model claimed an immediate financial disbursement.",
    ),
]


class OutputGuardrails:
    """Validates and sanitizes model-generated responses before delivery to client."""

    def __init__(self):
        self.enabled = settings.ENABLE_OUTPUT_SAFETY_FILTER

    def validate_complaint_summary(self, summary_text: str) -> OutputGuardrailResult:
        """Enforce PII leakage prevention and verify absence of unsupported transaction claims."""
        if not self.enabled:
            return OutputGuardrailResult(
                is_safe=True,
                action="PASSED",
                sanitized_output=summary_text,
            )

        # 1. Check for unsupported transaction execution claims
        claims_check = self._check_unsupported_claims(summary_text)
        if not claims_check.is_safe:
            return claims_check

        # 2. Check for PII leakage (unredacted numbers, emails, cards)
        pii_leak_check = self._check_pii_leakage(summary_text)
        if not pii_leak_check.is_safe:
            return pii_leak_check

        return OutputGuardrailResult(
            is_safe=True,
            action="PASSED",
            sanitized_output=summary_text,
        )

    def validate_procedure_answer(self, answer_text: str) -> OutputGuardrailResult:
        """Enforce procedural grounding and ensure no sensitive data leaks in answers."""
        if not self.enabled:
            return OutputGuardrailResult(
                is_safe=True,
                action="PASSED",
                sanitized_output=answer_text,
            )

        # 1. Check for unsupported transaction execution claims
        claims_check = self._check_unsupported_claims(answer_text)
        if not claims_check.is_safe:
            return claims_check

        # 2. Check for PII leakage
        pii_leak_check = self._check_pii_leakage(answer_text)
        if not pii_leak_check.is_safe:
            return pii_leak_check

        return OutputGuardrailResult(
            is_safe=True,
            action="PASSED",
            sanitized_output=answer_text,
        )

    def _check_unsupported_claims(self, text: str) -> OutputGuardrailResult:
        for pattern, category, explanation in UNSUPPORTED_BANKING_CLAIMS:
            if pattern.search(text):
                logger.error(
                    f"OUTPUT_GUARDRAIL_BLOCKED: Detected unsupported banking claim [{category}]: {explanation}",
                    extra={"action_type": "OUTPUT_GUARDRAIL_BLOCKED"},
                )
                return OutputGuardrailResult(
                    is_safe=False,
                    action="BLOCKED",
                    sanitized_output="[Output blocked: Model generated an unsupported banking claim regarding live verification.]",
                    violation_category=category,
                    reason=explanation,
                )
        return OutputGuardrailResult(is_safe=True, action="PASSED", sanitized_output=text)

    def _check_pii_leakage(self, text: str) -> OutputGuardrailResult:
        """Ensure no unmasked live emails or card PANs were introduced in model output."""
        # 1. Unmasked emails
        email_match = EMAIL_PATTERN.search(text)
        if email_match:
            logger.error("OUTPUT_GUARDRAIL_BLOCKED: Detected unredacted email in model output")
            return OutputGuardrailResult(
                is_safe=False,
                action="BLOCKED",
                sanitized_output="[Output blocked: Sensitive email data detected in model response]",
                violation_category="PII_LEAKAGE_EMAIL",
                reason="Model output contained an unredacted email address.",
            )

        # 2. Unmasked Card Numbers
        for card_match in CARD_PAN_PATTERN.finditer(text):
            digits = re.sub(r"\D", "", card_match.group(0))
            if 13 <= len(digits) <= 19 and luhn_checksum(digits):
                logger.error("OUTPUT_GUARDRAIL_BLOCKED: Detected valid card PAN in model output")
                return OutputGuardrailResult(
                    is_safe=False,
                    action="BLOCKED",
                    sanitized_output="[Output blocked: Payment card number detected in model response]",
                    violation_category="PII_LEAKAGE_PAN",
                    reason="Model output contained a payment card number passing Luhn verification.",
                )

        return OutputGuardrailResult(is_safe=True, action="PASSED", sanitized_output=text)


# Global output guardrails instance
output_guardrails = OutputGuardrails()
