"""Application-level input security guardrails and injection detection."""

import re
from typing import List, NamedTuple, Optional

from app.core.config import settings
from app.core.logging import logger


class InputGuardrailResult(NamedTuple):
    """Evaluation result of input security checks."""

    is_safe: bool
    action: str  # "PASSED" or "BLOCKED"
    violation_category: Optional[str] = None
    reason: Optional[str] = None


class InputGuardrailViolationError(Exception):
    """Raised when an input fails application security guardrails."""

    def __init__(self, category: str, reason: str):
        super().__init__(f"Input security check failed [{category}]: {reason}")
        self.category = category
        self.reason = reason


# Prompt injection and jailbreak signatures
INJECTION_PATTERNS = [
    (re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)\b"), "INJECTION_INSTRUCTION_OVERRIDE"),
    (re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+(?:directions|commands|rules)\b"), "INJECTION_INSTRUCTION_OVERRIDE"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+(?:(?:an?|in)\s+)?(?:unfiltered|uncensored|dan|jailbreak|developer\s+mode)\b"), "INJECTION_JAILBREAK"),
    (re.compile(r"(?i)\bdo\s+anything\s+now\b"), "INJECTION_JAILBREAK"),
    (re.compile(r"(?i)\bpretend\s+you\s+have\s+no\s+(?:rules|guidelines|restrictions)\b"), "INJECTION_ROLEPLAY_OVERRIDE"),
    (re.compile(r"(?i)\b(?:system\s*prompt|system\s*instructions|hidden\s*prompt)\s*:\s*(?:reveal|show|print|display|dump)\b"), "INJECTION_SECRET_EXPOSURE"),
    (re.compile(r"(?i)\b(?:reveal|print|show|output|leak)\s+(?:the\s+)?(?:system\s+(?:prompt|instructions)|developer\s+instructions|master\s+prompt)\b"), "INJECTION_SECRET_EXPOSURE"),
    (re.compile(r"(?i)\b(?:api[_\s]?keys?|aws[_\s]?(?:secret|access)[_\s]?(?:keys?)?|jwt[_\s]?tokens?|database[_\s]?passwords?)\b"), "INJECTION_SENSITIVE_CREDENTIAL"),
]

# Off-topic non-banking detection for banking procedure Q&A
OFF_TOPIC_PATTERNS = [
    (re.compile(r"(?i)\b(?:bake|recipe|cupcakes?|pasta|lasagna|cook\s+dinner)\b"), "OFF_TOPIC_CULINARY"),
    (re.compile(r"(?i)\b(?:write\s+(?:a\s+)?(?:poem|sonnet|rap\s+song|novel|screenplay|story))\b"), "OFF_TOPIC_CREATIVE_WRITING"),
    (re.compile(r"(?i)\b(?:python|javascript|c\+\+|java)\s+(?:code|script|program)\s+to\s+(?:hack|scrape|exploit|ddos)\b"), "MALICIOUS_CODE_REQUEST"),
]


class InputGuardrails:
    """Evaluates input text against size limits, prompt injections, and scope policies."""

    def __init__(self):
        self.max_length = settings.MAX_INPUT_TEXT_LENGTH
        self.enable_filter = settings.ENABLE_PROMPT_INJECTION_FILTER

    def evaluate_complaint_input(self, text: str) -> InputGuardrailResult:
        """Validate customer complaint input prior to PII redaction and Bedrock invocation."""
        # 1. Size and Malformed input checks
        size_check = self._check_text_size_and_encoding(text)
        if not size_check.is_safe:
            return size_check

        # 2. Prompt injection and jailbreak checks
        if self.enable_filter:
            injection_check = self._check_prompt_injection(text)
            if not injection_check.is_safe:
                return injection_check

        return InputGuardrailResult(is_safe=True, action="PASSED")

    def evaluate_chat_question(self, text: str) -> InputGuardrailResult:
        """Validate banking procedure question prior to retrieval and model invocation."""
        # 1. Size checks
        size_check = self._check_text_size_and_encoding(text)
        if not size_check.is_safe:
            return size_check

        # 2. Prompt injection checks
        if self.enable_filter:
            injection_check = self._check_prompt_injection(text)
            if not injection_check.is_safe:
                return injection_check

        # 3. Off-topic checks (specific to banking procedure assistant)
        off_topic_check = self._check_off_topic(text)
        if not off_topic_check.is_safe:
            return off_topic_check

        return InputGuardrailResult(is_safe=True, action="PASSED")

    def _check_text_size_and_encoding(self, text: str) -> InputGuardrailResult:
        if not text or not text.strip():
            return InputGuardrailResult(
                is_safe=False,
                action="BLOCKED",
                violation_category="EMPTY_INPUT",
                reason="Input text cannot be empty or purely whitespace.",
            )

        if len(text) > self.max_length:
            return InputGuardrailResult(
                is_safe=False,
                action="BLOCKED",
                violation_category="EXCESSIVE_LENGTH",
                reason=f"Input length {len(text)} exceeds maximum allowed limit of {self.max_length} characters.",
            )

        # Detect suspicious control characters (null bytes, non-printable characters)
        non_printable_count = sum(1 for c in text if ord(c) < 32 and c not in ("\n", "\r", "\t"))
        if non_printable_count > 5:
            return InputGuardrailResult(
                is_safe=False,
                action="BLOCKED",
                violation_category="MALFORMED_ENCODING",
                reason="Input contains excessive non-printable or malformed control characters.",
            )

        return InputGuardrailResult(is_safe=True, action="PASSED")

    def _check_prompt_injection(self, text: str) -> InputGuardrailResult:
        for pattern, category in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                matched_snippet = match.group(0)
                logger.warning(
                    f"INPUT_GUARDRAIL_BLOCKED: Detected potential prompt injection pattern [{category}]",
                    extra={"action_type": "INPUT_GUARDRAIL_BLOCKED"},
                )
                return InputGuardrailResult(
                    is_safe=False,
                    action="BLOCKED",
                    violation_category=category,
                    reason=f"Input matches security guardrail restriction for instruction override: '{category}'",
                )
        return InputGuardrailResult(is_safe=True, action="PASSED")

    def _check_off_topic(self, text: str) -> InputGuardrailResult:
        for pattern, category in OFF_TOPIC_PATTERNS:
            match = pattern.search(text)
            if match:
                logger.info(
                    f"INPUT_GUARDRAIL_BLOCKED: Rejected off-topic request [{category}]",
                    extra={"action_type": "INPUT_GUARDRAIL_OFF_TOPIC"},
                )
                return InputGuardrailResult(
                    is_safe=False,
                    action="BLOCKED",
                    violation_category=category,
                    reason="The banking procedure assistant only answers banking operational questions.",
                )
        return InputGuardrailResult(is_safe=True, action="PASSED")


# Global input guardrail instance
input_guardrails = InputGuardrails()
