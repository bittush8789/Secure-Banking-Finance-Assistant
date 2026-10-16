"""Deterministic PII detection and redaction engine for banking workloads.

IMPORTANT SECURITY NOTICE & LIMITATIONS:
Pattern-based regex detection is a deterministic safeguard suitable for standardized
banking data formats, explicit labels, and well-known identifiers. It DOES NOT and
CANNOT detect every subtle, contextual, or unlabelled occurrence of personal data.
In high-assurance production systems, this layer should be complemented with
contextual NER models, database tokenizers, and human-in-the-loop review.
"""

import re
from typing import Dict, List, NamedTuple, Optional, Set, Tuple


class PIIEntity(NamedTuple):
    """Metadata describing a detected PII entity."""

    entity_type: str
    original_value: str
    placeholder: str
    start: int
    end: int


class PIIRedactionResult(NamedTuple):
    """Result of a redaction operation."""

    redacted_text: str
    entities: List[PIIEntity]
    entity_count: int
    placeholder_to_original: Dict[str, str]
    original_to_placeholder: Dict[str, str]


class PIIRedactionError(Exception):
    """Raised when PII redaction fails.

    Fails closed: Any unhandled exception during redaction must halt processing
    and prevent LLM invocation.
    """

    pass


# Deterministic Detection Patterns
# 1. Email Addresses (RFC 5322 compatible regex)
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

# 2. Phone numbers (E.164, North American, UK, European international formats, and 7/10-digit domestic)
PHONE_PATTERN = re.compile(
    r"(?:(?:\+?[1-9]\d{0,2}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?:\s*(?:#|x\.?|ext\.?|extension)\s*\d+)?)"
    r"|\b\d{3}[-.\s]\d{4}\b"
)

# 3. Explicitly labelled customer names
# Matches constructs like: "Customer: Jane Doe", "Customer Name: John Doe", "Client: Bob Smith", "Name: Alice Wonder"
NAME_LABEL_PATTERN = re.compile(
    r"(?i:\b(?:customer(?:\s+name)?|client(?:\s+name)?|cardholder(?:\s+name)?|account\s+holder(?:\s+name)?|my\s+name\s+is|i\s+am|name)\s*[:=]\s*)([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})"
)

# 4. Bank Account numbers, IBANs, and Payment Card PANs
IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"
)

# Explicitly labelled bank accounts or routing numbers (e.g. Account: 123456789, Account Number: 9876543210)
ACCOUNT_LABEL_PATTERN = re.compile(
    r"(?i)\b(?:account(?:\s+number|\s+no\.?)?|acct(?:\s+no\.?)?|routing(?:\s+number)?|cif|iban)\s*[:=]\s*([0-9A-Za-z\-]{6,24})"
)

# Credit and Debit Card PANs (13-19 digits, optionally spaced or hyphenated)
CARD_PAN_PATTERN = re.compile(
    r"\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}|\d{13,19})\b"
)

# 5. Explicitly labelled customer IDs and Government IDs (SSN, Tax ID)
CUSTOMER_ID_PATTERN = re.compile(
    r"(?i)\b(?:customer\s*id|cust\s*id|client\s*id|member\s*id|ssn|social\s+security\s+number|tax\s*id)\s*[:=]?\s*([A-Z0-9]{3,4}[-.\s]?[A-Z0-9]{2,4}[-.\s]?[A-Z0-9]{2,9})\b"
)


def luhn_checksum(card_number_digits: str) -> bool:
    """Verify Luhn checksum for payment card numbers."""
    digits = [int(c) for c in card_number_digits if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        doubled = d * 2
        total += doubled - 9 if doubled > 9 else doubled
    return total % 10 == 0


class PIIRedactor:
    """Redacts personally identifiable information using deterministic rules and stable tokens."""

    def __init__(self):
        pass

    def redact(self, text: str, salt_collision_check: bool = True) -> PIIRedactionResult:
        """Scan input text, identify PII, and substitute with typed stable placeholders.

        Guarantees:
        - Placeholders remain consistent within the single request (same value -> same placeholder).
        - Placeholders do not collide with pre-existing user text.
        - Fails closed on any parse error.
        """
        if not text:
            return PIIRedactionResult(
                redacted_text="",
                entities=[],
                entity_count=0,
                placeholder_to_original={},
                original_to_placeholder={},
            )

        try:
            # Check for placeholder collision attack: user input attempting to spoof {{PERSON_1}}
            existing_placeholders = set(re.findall(r"\{\{[A-Z_]+_\d+\}\}", text))

            # Maintain stable mapping across identical values
            original_to_placeholder: Dict[str, str] = {}
            placeholder_to_original: Dict[str, str] = {}
            type_counters: Dict[str, int] = {
                "PERSON": 1,
                "PHONE": 1,
                "EMAIL": 1,
                "ACCOUNT": 1,
                "CUSTOMER_ID": 1,
            }

            # Gather candidate spans: (start, end, entity_type, raw_matched_value)
            raw_spans: List[Tuple[int, int, str, str]] = []

            # 1. Detect Explicit Names
            for match in NAME_LABEL_PATTERN.finditer(text):
                name_val = match.group(1).strip()
                start = match.start(1)
                end = match.end(1)
                raw_spans.append((start, end, "PERSON", name_val))

            # 2. Detect Emails
            for match in EMAIL_PATTERN.finditer(text):
                email_val = match.group(0).strip()
                raw_spans.append((match.start(), match.end(), "EMAIL", email_val))

            # 3. Detect Customer IDs & SSNs
            for match in CUSTOMER_ID_PATTERN.finditer(text):
                cid_val = match.group(1).strip()
                start = match.start(1)
                end = match.end(1)
                raw_spans.append((start, end, "CUSTOMER_ID", cid_val))

            # 4. Detect Explicit Account Numbers
            for match in ACCOUNT_LABEL_PATTERN.finditer(text):
                acct_val = match.group(1).strip()
                start = match.start(1)
                end = match.end(1)
                raw_spans.append((start, end, "ACCOUNT", acct_val))

            # 5. Detect IBANs
            for match in IBAN_PATTERN.finditer(text):
                iban_val = match.group(0).strip()
                raw_spans.append((match.start(), match.end(), "ACCOUNT", iban_val))

            # 6. Detect Card PANs with Luhn verification
            for match in CARD_PAN_PATTERN.finditer(text):
                candidate_pan = match.group(0).strip()
                digits_only = re.sub(r"\D", "", candidate_pan)
                if 13 <= len(digits_only) <= 19 and luhn_checksum(digits_only):
                    raw_spans.append((match.start(), match.end(), "ACCOUNT", candidate_pan))

            # 7. Detect Phone Numbers (avoiding overlapping already matched numbers)
            for match in PHONE_PATTERN.finditer(text):
                phone_val = match.group(0).strip()
                # Exclude trivial short matches or purely alphanumeric strings
                clean_phone = re.sub(r"[^\d+]", "", phone_val)
                if 7 <= len(clean_phone) <= 15:
                    raw_spans.append((match.start(), match.end(), "PHONE", phone_val))

            # Deduplicate and sort spans to handle overlaps (longest match first)
            resolved_spans = self._resolve_overlapping_spans(raw_spans)

            # Generate placeholders and build replacements
            entities: List[PIIEntity] = []
            replacements: List[Tuple[int, int, str]] = []

            for start, end, entity_type, raw_value in resolved_spans:
                # Normalise lookup key for consistency
                norm_val = raw_value.strip().lower() if entity_type == "EMAIL" else raw_value.strip()

                if norm_val in original_to_placeholder:
                    placeholder = original_to_placeholder[norm_val]
                else:
                    counter = type_counters[entity_type]
                    placeholder = f"{{{{{entity_type}_{counter}}}}}"

                    # Collision avoidance: If candidate placeholder appeared in raw text, advance counter
                    while placeholder in existing_placeholders:
                        counter += 1
                        placeholder = f"{{{{{entity_type}_{counter}}}}}"

                    type_counters[entity_type] = counter + 1
                    original_to_placeholder[norm_val] = placeholder
                    placeholder_to_original[placeholder] = raw_value

                entities.append(
                    PIIEntity(
                        entity_type=entity_type,
                        original_value=raw_value,
                        placeholder=placeholder,
                        start=start,
                        end=end,
                    )
                )
                replacements.append((start, end, placeholder))

            # Apply replacements from end to start to maintain index validity
            replacements.sort(key=lambda x: x[0], reverse=True)
            redacted_text = text
            for start, end, placeholder in replacements:
                redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]

            return PIIRedactionResult(
                redacted_text=redacted_text,
                entities=entities,
                entity_count=len(entities),
                placeholder_to_original=placeholder_to_original,
                original_to_placeholder=original_to_placeholder,
            )

        except Exception as exc:
            # Enforce fail-closed design: Never allow unhandled exceptions to bypass redaction
            raise PIIRedactionError(f"PII Redaction failure: {str(exc)}") from exc

    @staticmethod
    def _resolve_overlapping_spans(
        spans: List[Tuple[int, int, str, str]]
    ) -> List[Tuple[int, int, str, str]]:
        """Sort spans by start index and resolve any overlapping candidates by prioritizing longer spans."""
        if not spans:
            return []

        # Sort by start position asc, length desc
        sorted_spans = sorted(spans, key=lambda s: (s[0], -(s[1] - s[0])))
        resolved: List[Tuple[int, int, str, str]] = []

        last_end = -1
        for start, end, entity_type, val in sorted_spans:
            if start >= last_end:
                resolved.append((start, end, entity_type, val))
                last_end = end
            else:
                # Overlap detected; current span is within or clashes with previous accepted span
                continue

        return resolved


# Singleton redaction engine instance
pii_redactor = PIIRedactor()
