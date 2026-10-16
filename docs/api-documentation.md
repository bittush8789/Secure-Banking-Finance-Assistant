# API Documentation: Secure Banking & Finance Assistant

**API Base URL:** `http://localhost:8000/api/v1`  
**Authentication Scheme:** `Bearer <JWT>` issued by Microsoft Entra ID (Azure AD)  
**Content-Type:** `application/json`  

---

## 1. Authentication & Role-Based Access Control (RBAC)

All endpoints under `/api/v1` (except public health probes) require an HTTP Authorization header:

```http
Authorization: Bearer <JWT_ACCESS_TOKEN>
```

### Entra ID Application Roles

| Role Name | Description | Authorized Endpoints |
| :--- | :--- | :--- |
| `Complaints.Analyst` | Frontline and backoffice operations staff handling customer disputes. | `POST /api/v1/complaints/summarize` |
| `Banking.Reader` | Customer service representatives and branch staff querying banking standard operating procedures. | `POST /api/v1/chat/ask` |
| `Banking.Employee` | General banking employee persona with combined complaint intake and procedure search permissions. | `POST /api/v1/complaints/summarize`<br/>`POST /api/v1/chat/ask` |
| `TokenVault.Admin` | Security administrators authorized to decrypt reversible tokens for legal/compliance investigations. | `POST /api/v1/tokens/restore` |
| `Compliance.Officer` | Compliance auditors and legal officers with token restoration and audit log viewing privileges. | `POST /api/v1/tokens/restore`<br/>`GET /api/v1/audit/events` |
| `Audit.Viewer` | Read-only compliance auditor role for examining append-only event logs. | `GET /api/v1/audit/events`<br/>`GET /api/v1/audit/events/{id}` |

---

## 2. Customer Complaint Summarization

Redacts customer PII, invokes Amazon Bedrock with Guardrails, logs an append-only audit record in PostgreSQL, and delivers an actionable operational summary.

- **Method:** `POST`
- **Path:** `/api/v1/complaints/summarize`
- **Required Roles:** `Complaints.Analyst`, `Banking.Employee`, or `Admin`

### Request Headers
```http
Authorization: Bearer <VALID_JWT>
Content-Type: application/json
```

### Request Body
```json
{
  "complaint_text": "Customer Name: Eleanor Vance (account 9821847120, phone +1-555-0144, email eleanor.vance@fictional-bank-customer.test) noticed two identical debits of $142.50 to 'Metro Utilities' on her checking statement yesterday morning. Only one transaction should have been processed. Metro Utilities confirmed receiving only a single payment. Please reverse the duplicate deduction of $142.50 and refund any overdraft fees.",
  "complaint_reference_id": "CMP-2024-001",
  "store_reversible_tokens": true
}
```

### Response `200 OK`
```json
{
  "request_id": "d93efb84-48bf-4c74-9f20-160fa11239c0",
  "status": "SUCCESS",
  "customer_issue": "{{PERSON_1}} reported an unauthorized duplicate debit of $142.50 to Metro Utilities from Account: {{ACCOUNT_1}}.",
  "requested_resolution": "Full reversal of the $142.50 duplicate deduction and refund of any overdraft fees incurred.",
  "suggested_next_steps": "1. Compare settlement timestamps and Acquirer Reference Numbers (ARNs) for both debit entries.\n2. Verify if either charge is in pending authorization versus settled status.\n3. If both charges have posted as settled, file an ACH Return using reason code R10 or initiate a duplicate processing chargeback.\n4. Process an automated fee reversal for any resulting non-sufficient funds or overdraft charges within 24 business hours.",
  "sanitized_summary": "Customer Issue: {{PERSON_1}} reported an unauthorized duplicate debit of $142.50 to Metro Utilities from Account: {{ACCOUNT_1}}.\n\nRequested Resolution: Full reversal of the $142.50 duplicate deduction and refund of any overdraft fees incurred.\n\nSuggested Next Steps: 1. Compare settlement timestamps and ARNs for both entries. 2. Verify pending versus posted status. 3. File ACH Return R10 if posted. 4. Reverse associated overdraft fees within 24 hours.",
  "redacted_entities_count": 4,
  "guardrail_status": "PASSED"
}
```

### Error Responses
- `400 Bad Request`: Input rejected by application security guardrails (e.g., prompt injection detected).
- `401 Unauthorized`: Missing, expired, or invalid bearer token.
- `403 Forbidden`: Authenticated user lacks `Complaints.Analyst` role.
- `500 Internal Server Error`: PII redaction failure or strict audit persistence abort.

---

## 3. Banking Procedure Q&A

Answers employee operational and procedural inquiries grounded strictly in approved bank SOP documents. Treats retrieved content as untrusted context to prevent document-poisoning attacks.

- **Method:** `POST`
- **Path:** `/api/v1/chat/ask`
- **Required Roles:** `Banking.Reader`, `Banking.Employee`, or `Admin`

### Request Body
```json
{
  "question": "What is the procedure and timeline for handling duplicate card charges under Regulation E?",
  "procedure_topic_filter": "card_disputes"
}
```

### Response `200 OK`
```json
{
  "request_id": "b182f09a-66a1-4043-9844-3c817291a13b",
  "sanitized_question": "What is the procedure and timeline for handling duplicate card charges under Regulation E?",
  "answer": "Under Standard Operating Procedure SOP-OPS-CARD-001 (Regulation E / 12 CFR Part 1005):\n1. Notification Period: The cardholder must report the unauthorized charges within 60 calendar days of transmittal of the periodic statement showing the unauthorized debit.\n2. Investigation Window: The bank must complete its initial investigation within 10 business days of notification.\n3. Provisional Credit: If the bank cannot complete the investigation within 10 business days, provisional credit for the disputed amount must be credited to the customer account while the investigation continues (up to 45 or 90 calendar days for international/point-of-sale transactions).\n4. Personnel Prohibitions: Employees must never ask for the customer's 4-digit PIN, CVV, or online banking password.",
  "referenced_documents": [
    "card_disputes.md"
  ],
  "guardrail_status": "PASSED"
}
```

### Error Responses
- `400 Bad Request`: Question is off-topic (e.g., asking for recipes or creative writing) or contains prompt injection.
- `401 Unauthorized`: Missing or invalid bearer token.
- `403 Forbidden`: User lacks `Banking.Reader` role.

---

## 4. Reversible Token Restoration

Allows authorized compliance or fraud investigation officers to decrypt and retrieve the original sensitive PII value corresponding to an opaque token.

- **Method:** `POST`
- **Path:** `/api/v1/tokens/restore`
- **Required Roles:** `TokenVault.Admin`, `Compliance.Officer`, or `SecurityAdmin`

### Request Body
```json
{
  "token_id": "{{ACCOUNT_TOKEN_d7c7d73da2b86766}}",
  "justification_reason": "Compliance dispute verification for ticket #DISP-2024-9918 approved by supervisor"
}
```

### Response `200 OK`
```json
{
  "token_id": "{{ACCOUNT_TOKEN_d7c7d73da2b86766}}",
  "token_type": "ACCOUNT",
  "restored_value": "9821847120",
  "restored_at": "2024-10-15T09:30:00Z",
  "message": "Token restored successfully under compliance policy"
}
```

### Error Responses
- `403 Forbidden`: Actor lacks required `TokenVault.Admin` or `Compliance.Officer` role (attempt is audited as `outcome=DENIED`).
- `404 Not Found`: Token does not exist or mapping has expired under data retention policy.

---

## 5. Audit Trail Inspection

Queries sanitized append-only records from the PostgreSQL `audit_events` table with pagination and filtering.

- **Method:** `GET`
- **Path:** `/api/v1/audit/events`
- **Required Roles:** `Audit.Viewer`, `Compliance.Officer`, or `Admin`

### Query Parameters
- `limit` (integer, default 50, max 200)
- `offset` (integer, default 0)
- `action_type` (string, optional, e.g., `COMPLAINT_SUMMARIZE`, `CHAT_ASK`, `TOKEN_RESTORE`)
- `actor_id` (string, optional)

### Example Request
```http
GET /api/v1/audit/events?limit=10&action_type=COMPLAINT_SUMMARIZE HTTP/1.1
Authorization: Bearer <VALID_AUDITOR_JWT>
```

### Response `200 OK`
```json
{
  "total_count": 1,
  "events": [
    {
      "audit_event_id": "893c5c16-2395-46b5-b778-5a21fa39c29e",
      "request_id": "d93efb84-48bf-4c74-9f20-160fa11239c0",
      "actor_id": "analyst-usr-001",
      "timestamp": "2024-10-15T09:12:00Z",
      "action_type": "COMPLAINT_SUMMARIZE",
      "redaction_status": "REDACTED",
      "retrieved_document_ids": [],
      "guardrail_outcome": "PASSED",
      "model_invocation_outcome": "SUCCESS",
      "sanitized_response_summary": "Customer Issue: {{PERSON_1}} reported an unauthorized duplicate debit...",
      "status": "SUCCESS",
      "client_ip": "10.0.1.25",
      "details": {
        "redacted_entities_count": 4,
        "latency_ms": 312.4,
        "token_usage": {
          "input_tokens": 145,
          "output_tokens": 92,
          "total_tokens": 237
        },
        "reversible_tokens_stored": true
      }
    }
  ]
}
```

---

## 6. Service Health Check

Unauthenticated liveness probe for load balancers and container orchestrators.

- **Method:** `GET`
- **Path:** `/health`
- **Authentication:** None

### Response `200 OK`
```json
{
  "service": "secure-finance-assistant",
  "status": "UP",
  "database": "healthy",
  "environment": "production",
  "bedrock_model": "anthropic.claude-3-haiku-20240307-v1:0",
  "guardrails_configured": true
}
```
