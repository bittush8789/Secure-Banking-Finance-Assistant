# Security Controls Matrix: Secure Banking & Finance Assistant POC

| Control Domain | Control Identifier | Mechanism / Implementation | Verification Method |
| :--- | :--- | :--- | :--- |
| **Identity & Access** | AC-1: Central Authentication | Microsoft Entra ID OAuth 2.0 / OpenID Connect Bearer token validation via official JWKS keys. | Signature, audience (`aud`), issuer (`iss`), expiry (`exp`), and tenant ID (`tid`) verified on every request. |
| **Identity & Access** | AC-2: Role-Based Authorization | Granular application roles (`Complaints.Analyst`, `Banking.Reader`, `TokenVault.Admin`, `Audit.Viewer`). | Rejection of unauthorized actions with HTTP 403 Forbidden. Body-supplied identity claims strictly disregarded. |
| **Data Protection** | DP-1: Pre-Model PII Redaction | Deterministic redaction engine (`PIIRedactor`) scanning for customer names, PANs, IBANs, phone numbers, emails, customer IDs. | Executed strictly **before** Amazon Bedrock API invocation. |
| **Data Protection** | DP-2: Failure-Closed Privacy | Exception handling wraps all redaction logic. If an error occurs during parsing, the request is halted. | Model is never called when redaction fails; returns HTTP 500 safety error. |
| **Data Protection** | DP-3: Stable Token Replacement | Entity values mapped to typed placeholders (`{{PERSON_1}}`, `{{ACCOUNT_1}}`) consistently across the request. | Prevents placeholder collision with existing user text. |
| **Token Vault** | TV-1: Isolated Encrypted Vault | Sensitive mappings isolated from application text and encrypted using AES-256-GCM envelope encryption. | AWS KMS customer managed key (CMK) or local 256-bit envelope master key. |
| **Token Vault** | TV-2: Restoration Access Control | De-anonymization restricted to `TokenVault.Admin` or `Compliance.Officer` roles with mandatory justification. | Unauthorized attempts fail with HTTP 403 and are logged in the restoration audit table. |
| **Token Vault** | TV-3: No Automatic LLM Restoration | Original PII values are never returned to the LLM or automatically restored in summaries. | Model output strictly retains `{{PLACEHOLDER}}` tokens. |
| **AI Safety** | AI-1: Prompt Injection Defense | Heuristic static filter (`InputGuardrails`) detecting instruction overrides, jailbreaks, and credential leaks. | Malicious requests rejected with HTTP 400 before LLM or document retrieval. |
| **AI Safety** | AI-2: Bedrock Guardrails | Amazon Bedrock Guardrails configured with content filters, PII masking, and topic restrictions. | Interventions trigger `guardrail_intervened` trace and safe fallback. |
| **AI Safety** | AI-3: Untrusted Document Boundary | Retrieved banking procedure documents formatted within `<approved_procedure_document>` tags. | System prompt instructs LLM to treat reference documents as untrusted passive context. |
| **AI Safety** | AI-4: Output Claim Validation | Regex post-processing intercepting unsupported claims (e.g., claiming transaction verification or ledger debit/credit). | Catches financial hallucinations before returning response to user. |
| **Audit & Logging** | AU-1: Append-Only Audit Trail | PostgreSQL `audit_events` table storing sanitised execution metadata, request IDs, actor IDs, and outcomes. | Application code contains zero `UPDATE` or `DELETE` statements. |
| **Audit & Logging** | AU-2: Privacy in Audit Records | Raw complaints, unredacted prompts, access tokens, and encryption keys are strictly omitted from audit records. | Audit entries store only safe summary snippets, hash references, and operational counts. |
| **Audit & Logging** | AU-3: Strict Audit Fail-Safe | When `AUDIT_STRICT_FAIL_SAFE=true`, failure to persist the audit record immediately aborts the HTTP request. | Prevents silent execution without audit tracking. |
| **Audit & Logging** | AU-4: Sanitized Application Logs | `SanitizedJsonFormatter` enforces regex filters masking Bearer tokens, passwords, emails, and card numbers. | Ordinary standard output/stderr logs remain clean of customer PII and credentials. |
| **Infrastructure** | IN-1: Network Isolation | Multi-tier VPC with private application subnets and isolated database subnets; no public database exposure. | RDS `publicly_accessible = false`; security groups restrict database ingress to port 5432 from app SG. |
| **Infrastructure** | IN-2: Bedrock PrivateLink | Private connectivity to Amazon Bedrock Runtime via AWS PrivateLink VPC interface endpoint. | Eliminates exposure of model inference traffic to the public internet. |
| **Infrastructure** | IN-3: Least-Privilege IAM | IAM roles scoped strictly to specific Bedrock model ARNs, KMS Key ARNs, and CloudWatch Log Groups. | No wildcard administrator policies (`*`). |
| **Infrastructure** | IN-4: Hardened Container Runtime | Docker container executes as non-root user `appuser` (UID 10001) with read-only application files. | Prevents container privilege escalation attacks. |

---

## 5. PostgreSQL Role and Privilege Hardening Script

To enforce tamper resistance in PostgreSQL, execute the following least-privilege role setup script:

```sql
-- Revoke default public privileges
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_audit_writer, audit_reader;

-- Create application audit writer role with INSERT-only on audit_events
CREATE ROLE app_audit_writer WITH LOGIN PASSWORD 'strong_generated_password';
GRANT INSERT ON audit_events TO app_audit_writer;
GRANT SELECT, INSERT ON token_vault_mappings TO app_audit_writer;
GRANT INSERT ON token_restoration_audits TO app_audit_writer;

-- Create auditor read-only role with SELECT on audit_events
CREATE ROLE audit_reader WITH LOGIN PASSWORD 'strong_auditor_password';
GRANT SELECT ON audit_events TO audit_reader;
GRANT SELECT ON token_restoration_audits TO audit_reader;
-- audit_reader CANNOT read token_vault_mappings
```
