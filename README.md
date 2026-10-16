# Secure Banking & Finance Assistant

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg)](https://fastapi.tiangolo.com)
[![Bedrock](https://img.shields.io/badge/AWS-Amazon%20Bedrock-FF9900.svg)](https://aws.amazon.com/bedrock/)
[![Entra ID](https://img.shields.io/badge/Auth-Microsoft%20Entra%20ID-0078D4.svg)](https://learn.microsoft.com/en-us/entra/)
[![Tests](https://img.shields.io/badge/pytest-35%20passed-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/Security-PII%20Redacted-success.svg)](docs/security-controls.md)

A production-grade, privacy-first backend service built for retail banking operations. It automates customer complaint summarization and standard procedure Q&A with **Amazon Bedrock**, enforces **deterministic PII redaction**, safeguards against prompt injection, isolates reversible tokens via **AWS KMS envelope encryption**, authenticates with **Microsoft Entra ID (Azure AD)**, and maintains an **append-only PostgreSQL audit trail**.

---

## Architecture Overview

```
                                      [ Microsoft Entra ID ]
                                                 │
                                                 ▼ (RS256 JWT / JWKS)
[ Banking Employee ] ──▶ [ FastAPI Gateway (Non-Root Docker) ]
                               │
       ┌───────────────────────┼────────────────────────┐
       ▼                       ▼                        ▼
[ Input Guardrails ]  [ PII Redaction Engine ]  [ Local Procedure Retrieval ]
(Injections / Leaks)   (Deterministic Masking)    (Approved Banking Docs)
                               │                        │
                               ▼ ({{PLACEHOLDER}} text) ▼
                      [ Amazon Bedrock Converse API ]
                      (With Bedrock Guardrails Active)
                               │
                               ▼
                      [ Output Guardrails ]
                      (PII Leaks & Hallucination Defense)
                               │
       ┌───────────────────────┴────────────────────────┐
       ▼                                                ▼
[ Append-Only Audit Trail ]                   [ Restricted Token Vault ]
 (PostgreSQL 15 / Fail-Safe)                  (AES-256-GCM Envelope Encryption)
```

---

## Key Capabilities

- **Deterministic PII Redaction:** Strips customer names, account numbers, payment card PANs (with Luhn check), IBANs, emails, phone numbers, and customer IDs before foundation model invocation.
- **Amazon Bedrock Converse Integration:** Directly leverages the Bedrock Runtime `converse` API passing `guardrailConfig` (`guardrailIdentifier`, `guardrailVersion`, `trace="enabled"`) and separate system prompt blocks.
- **Restricted Token Vault:** Encrypts reversible PII with AES-256-GCM envelope encryption (AWS KMS / local envelope). De-anonymization is restricted to `TokenVault.Admin` or `Compliance.Officer` roles with mandatory justification and audit logging.
- **Append-Only Audit Trail:** Records all inference interactions, redactions, guardrail decisions, and token operations without logging raw complaints or unmasked PII. Configured with strict fail-safe abort.
- **Enterprise Authentication:** Validates Microsoft Entra ID RS256 JWT tokens with OpenID Connect / JWKS signature verification, audience, issuer, expiry, and tenant isolation checks.
- **AWS Private Networking (Terraform):** Complete IaC provisioning an isolated multi-tier VPC, private application subnets, private RDS PostgreSQL, security groups, and AWS PrivateLink VPC interface endpoints for Bedrock, KMS, and Secrets Manager.

---

## Directory Structure

```
.
├── Dockerfile                   # Multi-stage minimal container (non-root UID 10001)
├── docker-compose.yml           # Local multi-container stack (App + PostgreSQL)
├── requirements.txt             # Pinned, mutually compatible dependencies
├── pytest.ini                   # Pytest configuration with asyncio auto mode
├── .env.example                 # Configuration template with documented variables
├── .gitignore                   # Standard exclusions for secrets, state, and venvs
├── README.md                    # Project documentation and developer runbook
│
├── app/
│   ├── main.py                  # FastAPI application entrypoint, lifespan, and CORS
│   ├── api/                     # REST routers & RBAC dependencies
│   │   ├── auth.py              # Entra ID token validation & role requirement factories
│   │   ├── complaints.py        # POST /api/v1/complaints/summarize
│   │   ├── chat.py              # POST /api/v1/chat/ask
│   │   ├── audit.py             # GET /api/v1/audit/events
│   │   └── tokens.py            # POST /api/v1/tokens/restore
│   ├── core/                    # Application settings, security, and logging
│   │   ├── config.py            # Pydantic Settings configuration loader
│   │   ├── security.py          # Entra ID JWKS validator & AuthenticatedUser model
│   │   └── logging.py           # Sanitized JSON structured log formatter
│   ├── db/                      # Database engine, models, and repositories
│   │   ├── database.py          # Async SQLAlchemy engine & session generator
│   │   ├── models.py            # AuditEvent, TokenVaultMapping, TokenRestorationAudit
│   │   └── audit_repository.py  # Append-only audit logger and token vault queries
│   ├── schemas/                 # Pydantic v2 request & response models
│   │   ├── complaint.py
│   │   ├── chat.py
│   │   ├── audit.py
│   │   └── token.py
│   └── services/                # Business logic & security pipelines
│       ├── pii_redaction.py     # Deterministic PII regex masking & stable placeholders
│       ├── token_vault.py       # Reversible token vault (AES-256-GCM / KMS envelope)
│       ├── input_guardrails.py  # Prompt injection, jailbreak, & off-topic detection
│       ├── output_guardrails.py # PII leakage check & unsupported claim prevention
│       ├── procedure_retrieval.py # Keyword retrieval over approved banking procedures
│       └── bedrock_service.py   # Amazon Bedrock Converse API with Guardrails
│
├── data/
│   ├── sample_complaints.json   # Synthetic customer complaints
│   ├── sample_transactions.json # Synthetic banking transactions
│   └── banking_procedures/      # Approved standard operating procedures (SOPs)
│       ├── card_disputes.md
│       ├── duplicate_payments.md
│       ├── refund_policy.md
│       └── account_servicing.md
│
├── terraform/                   # Infrastructure as Code (AWS)
│   ├── main.tf                  # Providers & KMS Customer Managed Keys
│   ├── variables.tf             # Parameterized variables
│   ├── outputs.tf               # VPC IDs, RDS endpoints, and KMS ARNs
│   ├── networking.tf            # Isolated VPC, subnets, SGs, and Bedrock VPC endpoints
│   ├── iam.tf                   # Least-privilege IAM roles and scoped policies
│   └── database.tf              # Private RDS PostgreSQL instance & Secrets Manager
│
├── docs/                        # Security, API, architectural, and engineering specs
│   ├── BRD.md                   # Business Requirements Document (GLBA, Reg E, NACHA, KPIs)
│   ├── SRD.md                   # Security & System Requirements Document (CIA, Entra ID, Guardrails)
│   ├── TRD.md                   # Technical Requirements Document (Specs, Data Models, Bedrock)
│   ├── FDE.md                   # Functional Design & Engineering Document (Algorithms, State Machine)
│   ├── architecture.md          # Architectural specifications & Mermaid sequence flows
│   ├── threat-model.md          # Comprehensive threat model covering 11 critical threats
│   ├── security-controls.md     # Security controls matrix & PostgreSQL hardening script
│   ├── api-documentation.md     # Full REST API specifications, curl examples, & responses
│   ├── runbook.md               # SRE runbook, Entra ID setup, KMS rotation, & playbooks
│   └── terraform-ubuntu-guide.md # Step-by-step Terraform deployment guide on Ubuntu Linux
│
└── tests/                       # Automated test suites (100% Passing)
    ├── conftest.py              # Pytest fixtures, mock tokens, and async in-memory SQLite DB
    ├── test_pii_redaction.py    # PII detection, Luhn check, and placeholder collision tests
    ├── test_token_vault.py      # Envelope encryption & RBAC restoration tests
    ├── test_guardrails.py       # Input prompt injection & output hallucination tests
    ├── test_auth.py             # Entra ID token signature, expiration, & tenant tests
    ├── test_bedrock.py          # Bedrock Converse invocation & error handling tests
    ├── test_audit.py            # Append-only audit persistence & fail-safe tests
    └── test_api.py              # End-to-end REST endpoint tests with TestClient
```

---

## API Endpoints

| Method | Endpoint | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/complaints/summarize` | `Complaints.Analyst`, `Banking.Employee`, `Admin` | Redacts PII, invokes Bedrock with Guardrails, logs audit trail, returns safe summary. |
| `POST` | `/api/v1/chat/ask` | `Banking.Reader`, `Banking.Employee`, `Admin` | Answers banking procedure questions grounded in approved documents; audits referenced docs. |
| `POST` | `/api/v1/tokens/restore` | `TokenVault.Admin`, `Compliance.Officer` | De-anonymizes reversible token with required justification and mandatory audit logging. |
| `GET` | `/api/v1/audit/events` | `Audit.Viewer`, `Compliance.Officer`, `Admin` | Paginated listing of sanitized audit records. |
| `GET` | `/api/v1/audit/events/{id}` | `Audit.Viewer`, `Compliance.Officer`, `Admin` | Retrieve details for a specific audit record by UUID. |
| `GET` | `/health` | *Public* | Liveness and readiness probe reporting DB and Bedrock status. |

---

## Quickstart Guide

### 1. Running with Docker Compose (Recommended)

```bash
# 1. Prepare environment variables
cp .env.example .env

# 2. Build and run stack (FastAPI App + Isolated PostgreSQL)
docker compose up --build -d

# 3. Check container status
curl http://localhost:8000/health
```

### 2. Running Locally with Python Virtual Environment

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Start local application
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Automated Test Results

The entire test suite runs offline using synthetic fixtures, mock tokens, and an isolated in-memory SQLite database (`aiosqlite`):

```bash
python -m pytest -v
```

### Execution Summary

```
============================= test session starts =============================
platform win32 -- Python 3.13.15, pytest-9.1.1, pluggy-1.6.0
configfile: pytest.ini
plugins: anyio-4.11.0, langsmith-0.4.43, asyncio-1.4.0
asyncio: mode=Mode.AUTO
collected 35 items

tests/test_api.py::test_health_endpoint PASSED                           [  2%]
tests/test_api.py::test_summarize_complaint_success PASSED               [  5%]
tests/test_api.py::test_summarize_complaint_blocked_by_input_guardrail PASSED [  8%]
tests/test_api.py::test_summarize_complaint_unauthorized_role PASSED     [ 11%]
tests/test_api.py::test_summarize_complaint_unauthenticated PASSED       [ 14%]
tests/test_api.py::test_chat_procedure_ask_success PASSED                [ 17%]
tests/test_api.py::test_chat_procedure_rejects_off_topic PASSED          [ 20%]
tests/test_api.py::test_audit_events_endpoint_rbac PASSED                [ 22%]
tests/test_api.py::test_token_restore_endpoint_rbac PASSED               [ 25%]
tests/test_audit.py::test_audit_event_insertion PASSED                   [ 28%]
tests/test_audit.py::test_audit_fail_safe_behavior PASSED                [ 31%]
tests/test_auth.py::test_validate_valid_token PASSED                     [ 34%]
tests/test_auth.py::test_validate_expired_token PASSED                   [ 37%]
tests/test_auth.py::test_validate_wrong_tenant_token PASSED              [ 40%]
tests/test_auth.py::test_validate_audience_mismatch PASSED               [ 42%]
tests/test_auth.py::test_validate_empty_or_malformed_token PASSED        [ 45%]
tests/test_bedrock.py::test_bedrock_summarize_complaint_mock PASSED      [ 48%]
tests/test_bedrock.py::test_bedrock_answer_procedure_mock PASSED         [ 51%]
tests/test_bedrock.py::test_bedrock_handles_client_error PASSED          [ 54%]
tests/test_guardrails.py::test_input_guardrail_valid_banking_input PASSED [ 57%]
tests/test_guardrails.py::test_input_guardrail_prompt_injection_rejection PASSED [ 60%]
tests/test_guardrails.py::test_input_guardrail_off_topic_rejection PASSED [ 62%]
tests/test_guardrails.py::test_input_guardrail_excessive_length PASSED   [ 65%]
tests/test_guardrails.py::test_output_guardrail_detects_unsupported_transaction_claims PASSED [ 68%]
tests/test_guardrails.py::test_output_guardrail_detects_pii_leakage PASSED [ 71%]
tests/test_guardrails.py::test_output_guardrail_allows_safe_sanitized_summary PASSED [ 74%]
tests/test_pii_redaction.py::test_luhn_checksum_valid_and_invalid PASSED [ 77%]
tests/test_pii_redaction.py::test_redact_explicit_customer_names PASSED  [ 80%]
tests/test_pii_redaction.py::test_redact_emails_and_phones PASSED        [ 82%]
tests/test_pii_redaction.py::test_redact_accounts_and_customer_ids PASSED [ 85%]
tests/test_pii_redaction.py::test_placeholder_stability_and_collision_avoidance PASSED [ 88%]
tests/test_pii_redaction.py::test_failure_closed_on_error PASSED         [ 91%]
tests/test_token_vault.py::test_store_and_restore_token_authorized PASSED [ 94%]
tests/test_token_vault.py::test_restore_token_unauthorized PASSED        [ 97%]
tests/test_token_vault.py::test_restore_nonexistent_token PASSED         [100%]

============================= 35 passed in 1.13s ==============================
```

---

## AWS Infrastructure Deployment (Terraform)

The Terraform definitions provision a private, least-privilege banking cloud architecture:

> [!TIP]
> For a dedicated, step-by-step installation and deployment guide on Ubuntu Linux, see [docs/terraform-ubuntu-guide.md](docs/terraform-ubuntu-guide.md).

```bash
cd terraform

# 1. Initialize Terraform
terraform init

# 2. Plan configuration
terraform plan -var="aws_region=us-east-1" -var="environment=prod"

# 3. Apply infrastructure
terraform apply
```

### Managed Resources

- **VPC & Subnets:** Isolated VPC (`10.20.0.0/16`), private application subnets, and isolated database subnets.
- **AWS PrivateLink:** Private interface VPC endpoints for `bedrock-runtime`, `kms`, `secretsmanager`, and `logs`.
- **RDS PostgreSQL:** Multi-AZ RDS instance in private DB subnets with KMS encryption at rest, forced SSL/TLS (`rds.force_ssl = 1`), and non-public ingress.
- **KMS Customer Managed Keys:** CMKs with automated rotation for Token Vault envelope encryption and database storage.
- **IAM Policies:** Strictly scoped policies for Bedrock invocation, KMS data key generation, and CloudWatch audit logging without wildcard admin permissions.

---

## Enterprise Documentation Suite

| Document | File Link | Focus & Content |
| :--- | :--- | :--- |
| **BRD** | [BRD.md](docs/BRD.md) | **Business Requirements Document:** Business KPIs, GLBA / Reg E / NACHA compliance mandates, stakeholder personas, and operational business workflows. |
| **SRD** | [SRD.md](docs/SRD.md) | **Security & System Requirements Document:** CIA triad specifications, Entra ID RS256 JWT RBAC, deterministic PII redactor, AES-256-GCM token vault, and input/output guardrails. |
| **TRD** | [TRD.md](docs/TRD.md) | **Technical Requirements Document:** Exact dependency versions, database ER diagram, PostgreSQL physical schemas, Bedrock payload structures, and performance SLAs. |
| **FDE** | [FDE.md](docs/FDE.md) | **Functional Design & Engineering Document:** Subsystem state machines, span resolution algorithms, Luhn mod-10 card check, exception hierarchy, and deployment checklists. |
| **Architecture** | [architecture.md](docs/architecture.md) | End-to-end data flow diagrams, zero-trust network boundaries, and sequence diagrams. |
| **Threat Model** | [threat-model.md](docs/threat-model.md) | STRIDE analysis evaluating 11 critical banking threats, attack vectors, and countermeasure matrix. |
| **Security Controls** | [security-controls.md](docs/security-controls.md) | Security controls matrix & PostgreSQL role privilege hardening script. |
| **API Documentation** | [api-documentation.md](docs/api-documentation.md) | Exhaustive REST API guide with curl commands, JSON request/response payloads, and error codes. |
| **Operations Runbook** | [runbook.md](docs/runbook.md) | SRE operational runbook, Entra ID setup, KMS rotation guide, and incident response playbooks. |
| **Terraform Ubuntu Guide** | [terraform-ubuntu-guide.md](docs/terraform-ubuntu-guide.md) | Step-by-step Terraform provisioning and zero-trust verification on Ubuntu Linux. |
