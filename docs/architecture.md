# System Architecture: Secure Banking & Finance Assistant POC

## 1. System Overview and Goals

The **Secure Banking & Finance Assistant** provides an automated operational interface for retail banking employees. It enables:
1. **Complaints Summarization:** Extracting customer issues, requested remediations, and operational next steps without exposing customer PII to cloud foundation models.
2. **Procedural Q&A:** Answering employee policy questions grounded strictly in approved bank procedure documents.
3. **Reversible Token Vault:** Isolating and encrypting sensitive customer data under strict RBAC and audit controls.
4. **Append-Only Auditing:** Maintaining an immutable record of all inference interactions, redactions, guardrail interventions, and de-anonymization requests.

---

## 2. High-Level Architecture & Trust Boundaries

```mermaid
graph TD
    subgraph Untrusted External Zone
        User["Banking Employee / Client Application"]
    end

    subgraph Identity Provider
        EntraID["Microsoft Entra ID (Azure AD)<br/>OAuth 2.0 / OIDC (JWKS)"]
    end

    subgraph AWS Cloud Environment
        subgraph Dedicated Banking VPC
            subgraph Private Application Subnets
                FastAPI["FastAPI Backend Service<br/>(Non-Root Container)"]
                Redactor["PII Redaction Engine<br/>(Deterministic Masking)"]
                Guardrails["Input & Output Guardrails"]
                Retrieval["Local Procedure Retrieval<br/>(data/banking_procedures/)"]
            end

            subgraph AWS PrivateLink VPC Endpoints
                BedrockVPCE["Bedrock Runtime Endpoint<br/>(com.amazonaws.us-east-1.bedrock-runtime)"]
                KMSVPCE["KMS VPC Endpoint"]
                SMVPCE["Secrets Manager VPC Endpoint"]
            end

            subgraph Isolated Database Subnets
                Postgres["RDS PostgreSQL 15<br/>(Append-Only Audit & Token Vault)"]
            end
        end

        subgraph Managed AWS AI & Security Services
            Bedrock["Amazon Bedrock<br/>(Claude 3 / Titan)"]
            BedrockGuardrails["Amazon Bedrock Guardrails"]
            KMS["AWS Key Management Service (KMS)<br/>Customer Managed Key (CMK)"]
        end
    end

    %% Flows
    User -- "1. Bearer Token + Request" --> FastAPI
    FastAPI -- "2. Validate Signature / Claims" --> EntraID
    FastAPI --> Guardrails
    FastAPI --> Redactor
    FastAPI --> Retrieval
    FastAPI -- "3. HTTPS PrivateLink" --> BedrockVPCE
    BedrockVPCE --> Bedrock
    Bedrock --> BedrockGuardrails
    FastAPI -- "4. Envelope Key Gen / Decrypt" --> KMSVPCE
    KMSVPCE --> KMS
    FastAPI -- "5. TLS 1.3 Insert-Only" --> Postgres
```

---

## 3. Core Component Workflows

### A. Complaint Summarization Flow

```mermaid
sequenceDiagram
    autonumber
    actor Employee as Banking Employee
    participant API as FastAPI Router
    participant Auth as Entra ID Validator
    participant InGuard as Input Guardrails
    participant Redact as PII Redactor
    participant Vault as Token Vault (KMS)
    participant Bedrock as Amazon Bedrock
    participant OutGuard as Output Guardrails
    participant Audit as PostgreSQL Audit

    Employee->>API: POST /api/v1/complaints/summarize (Bearer JWT)
    API->>Auth: Validate JWT Signature, Aud, Iss, Tid, Roles
    Auth-->>API: AuthenticatedUser (Complaints.Analyst)
    
    API->>InGuard: Evaluate Input (Length, Injections, Overrides)
    InGuard-->>API: Status: PASSED
    
    API->>Redact: Scan & Mask PII (Names, PAN, Phone, Email, Accts)
    Redact-->>API: PIIRedactionResult (Redacted Text + Placeholders)
    
    opt store_reversible_tokens == True
        API->>Vault: Encrypt PII with KMS Envelope (AES-256-GCM)
        Vault-->>API: Stored Mappings (Opaque Tokens)
    end
    
    API->>Bedrock: Converse API (Redacted Text + GuardrailConfig)
    Bedrock-->>API: Raw Model Summary
    
    API->>OutGuard: Verify Output Safety (No PII Leaks, No Unsupported Claims)
    OutGuard-->>API: Sanitized Summary
    
    API->>Audit: Append Audit Event (Actor, RequestID, Outcome, Safe Summary)
    Audit-->>API: Event Committed
    
    API-->>Employee: Return 200 OK (Sanitized Summary + Request ID)
```

---

### B. Procedural Q&A Flow

```mermaid
sequenceDiagram
    autonumber
    actor Employee as Banking Employee
    participant API as FastAPI Router
    participant Auth as Entra ID Validator
    participant InGuard as Input Guardrails
    participant Docs as Procedure Engine (Local)
    participant Redact as PII Redactor
    participant Bedrock as Amazon Bedrock
    participant OutGuard as Output Guardrails
    participant Audit as PostgreSQL Audit

    Employee->>API: POST /api/v1/chat/ask (Question)
    API->>Auth: Validate JWT & Roles (Banking.Reader)
    Auth-->>API: Authorized
    
    API->>InGuard: Check Injections, Overrides, Off-Topic Queries
    InGuard-->>API: Status: PASSED
    
    API->>Docs: Retrieve Relevant Procedure Documents (Keyword Matching)
    Docs-->>API: Matching Snippets (Formatted as Untrusted XML Context)
    
    API->>Redact: Redact Stray PII from Question
    Redact-->>API: Sanitized Question
    
    API->>Bedrock: Converse API (Untrusted Context + Question + Guardrails)
    Bedrock-->>API: Grounded Answer
    
    API->>OutGuard: Check Answer Grounding & Absence of Fake Commitments
    OutGuard-->>API: Validated Safe Answer
    
    API->>Audit: Record Audit Event (Referenced Doc IDs, Latency, Token Usage)
    Audit-->>API: Committed
    
    API-->>Employee: Return 200 OK (Answer + Doc References)
```

---

### C. Reversible Token Vault & De-anonymization Flow

```mermaid
sequenceDiagram
    autonumber
    actor Officer as Compliance Officer
    participant API as FastAPI Router
    participant Auth as Entra ID Validator
    participant Vault as Token Vault Service
    participant KMS as AWS KMS
    participant DB as PostgreSQL Database
    participant Audit as Restoration Audit

    Officer->>API: POST /api/v1/tokens/restore (TokenID + Business Justification)
    API->>Auth: Validate Token (Require 'TokenVault.Admin' or 'Compliance.Officer')
    
    alt Unauthorized Role
        Auth-->>API: Access Denied
        API->>Audit: Record Denied Restoration Attempt (Actor, TokenID, Outcome=DENIED)
        API-->>Officer: 403 Forbidden
    else Authorized Role
        API->>DB: Fetch Encrypted Token Record
        DB-->>API: Ciphertext, Nonce, Auth Tag, Key ARN
        
        API->>KMS: Decrypt Envelope Data Key
        KMS-->>API: Plaintext Key
        
        API->>Vault: AES-256-GCM Decrypt Value
        Vault-->>API: Restored Plaintext PII
        
        API->>Audit: Record Successful Attempt (Actor, TokenID, Outcome=SUCCESS, NO PII LOGGED)
        API-->>Officer: 200 OK (Restored Value)
    end
```

---

## 4. Network and Private Infrastructure Topology

1. **VPC Architecture:**
   - Dedicated CIDR `10.20.0.0/16` spanned across multi-AZ configurations.
   - **Tier 1 (Application):** Private subnets without Internet Gateways. Only accessible via internal load balancer.
   - **Tier 2 (Database):** Isolated database subnets without external routing of any kind.
2. **Bedrock Private Connectivity:**
   - Instead of routing across public internet, traffic flows through `com.amazonaws.us-east-1.bedrock-runtime` AWS PrivateLink VPC interface endpoints located inside the application subnets.
3. **Storage Security:**
   - PostgreSQL runs on RDS with AES-256 KMS storage encryption, forced SSL/TLS connections (`rds.force_ssl = 1`), and automated snapshots.
