# Operations & Security Runbook: Secure Banking & Finance Assistant

**Target Audience:** Site Reliability Engineers (SREs), AI Security Engineers, and Database Administrators (DBAs)  
**System Classification:** Tier-1 Confidential Financial Processing Service  

---

## 1. Microsoft Entra ID (Azure AD) Configuration

To configure production identity federation with Microsoft Entra ID:

### Step 1: Create App Registration
1. Navigate to the **Microsoft Entra admin center** > **Applications** > **App registrations**.
2. Select **New registration**.
   - **Name:** `Secure-Finance-Assistant-API`
   - **Supported account types:** Accounts in this organizational directory only (Single tenant).
   - **Redirect URI:** Leave blank (API resource).
3. Record the **Application (client) ID** and **Directory (tenant) ID**.

### Step 2: Configure Application Roles in Manifest
Under **App roles**, select **Create app role** for each of the following:

```json
[
  {
    "allowedMemberTypes": ["User", "Application"],
    "description": "Can summarize customer complaints and view redacted summaries",
    "displayName": "Complaints Analyst",
    "isEnabled": true,
    "value": "Complaints.Analyst"
  },
  {
    "allowedMemberTypes": ["User", "Application"],
    "description": "Can query approved banking procedures",
    "displayName": "Banking Reader",
    "isEnabled": true,
    "value": "Banking.Reader"
  },
  {
    "allowedMemberTypes": ["User"],
    "description": "Authorized to de-anonymize reversible PII tokens with justification",
    "displayName": "Token Vault Administrator",
    "isEnabled": true,
    "value": "TokenVault.Admin"
  },
  {
    "allowedMemberTypes": ["User"],
    "description": "Read-only access to append-only audit trail records",
    "displayName": "Audit Viewer",
    "isEnabled": true,
    "value": "Audit.Viewer"
  }
]
```

### Step 3: Assign Users and Groups
Navigate to **Enterprise applications** > `Secure-Finance-Assistant-API` > **Users and groups** and assign security groups (e.g., `SG-Complaints-Operations`, `SG-Compliance-Officers`) to the corresponding App Roles.

---

## 2. Amazon Bedrock & Guardrails Setup

### Step 1: Request Foundation Model Access
1. Open the **Amazon Bedrock Console** in the target AWS region (e.g., `us-east-1`).
2. Navigate to **Model access** in the bottom left navigation pane.
3. Select **Modify model access** and enable:
   - **Anthropic Claude 3 Haiku** (`anthropic.claude-3-haiku-20240307-v1:0`)
   - **Amazon Titan Text Express** (`amazon.titan-text-express-v1`)

### Step 2: Create Bedrock Guardrail
1. Under **Guardrails**, click **Create guardrail**.
   - **Name:** `banking-pii-safety-guardrail`
   - **Blocked messaging:** `"This response was blocked by the bank safety guardrail policy."`
2. **Content Filters:**
   - Hate, Insults, Sexual, Violence: Set filters to **High**.
   - Misconduct / Financial Fraud: Set to **High**.
3. **Sensitive Information Filters:**
   - Add standard PII types (Bank Account Number, US SSN, Email, Phone).
   - Set Action to **Block** or **Mask**.
4. Publish the guardrail version (e.g., Version `1`) and record the **Guardrail ID** in `.env` as `BEDROCK_GUARDRAIL_ID`.

---

## 3. Cryptographic Key Management & Rotation

### KMS Key Rotation (Token Vault & Database)
1. **Automated Yearly Rotation:**  
   The Terraform definition enables automated annual rotation:
   ```hcl
   enable_key_rotation = true
   ```
2. **Manual Envelope Key Re-encryption:**  
   To rotate the Token Vault Customer Managed Key (CMK):
   - Create new KMS Key Alias (e.g., `alias/secure-finance-assistant-token-vault-v2`).
   - Update `TOKEN_VAULT_KMS_KEY_ARN` in production environment configuration.
   - Existing tokens remain decryptable because each mapping stores its original `key_identifier`.

### Database Password Rotation via Secrets Manager
1. Master database credentials are encrypted at rest in AWS Secrets Manager:
   ```bash
   aws secretsmanager get-secret-value \
     --secret-id "secure-finance-assistant-db-credentials" \
     --query SecretString --output text
   ```
2. To rotate the database password:
   ```bash
   aws secretsmanager rotate-secret \
     --secret-id "secure-finance-assistant-db-credentials"
   ```

---

## 4. Incident Response Playbooks

### Playbook A: Strict Audit Trail Persistence Failure
- **Symptom:** API returns `HTTP 500 Internal Server Error` with message `"Audit logging service failure. Response withheld under strict compliance policy."`
- **Root Cause:** PostgreSQL database unreachable, disk space full, or connection pool exhausted.
- **Triage Steps:**
  1. Check database connectivity:
     ```bash
     curl http://localhost:8000/health
     ```
  2. Inspect PostgreSQL connection metrics and storage in CloudWatch:
     - `FreeStorageSpace` < 5 GB triggers automatic storage expansion.
     - `DatabaseConnections` approaching `DATABASE_POOL_SIZE` limit.
  3. Verify application connection pool settings in `.env`:
     ```ini
     DATABASE_POOL_SIZE=20
     DATABASE_MAX_OVERFLOW=30
     ```

### Playbook B: Burst Token De-anonymization Alert
- **Symptom:** SIEM alert fires for > 5 token restoration calls within 10 minutes from a single actor ID.
- **Triage Steps:**
  1. Query the `token_restoration_audits` table for recent attempts:
     ```sql
     SELECT restoration_id, token_id, actor_id, reason, outcome, client_ip, timestamp
     FROM token_restoration_audits
     ORDER BY timestamp DESC
     LIMIT 20;
     ```
  2. Verify that each `reason` correlates with an active, approved dispute investigation ticket.
  3. If unauthorized activity is suspected, immediately revoke the actor's Entra ID session tokens via the Entra ID portal.

### Playbook C: Bedrock VPC Endpoint Network Partition
- **Symptom:** Bedrock requests timeout or fail with `HTTP 502 Bad Gateway` (`EndpointConnectionError`).
- **Triage Steps:**
  1. Verify the status of the `bedrock-runtime` PrivateLink interface endpoint:
     ```bash
     aws ec2 describe-vpc-endpoints \
       --filters "Name=service-name,Values=com.amazonaws.us-east-1.bedrock-runtime" \
       --query "VpcEndpoints[0].State"
     ```
  2. Ensure the VPC endpoint security group allows HTTPS inbound on port 443 from the application security group.
  3. Confirm that Private DNS is enabled on the VPC endpoint (`PrivateDnsEnabled: true`).
