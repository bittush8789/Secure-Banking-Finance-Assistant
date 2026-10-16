# Step-by-Step Terraform Deployment Guide on Ubuntu Linux

This guide provides end-to-end instructions for deploying the **Secure Banking & Finance Assistant** AWS infrastructure from an **Ubuntu Linux system** (Ubuntu 20.04, 22.04, or 24.04 LTS).

---

## 1. System Prerequisites on Ubuntu

Update your package repositories and install the required utility packages:

```bash
sudo apt-get update && sudo apt-get install -y \
    curl \
    gnupg \
    software-properties-common \
    unzip \
    jq \
    git
```

---

## 2. Install HashiCorp Terraform on Ubuntu

Install official Terraform binaries via HashiCorp's signed Debian/Ubuntu repository:

```bash
# 1. Download and install the official HashiCorp GPG key
wget -O- https://apt.releases.hashicorp.com/gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

# 2. Add the official HashiCorp repository to your APT sources
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
    https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
    sudo tee /etc/apt/sources.list.d/hashicorp.list

# 3. Update repositories and install Terraform
sudo apt-get update && sudo apt-get install -y terraform

# 4. Verify Terraform installation
terraform -version
# Expected: Terraform v1.5.0 or higher
```

---

## 3. Install and Configure AWS CLI v2 on Ubuntu

The official AWS CLI v2 is required for credentials management and inspecting AWS Secrets Manager:

```bash
# 1. Download the AWS CLI v2 installer
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"

# 2. Unpack the installer
unzip awscliv2.zip

# 3. Run the installer
sudo ./aws/install

# 4. Clean up installation files
rm -rf awscliv2.zip aws/

# 5. Verify installation
aws --version
```

### Configure AWS Authentication

Configure your AWS credentials (IAM user or IAM role with administrator/provisioning privileges):

```bash
aws configure
```

You will be prompted for:
- **AWS Access Key ID:** `AKIA...`
- **AWS Secret Access Key:** `...`
- **Default region name:** `us-east-1` (or your target region where Bedrock is active)
- **Default output format:** `json`

Verify authentication:
```bash
aws sts get-caller-identity
```

---

## 4. Configure Terraform Variables (`terraform.tfvars`)

Navigate to the `terraform/` directory:

```bash
cd terraform/
```

Create a customized `terraform.tfvars` file:

```bash
cat << 'EOF' > terraform.tfvars
# Deployment Region & Identity
aws_region   = "us-east-1"
environment  = "prod"
project_name = "secure-finance-assistant"

# Dedicated Isolated VPC CIDRs
vpc_cidr           = "10.20.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b"]
app_subnet_cidrs   = ["10.20.1.0/24", "10.20.2.0/24"]
db_subnet_cidrs    = ["10.20.10.0/24", "10.20.11.0/24"]

# Database Instance Specifications
db_instance_class    = "db.t4g.medium"
db_name              = "secure_banking"
db_username          = "dbadmin_audit"
db_allocated_storage = 50

# Foundation Model & Private Connectivity
bedrock_model_id            = "anthropic.claude-3-haiku-20240307-v1:0"
enable_bedrock_vpc_endpoint = true
EOF
```

---

## 5. Execute Terraform Lifecycle

### Step 5.1: Initialize Providers and Backend
Initialize the working directory and download the AWS and Random providers:

```bash
terraform init
```

### Step 5.2: Validate Syntax and Configuration
Ensure that all HCL definitions, schemas, and references are valid:

```bash
terraform validate
# Expected output: Success! The configuration is valid.
```

### Step 5.3: Generate and Review the Execution Plan
Generate an immutable execution plan and inspect the resources to be created:

```bash
terraform plan -out=tfplan
```

Review the planned resources:
- Dedicated VPC (`aws_vpc.main`)
- 2 Application Subnets (`aws_subnet.app`)
- 2 Database Subnets (`aws_subnet.db`)
- 3 Security Groups (`app`, `db`, `vpc_endpoints`)
- AWS PrivateLink Interface VPC Endpoints (`bedrock-runtime`, `kms`, `secretsmanager`, `logs`)
- 2 KMS Customer Managed Keys with automated rotation (`token_vault`, `rds`)
- 1 Multi-AZ RDS PostgreSQL Instance (`aws_db_instance.postgres`)
- 1 Secrets Manager Secret (`aws_secretsmanager_secret.db_credentials`)
- Least-privilege IAM Roles & Scoped Policies (`aws_iam_role.app_execution_role`)

### Step 5.4: Apply the Plan
Deploy the infrastructure:

```bash
terraform apply tfplan
```

> [!NOTE]
> RDS PostgreSQL multi-AZ provisioning and KMS key generation typically take between 5 to 10 minutes to complete.

---

## 6. Post-Deployment Verification & App Configuration

### Step 6.1: Inspect Terraform Outputs
Once deployment completes, inspect the outputs:

```bash
terraform output
```

Output example:
```
app_execution_role_arn      = "arn:aws:iam::123456789012:role/secure-finance-assistant-app-role"
bedrock_runtime_endpoint_id = "vpce-0123456789abcdef0"
database_endpoint           = "secure-finance-assistant-audit-db.c12345678901.us-east-1.rds.amazonaws.com"
database_port               = 5432
db_credentials_secret_arn   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:secure-finance-assistant-db-credentials-AbCdEf"
kms_token_vault_key_arn     = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
private_app_subnet_ids      = ["subnet-01a...", "subnet-02b..."]
private_db_subnet_ids       = ["subnet-03c...", "subnet-04d..."]
vpc_id                      = "vpc-0a1b2c3d4e5f6g7h8"
```

### Step 6.2: Retrieve Database Password from AWS Secrets Manager
The master database password was dynamically generated and stored in Secrets Manager. Extract it using `jq`:

```bash
DB_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "secure-finance-assistant-db-credentials" \
  --query SecretString \
  --output text)

DB_HOST=$(echo $DB_SECRET | jq -r .host)
DB_PORT=$(echo $DB_SECRET | jq -r .port)
DB_NAME=$(echo $DB_SECRET | jq -r .dbname)
DB_USER=$(echo $DB_SECRET | jq -r .username)
DB_PASS=$(echo $DB_SECRET | jq -r .password)

echo "PostgreSQL Host: $DB_HOST"
echo "PostgreSQL Port: $DB_PORT"
echo "Database Name:   $DB_NAME"
```

### Step 6.3: Update Application Environment (`.env`)
From the repository root (`../`), update your production `.env` file with the provisioned AWS resources:

```bash
cd ..

# Populate .env with provisioned infrastructure parameters
sed -i "s|POSTGRES_SERVER=.*|POSTGRES_SERVER=$DB_HOST|" .env
sed -i "s|POSTGRES_PORT=.*|POSTGRES_PORT=$DB_PORT|" .env
sed -i "s|POSTGRES_DB=.*|POSTGRES_DB=$DB_NAME|" .env
sed -i "s|POSTGRES_USER=.*|POSTGRES_USER=$DB_USER|" .env
sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$DB_PASS|" .env
sed -i "s|DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$DB_NAME|" .env

KMS_KEY_ARN=$(cd terraform && terraform output -raw token_vault_kms_key_arn)
sed -i "s|TOKEN_VAULT_KMS_KEY_ARN=.*|TOKEN_VAULT_KMS_KEY_ARN=$KMS_KEY_ARN|" .env
sed -i "s|TOKEN_VAULT_KEY_PROVIDER=.*|TOKEN_VAULT_KEY_PROVIDER=kms|" .env
```

---

## 7. Infrastructure Teardown (Clean-Up)

When you wish to decommission the cloud resources and avoid ongoing AWS charges:

```bash
cd terraform/

# 1. Preview resources to be destroyed
terraform plan -destroy

# 2. Destroy all resources
terraform destroy -auto-approve
```

---

## 8. Common Ubuntu Troubleshooting & FAQ

### Issue A: `Error: AccessDeniedException: User ... is not authorized to perform: bedrock:InvokeModel`
- **Cause:** Model access has not been activated in the AWS account.
- **Fix:** Go to AWS Console > **Amazon Bedrock** > **Model access** > **Modify model access** > Request access for **Anthropic Claude 3 Haiku**.

### Issue B: `Error creating DB Instance: DBSubnetGroupDoesNotCoverEnoughAZs`
- **Cause:** RDS requires subnets in at least two distinct Availability Zones.
- **Fix:** Ensure `availability_zones` in `terraform.tfvars` specifies at least two zones (e.g., `["us-east-1a", "us-east-1b"]`).

### Issue C: `permission denied while attempting to connect to the docker socket`
- **Fix (if running containers on Ubuntu):** Add your Ubuntu user to the `docker` group:
  ```bash
  sudo usermod -aG docker $USER && newgrp docker
  ```
