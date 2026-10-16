# ==============================================================================
# Least-Privilege IAM Roles and Policies
# ==============================================================================

# Application Execution Role (assumed by ECS Task or EKS Pod Identity)
resource "aws_iam_role" "app_execution_role" {
  name        = "${var.project_name}-app-role"
  description = "Execution role for banking assistant container with strictly scoped permissions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-app-role"
  }
}

# 1. Scoped Amazon Bedrock Invocation Policy
resource "aws_iam_policy" "bedrock_invocation" {
  name        = "${var.project_name}-bedrock-policy"
  description = "Allows invoking specified Bedrock foundation model and applying guardrails"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowModelConverseAndInvoke"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}"
        ]
      },
      {
        Sid    = "AllowGuardrailApplication"
        Effect = "Allow"
        Action = [
          "bedrock:ApplyGuardrail"
        ]
        Resource = var.bedrock_guardrail_arn != "" ? [var.bedrock_guardrail_arn] : [
          "arn:aws:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:guardrail/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_bedrock" {
  role       = aws_iam_role.app_execution_role.name
  policy_arn = aws_iam_policy.bedrock_invocation.policy_arn
}

# 2. Scoped Token Vault KMS Envelope Encryption Policy
resource "aws_iam_policy" "token_vault_kms" {
  name        = "${var.project_name}-kms-token-vault-policy"
  description = "Restricts KMS key operations to generating data keys and decrypting for token vault"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEnvelopeDataKeyGenerationAndDecryption"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = [
          aws_kms_key.token_vault.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_kms" {
  role       = aws_iam_role.app_execution_role.name
  policy_arn = aws_iam_policy.token_vault_kms.policy_arn
}

# 3. Scoped Secrets Manager Read Policy for Database Credentials
resource "aws_iam_policy" "db_secret_read" {
  name        = "${var.project_name}-db-secret-policy"
  description = "Allows application role to retrieve PostgreSQL credentials from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadDbCredential"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.db_credentials.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_secret" {
  role       = aws_iam_role.app_execution_role.name
  policy_arn = aws_iam_policy.db_secret_read.policy_arn
}

# 4. Scoped CloudWatch Logs Policy
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/banking/${var.project_name}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.rds.arn

  tags = {
    Name = "${var.project_name}-log-group"
  }
}

resource "aws_iam_policy" "cloudwatch_logs" {
  name        = "${var.project_name}-logging-policy"
  description = "Allows application to emit structured audit logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EmitLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.app_logs.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_logs" {
  role       = aws_iam_role.app_execution_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs.policy_arn
}
