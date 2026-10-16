# ==============================================================================
# Terraform Core Configuration and KMS Cryptographic Providers
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      DataClass   = "Confidential-Banking"
    }
  }
}

data "aws_caller_identity" "current" {}

# Customer Managed Key (CMK) for Token Vault Envelope Encryption
resource "aws_kms_key" "token_vault" {
  description             = "KMS Key for Token Vault Envelope Encryption (${var.project_name})"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootIAMManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowApplicationRoleEnvelopeOperations"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.app_execution_role.arn
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-token-vault-key"
  }
}

resource "aws_kms_alias" "token_vault" {
  name          = "alias/${var.project_name}-token-vault"
  target_key_id = aws_kms_key.token_vault.key_id
}

# Customer Managed Key (CMK) for RDS Storage Encryption
resource "aws_kms_key" "rds" {
  description             = "KMS Key for RDS PostgreSQL Storage Encryption (${var.project_name})"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${var.project_name}-rds-key"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.project_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}
