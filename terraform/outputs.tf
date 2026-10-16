# ==============================================================================
# Terraform Outputs
# ==============================================================================

output "vpc_id" {
  description = "ID of the dedicated banking VPC"
  value       = aws_vpc.main.id
}

output "private_app_subnet_ids" {
  description = "Subnet IDs for deploying application containers"
  value       = aws_subnet.app[*].id
}

output "private_db_subnet_ids" {
  description = "Subnet IDs hosting RDS PostgreSQL"
  value       = aws_subnet.db[*].id
}

output "database_endpoint" {
  description = "Private address of PostgreSQL RDS instance"
  value       = aws_db_instance.postgres.address
}

output "database_port" {
  description = "Port number for PostgreSQL"
  value       = aws_db_instance.postgres.port
}

output "token_vault_kms_key_arn" {
  description = "Customer Managed KMS Key ARN for Token Vault Envelope Encryption"
  value       = aws_kms_key.token_vault.arn
}

output "app_execution_role_arn" {
  description = "IAM Role ARN for the application execution identity"
  value       = aws_iam_role.app_execution_role.arn
}

output "bedrock_runtime_endpoint_id" {
  description = "AWS PrivateLink interface VPC endpoint ID for Amazon Bedrock Runtime"
  value       = var.enable_bedrock_vpc_endpoint ? aws_vpc_endpoint.bedrock_runtime[0].id : "Endpoint disabled"
}

output "db_credentials_secret_arn" {
  description = "AWS Secrets Manager ARN holding the encrypted database connection secret"
  value       = aws_secretsmanager_secret.db_credentials.arn
}
