# ==============================================================================
# Terraform Variables Definition
# ==============================================================================

variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g., prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Name prefix applied to all managed resources"
  type        = string
  default     = "secure-finance-assistant"
}

variable "vpc_cidr" {
  description = "Primary CIDR block for the dedicated banking VPC"
  type        = string
  default     = "10.20.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones for multi-AZ high availability"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "app_subnet_cidrs" {
  description = "CIDR blocks for private application workloads"
  type        = list(string)
  default     = ["10.20.1.0/24", "10.20.2.0/24"]
}

variable "db_subnet_cidrs" {
  description = "CIDR blocks for isolated database tier"
  type        = list(string)
  default     = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "db_instance_class" {
  description = "RDS PostgreSQL compute instance type"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "secure_banking"
}

variable "db_username" {
  description = "Master administrative username for RDS instance"
  type        = string
  default     = "dbadmin_audit"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GB for RDS instance"
  type        = number
  default     = 50
}

variable "bedrock_model_id" {
  description = "Model ID for Bedrock invocation permissions"
  type        = string
  default     = "anthropic.claude-3-haiku-20240307-v1:0"
}

variable "bedrock_guardrail_arn" {
  description = "Optional ARN of pre-configured Bedrock Guardrail. If empty, account-wide guardrails in region are permitted."
  type        = string
  default     = ""
}

variable "enable_bedrock_vpc_endpoint" {
  description = "Provision private AWS PrivateLink VPC interface endpoint for Bedrock Runtime"
  type        = bool
  default     = true
}
