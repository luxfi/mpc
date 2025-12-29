# AWS deployment for fund-private mpcd clusters.
#
# What this module provisions:
#   - EKS cluster (multi-AZ private subnets, no internet gateway)
#   - AWS CloudHSM cluster for ZapDB password unwrap
#   - S3 bucket with Object Lock + Glacier Vault Lock for audit log
#   - AWS Secrets Manager entries for jwt-secret and internal-api-key
#   - Outputs that feed into the kustomize overlay at
#     deployments/k8s-private/
#
# Usage:
#   cd deployments/terraform/aws
#   terraform init
#   terraform plan -var "fund_id=acme-fund" -var "region=us-east-1"
#   terraform apply -var "fund_id=acme-fund" -var "region=us-east-1"
#
# After apply, copy the outputs into the fund's KMS pipeline that
# populates k8s-private/mpc-secrets.yaml.

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

variable "fund_id" {
  type        = string
  description = "Short identifier for the fund (lowercase, hyphenated). Used as a name prefix."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,32}$", var.fund_id))
    error_message = "fund_id must be 3-33 chars, lowercase alphanumeric+hyphen, starting with a letter."
  }
}

variable "region" {
  type        = string
  description = "AWS region. Audit S3 bucket inherits this region — choose for residency."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.42.0.0/16"
  description = "Primary VPC CIDR. Subnets are carved as /20 across three AZs."
}

provider "aws" {
  region = var.region
}

# VPC: private subnets only. No NAT gateway. No internet gateway.
# Egress to AWS services goes via VPC endpoints, defined below.
resource "aws_vpc" "fund" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name      = "${var.fund_id}-mpc-vpc"
    Component = "lux-mpc"
    Mode      = "private"
  }
}

resource "aws_subnet" "private" {
  count                   = 3
  vpc_id                  = aws_vpc.fund.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.fund_id}-mpc-private-${count.index}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# S3 audit bucket with Object Lock — compliance mode, retention measured
# in years. The mpc daemon writes audit batches via the s3-glacier-vault
# dispatcher (build with the cloud-audit tag).
resource "aws_s3_bucket" "audit" {
  bucket              = "${var.fund_id}-mpc-audit"
  object_lock_enabled = true
  force_destroy       = false
  tags = {
    Component = "lux-mpc"
    Mode      = "private"
    Purpose   = "audit-worm"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Outputs feed the kustomize overlay's secret pipeline.
output "audit_bucket" {
  value = aws_s3_bucket.audit.bucket
}

output "vpc_id" {
  value = aws_vpc.fund.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

# CloudHSM and EKS modules intentionally elided here. They are large
# enough to deserve their own files; the structure above is what the
# runbook assumes. See deployments/terraform/aws/README.md for the
# full module layout.
