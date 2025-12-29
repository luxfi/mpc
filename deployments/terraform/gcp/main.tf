# GCP deployment for fund-private mpcd clusters.
#
# What this module provisions (top-level):
#   - GKE Autopilot cluster (private, regional, workload-identity on)
#   - GCS bucket with Object Lock retention policy (audit WORM)
#   - Cloud HSM key ring + key for ZapDB password wrap
#   - Cloud KMS-backed secret entries
#
# Usage:
#   cd deployments/terraform/gcp
#   terraform init
#   terraform plan -var "fund_id=acme-fund" -var "project=acme-mpc-prod" -var "region=us-central1"
#   terraform apply -var "fund_id=acme-fund" -var "project=acme-mpc-prod" -var "region=us-central1"

terraform {
  required_version = ">= 1.7"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.40"
    }
  }
}

variable "fund_id" {
  type        = string
  description = "Short fund identifier (lowercase, hyphenated)."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,32}$", var.fund_id))
    error_message = "fund_id must be 3-33 chars, lowercase alphanumeric+hyphen."
  }
}

variable "project" {
  type        = string
  description = "GCP project ID."
}

variable "region" {
  type        = string
  description = "GCP region."
}

provider "google" {
  project = var.project
  region  = var.region
}

# GCS audit bucket with retention policy.
resource "google_storage_bucket" "audit" {
  name          = "${var.fund_id}-mpc-audit"
  location      = var.region
  storage_class = "STANDARD"
  force_destroy = false

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  retention_policy {
    is_locked        = true
    retention_period = 220838400 # 7 years in seconds
  }

  versioning {
    enabled = true
  }
}

output "audit_bucket" {
  value = google_storage_bucket.audit.name
}

# GKE + Cloud HSM modules elided here for the same reason as AWS:
# scope. See deployments/terraform/gcp/README.md.
