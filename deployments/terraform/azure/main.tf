# Azure deployment for fund-private mpcd clusters.

terraform {
  required_version = ">= 1.7"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
  }
}

variable "fund_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,32}$", var.fund_id))
    error_message = "fund_id must be 3-33 chars, lowercase alphanumeric+hyphen."
  }
}

variable "location" {
  type    = string
  default = "eastus"
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "fund" {
  name     = "${var.fund_id}-mpc-rg"
  location = var.location
}

resource "azurerm_storage_account" "audit" {
  name                     = "${replace(var.fund_id, "-", "")}mpcaudit"
  resource_group_name      = azurerm_resource_group.fund.name
  location                 = azurerm_resource_group.fund.location
  account_tier             = "Standard"
  account_replication_type = "GZRS"

  blob_properties {
    versioning_enabled = true
  }
}

# Immutable Blob Storage policy is added in storage.tf (TODO: not yet
# plan-tested). The audit dispatcher's azure-immutable backend writes
# blobs to this account.

output "audit_account" {
  value = azurerm_storage_account.audit.name
}
