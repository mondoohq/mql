terraform {
  required_providers {
    clickhouse = {
      source  = "ClickHouseCloud/clickhouse"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# Authenticates with a ClickHouse Cloud organization API key (key id + secret).
# The same credentials are used by the mql clickhousecloud provider.
provider "clickhouse" {
  organization_id = var.organization_id
  token_key       = var.api_key
  token_secret    = var.api_secret
}

# ClickHouse Cloud requires a service password at creation. The mql provider
# audits the control-plane API and never uses it, so this is a throwaway value
# that only lives in Terraform state (nothing sensitive is committed).
resource "random_password" "svc" {
  length  = 24
  special = false
}

# A minimal, cheapest-tier service to audit. idle_scaling lets it scale to zero
# when unused. Run `terraform destroy` when you are done to avoid charges.
resource "clickhouse_service" "test" {
  name           = var.service_name
  cloud_provider = var.cloud_provider
  region         = var.region
  tier           = var.tier

  # password_hash is base64(sha256(password)), the format ClickHouse Cloud expects.
  password_hash = base64sha256(random_password.svc.result)

  idle_scaling         = true
  idle_timeout_minutes = 5

  # An IP allow-list with a description so the provider's ipAccessList resource
  # has entries to resolve. Set var.test_open_access = true to also add a
  # 0.0.0.0/0 entry and exercise the "open to all IPs" finding (creates an
  # internet-reachable but empty, password-protected service — destroy after).
  ip_access = var.test_open_access ? [
    { source = "0.0.0.0/0", description = "mondoo-test: open (exercises openToAllIps finding)" },
    { source = "198.51.100.0/24", description = "mondoo-test: example office range" },
    ] : [
    { source = "198.51.100.0/24", description = "mondoo-test: example office range" },
  ]
}
