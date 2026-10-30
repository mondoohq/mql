variable "organization_id" {
  type        = string
  description = "ClickHouse Cloud organization ID (from the Cloud console, or the org the API key belongs to)."
}

variable "api_key" {
  type        = string
  sensitive   = true
  description = "ClickHouse Cloud API key id (also set as CLICKHOUSE_CLOUD_TEST_KEY for the provider test)."
}

variable "api_secret" {
  type        = string
  sensitive   = true
  description = "ClickHouse Cloud API key secret."
}

variable "service_name" {
  type        = string
  default     = "mondoo-clickhousecloud-test"
  description = "Name of the throwaway test service."
}

variable "cloud_provider" {
  type        = string
  default     = "aws"
  description = "Cloud provider for the service: aws, gcp, or azure."
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Region for the service (must be valid for the chosen cloud_provider)."
}

variable "tier" {
  type        = string
  default     = "development"
  description = "Service tier. \"development\" is cheapest. On a Scale-tier organization the tier field is not accepted — set it to null here and add min_replica_memory_gb/max_replica_memory_gb to the service in main.tf instead."
}

variable "test_open_access" {
  type        = bool
  default     = false
  description = "When true, add a 0.0.0.0/0 entry to the IP allow-list so the provider's openToAllIps finding can be verified live. This makes the (empty, password-protected) service internet-reachable; destroy it after testing."
}
