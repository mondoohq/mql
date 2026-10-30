output "organization_id" {
  value       = var.organization_id
  description = "Set as CLICKHOUSE_CLOUD_TEST_ORG for the provider integration test."
}

output "service_id" {
  value       = clickhouse_service.test.id
  description = "The provisioned service id; the seeded test asserts this service resolves."
}

output "service_name" {
  value = clickhouse_service.test.name
}

output "endpoints" {
  value       = clickhouse_service.test.endpoints
  description = "The service's connection endpoints (protocol/host/port)."
}
