# ClickHouse Cloud Provider

The `clickhousecloud` provider connects to the ClickHouse Cloud control-plane API and inventories an organization through read-only queries. It exposes the organization's services (with their IP allow-lists and endpoints), API keys, and members, so you can audit the organization's security posture, for example services reachable from any IP address or API keys that never expire.

This audits the **control plane** (services, access, org membership). To audit the database *inside* a Cloud service (users, roles, grants), point the `clickhousedb` provider at the service endpoint.

## Authentication

The provider authenticates with a ClickHouse Cloud **organization API key** (a key id + secret), created in the Cloud console under **API keys**. A key with read access is sufficient.

Arguments:

- `--organization-id` - the ClickHouse Cloud organization ID.
- `--api-key` - the API key id.
- `--api-secret` - the API key secret, or `--ask-secret` to be prompted.
- `--api-url` - override the API base URL (default `https://api.clickhouse.cloud/v1`).

```shell
mql shell clickhousecloud --organization-id ORG_ID --api-key KEY_ID --ask-secret
```

## Examples

**Services reachable from any IP address**

```shell
mql> clickhousecloud.organization.services.where(openToAllIps) { name region ipAccessList { source description } }
clickhousecloud.organization.services.where: [
  0: {
    name: "My first service"
    region: "eu-central-1"
    ipAccessList: [
      0: { source: "0.0.0.0/0"  description: "Anywhere" }
    ]
  }
]
```

**Services without encryption at rest**

```shell
mql> clickhousecloud.organization.services.where(hasTransparentDataEncryption == false) { name }
```

**API keys, their roles and expiry**

```shell
mql> clickhousecloud.organization.apiKeys { name state roles neverExpires }
clickhousecloud.organization.apiKeys: [
  0: { name: "cnspec"  state: "enabled"  roles: ["Admin"]  neverExpires: false }
]
```

Use `.where(neverExpires)` to flag keys with no expiration.

**Organization administrators**

```shell
mql> clickhousecloud.organization.members.where(role == "admin") { email name }
clickhousecloud.organization.members.where: [
  0: { email: "chris@mondoo.com" }
]
```

## Verification

Confirm the connection with a single query:

```shell
mql shell clickhousecloud --organization-id ORG_ID --api-key KEY_ID --ask-secret -c "clickhousecloud.organization { name }"
```

If `clickhousecloud.organization.services` comes back empty, the API key lacks read access to services; grant it (or use a more privileged key) and retry.

## Development

The integration tests in `resources/integration_test.go` are gated on the
`CLICKHOUSE_CLOUD_TEST_*` environment, so they skip in CI and run only against a
live organization. `resources/testdata/terraform/` provisions a minimal,
cheapest-tier test service with Terraform; see its README for how to apply it and
feed its outputs into the tests. Unit tests (the API client envelope/auth and
role parsing) run without any credentials via `go test ./...`.

## Notes

- API key secrets are never returned by the ClickHouse Cloud API and are never exposed here; keys report only their id, name, state, roles, and expiry.
- This provider reads the ClickHouse Cloud control-plane API only. Organization-level items not exposed by that API are out of scope.
