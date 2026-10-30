# ClickHouse Cloud test environment

Provisions a minimal, cheapest-tier ClickHouse Cloud service so the
`clickhousecloud` provider can be verified against a live organization. The
service is empty and password-protected; the mql provider audits the
control-plane API and never connects to it.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform) installed.
- A ClickHouse Cloud **organization ID** and an **API key** (key id + secret)
  with read/write on the org (create one in the Cloud console under
  **API keys**).

## Apply

Pass the credentials as variables (do **not** commit them). Environment
variables are cleanest:

```shell
cd providers/clickhousecloud/resources/testdata/terraform
export TF_VAR_organization_id=<org-id>
export TF_VAR_api_key=<key-id>
export TF_VAR_api_secret=<key-secret>

terraform init
terraform apply
```

Adjust `-var cloud_provider=...`, `-var region=...`, or `-var tier=...` for your
organization. On a Scale-tier organization the `tier` field is not accepted; set
`-var tier=null` and add `min_replica_memory_gb`/`max_replica_memory_gb` to the
service in `main.tf`. To exercise the "open to all IPs" finding, add
`-var test_open_access=true` (creates an internet-reachable, empty service —
`terraform destroy` it afterwards).

## Run the provider tests against it

The same API key authenticates the provider. Feed the outputs into the
env-gated integration test:

```shell
export CLICKHOUSE_CLOUD_TEST_ORG=$(terraform output -raw organization_id)
export CLICKHOUSE_CLOUD_TEST_KEY=<key-id>
export CLICKHOUSE_CLOUD_TEST_SECRET=<key-secret>
export CLICKHOUSE_CLOUD_TEST_SERVICE=$(terraform output -raw service_id)

go test ../.. -run TestIntegration -v
```

## Tear down

```shell
terraform destroy
```
