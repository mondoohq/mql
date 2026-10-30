# Cloud provisioning notes

Per-cloud gotchas learned from real verification runs. Read the relevant
section before generating Terraform (step 4), applying (step 6), and
tearing down (step 10). These are the things that turn a clean `plan` into a
failed `apply`.

## Table of contents

- [General](#general)
- [AWS](#aws)
- [Azure](#azure)
- [GCP](#gcp)
- [OCI](#oci)
- [Resources Terraform cannot provision](#resources-terraform-cannot-provision)
- [Teardown failure modes](#teardown-failure-modes)

## General

- Pick the smallest SKU / instance / tier that still makes the field populate.
  Free tiers exist on most clouds — use them.
- The sandbox blocks the Terraform registry and most cloud APIs. `terraform`
  and cloud CLIs generally need the command sandbox disabled.
- A field resolving to `false`/`""`/`[]` is a valid pass only when that
  reflects reality. If a field *should* hold data and doesn't, it is a bug —
  often the provider listing with the wrong scope or API view.
- Slow resources dominate wall time. Apply every cloud in parallel in the
  background.

## AWS

- **Region**: Aurora DSQL and Bedrock advanced-prompt-optimization are limited
  to a few regions (`us-east-1`, `us-east-2`, `us-west-2`). Default to
  `us-west-2`.
- **ES / OpenSearch domains**: smallest is `t3.small.search`, 1 node, ~10 GiB
  gp3. ~10–15 min to become active.
- **CloudFront distributions**: ~15 min to deploy and ~15 min to delete.
- **SageMaker domain**: needs a VPC + subnet + execution IAM role.
- **CloudFront viewer mTLS**: set `viewer_mtls_config` on the distribution
  referencing a `aws_cloudfront_trust_store` (CA bundle uploaded to S3).
- **Private CA (`aws_acmpca_certificate_authority`)**: a general-purpose CA bills
  **~$400/month flat** whether or not it issues a cert, with no compute to signal
  it is running — a silent cost bomb. Prefer avoiding it; if a check needs one,
  make sure `mondoo-expiry` is short and confirm it is deleted in teardown.
- **Apply tags via `default_tags` on the `aws` provider block** (schema in
  SKILL.md step 5) — never per resource, or one untagged resource escapes cleanup.

## Azure

- **VPN Gateway**: non-AZ `VpnGw1`..`VpnGw5` SKUs can no longer be created —
  use the `VpnGw1AZ` (etc.) AZ SKUs. An AZ VPN gateway also requires a
  **zone-redundant Standard public IP** (`zones = ["1","2","3"]`). The Basic
  SKU does not support custom IPsec policies. Provisioning takes ~30–45 min.
- **Function App**: the classic Consumption plan (`Y1`) is rejected on quota-
  limited subscriptions ("additional quota … Total VMs: 0"). Use the **Flex
  Consumption** plan: `azurerm_service_plan` SKU `FC1` +
  `azurerm_function_app_flex_consumption` (needs a storage container). Note the
  flex-consumption resource has **no `key_vault_reference_identity_id`
  argument** — set `keyVaultReferenceIdentity` post-apply with
  `az functionapp update --set keyVaultReferenceIdentity=<uami-id>`.
- **Cognitive Services**: use `kind = "CognitiveServices"` (multi-service, SKU
  `S0`). `kind = "OpenAI"` needs special subscription approval — avoid it.
- **AI Search**: cheapest paid SKU is `basic` (~$0.10/hr). `free` is limited to
  one per subscription.
- Put everything in one resource group; tag `project = mql-pr-verify`.

## GCP

- **Provider block**: set `billing_project` and `user_project_override = true`.
  Some APIs (DLP/Sensitive Data Protection) reject ADC user credentials without
  a quota project. Also run
  `gcloud auth application-default set-quota-project <project>`.
- **Enable APIs explicitly** with `google_project_service` and `depends_on`
  them — composer, dlp, healthcare, apigateway, workstations, etc.
- **Cloud Composer**: ~25–40 min to create, ~20 min to destroy, ~$0.40–0.55/hr
  — the dominant cost. Composer 3 web server memory must be **≥ 2 GB**.
- **Workstation cluster**: ~20 min to create, ~15 min to destroy. The cluster
  itself is free; only running workstations cost.
- **DLP connections** must be in `AVAILABLE` state at creation — they need a
  live Cloud SQL instance and valid credentials. A placeholder instance is
  rejected. The Terraform `google` provider has no DLP connection resource.
- **Legacy Notebooks** (`google_notebooks_instance`, user-managed) can no
  longer be created — GCP rejects with "deprecated". The accessor still
  resolves to an empty list.
- App Engine runtimes go end-of-support — use a current runtime
  (`python312`, not `python39`).

## OCI

- **Compartment scope**: the OCI provider lists *network* resources (VCN,
  security lists, NSGs) only in the **tenancy root compartment**. Put network
  and compute resources for those checks in the root compartment, not a
  sub-compartment. Data Safe resources *are* scanned subtree-wide, so they can
  live in a sub-compartment.
- **Always Free tier**: Autonomous DB (`is_free_tier = true`) and
  `VM.Standard.E2.1.Micro` compute are $0 — use them.
- **Data Safe target databases** require a non-expired account promotion.
  On an Always-Free-only tenancy, `CreateTargetDatabase` fails with
  `405 … promotion is expired` — an account limit, not a bug.
- Auth: the Terraform `oci` provider reads `~/.oci/config`; set
  `config_file_profile = "DEFAULT"`.

## Resources Terraform cannot provision

Some resources have no Terraform resource, or are ephemeral. Create them
best-effort via the cloud CLI after `apply`, then verify the accessor:

- **AWS Bedrock advanced-prompt-optimization job** — ephemeral batch job.
  `aws bedrock create-advanced-prompt-optimization-job`. The input JSONL is
  undocumented: each entry needs `version`, `templateId`, `promptTemplate`,
  and `evaluationSamples` with `inputVariables` as `[{var: value}]`. Use a
  model the account can actually invoke (an inference-profile id such as
  `us.amazon.nova-lite-v1:0`).
- **AWS DSQL CDC stream** — `aws dsql create-stream` with
  `--ordering UNORDERED` and a Kinesis stream + IAM role created in Terraform.
- **GCP DLP connection** — `gcloud dlp` may be unavailable; POST to
  `https://dlp.googleapis.com/v2/projects/<p>/locations/us/connections`. Needs
  a live Cloud SQL instance to reach `AVAILABLE`.

If a resource cannot be created even by CLI, verify the accessor resolves
cleanly (empty list, no error) and record the limitation.

## Teardown failure modes

`terraform destroy` frequently cannot finish on its own. Known cases:

- **AWS subnet stuck on `DependencyViolation`**: a deleted SageMaker domain
  leaves an EFS filesystem + mount-target ENI in the subnet. Find it with
  `aws ec2 describe-network-interfaces --filters Name=subnet-id,Values=<id>`,
  then `aws efs delete-mount-target` → wait → `aws efs delete-file-system`,
  then re-run `terraform destroy`.
- **OCI security list "in use" / API circuit-breaker open**: repeated retries
  trip the OCI VirtualNetwork circuit breaker. Delete the OCI resources
  directly with the CLI in dependency order — subnet → security list → route
  table → internet gateway → VCN → compartment — using
  `--wait-for-state TERMINATED`.
- **OCI state drift**: Terraform may drop a resource from state while it still
  exists in OCI (e.g. a subnet). Check the cloud directly, not just
  `terraform state list`.
- **GCP App Engine app**: once created it can never be deleted (only by
  deleting the whole project). `terraform destroy` fails on the default
  service. `terraform state rm` the App Engine resources and delete the rest;
  report the App Engine app as a permanent leftover (it costs ~$0 idle).

## Verifying teardown (do not trust the tag API)

- **The Resource Groups Tagging API lags deletions by hours** and keeps listing
  resources that are already gone — it *over*-reports leftovers. Confirm each
  delete against the owning service (`describe-*` / `get-*` → NotFound), not the
  tag sweep. In one cleanup, ~40% of what the tag API listed was already deleted.
- **`get-resources` cannot delete** — it only lists. Deletion is `terraform
  destroy`, a tag-scoped nuke tool, or per-service calls in dependency order.
- **Non-deletable historical records are expected, not leaks** (and cost $0):
  deregistered ECS task-definitions and Batch job-definitions linger as
  `INACTIVE` forever, terminated EMR clusters and completed SageMaker jobs stay
  listed, canceled signer profiles remain. Don't chase them.
- **Scope teardown by `mondoo-run-id`**, and sweep **all regions** — a leftover
  can sit in a region the current run never touched (as can a security group in
  the account's *default* VPC, which a VPC-scoped teardown will miss).

After teardown, confirm nothing tagged `mql-pr-verify` for this `mondoo-run-id`
remains — verified per service, per the points above.
