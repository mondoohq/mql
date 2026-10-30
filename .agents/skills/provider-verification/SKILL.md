---
name: provider-verification
description: >-
  Verify mql provider resource/field changes against real cloud infrastructure.
  Given a pull request or a commit range, this provisions Terraform infra in the
  affected cloud(s), runs mql queries against every new or changed resource and
  field, reports the hourly cost (pausing for approval above $2/hr), opens a fix
  PR for any provider bugs it uncovers, and tears the infrastructure back down.
  Use this whenever someone wants to test, verify, smoke-test, or "prove out" a
  provider PR or a range of commits against live cloud APIs — e.g. "verify PR
  #7701 works", "spin up infra to test the new GCP resources", "check the azure
  changes against real infrastructure", "test resources changed between these
  commits". Trigger it even when the user only says "test this PR" in the
  context of an mql provider change.
---

# Provider Verification

mql resources are thin wrappers over cloud APIs, so a `.lr` schema change is
only really "done" once it has been run against a real cloud account. This
skill automates that loop: figure out what changed, stand up just enough real
infrastructure to exercise it, query it with `mql run`, and clean up.

It exists because the failure modes that matter — a wrong location wildcard, a
missing API view, an SDK that lags the service — are invisible to compile
checks and unit tests. They only show up against live APIs.

## Inputs

One of:
- **A pull request**: a number (`7701`) or URL. Diff comes from `gh pr diff`.
- **A commit range**: `<base>..<head>` (e.g. `7bfc8787a..HEAD`). Diff comes from
  `git diff`.

Accept multiple PRs at once — verify them together in one infra spin-up.

## Workflow

Work through these steps in order. Track them with TodoWrite — the run is long
and the teardown step must not be skipped.

### 1. Extract what changed

Run the bundled script — it parses the diff and lists every added/changed
resource and field, grouped by provider:

```bash
python3 .agents/skills/provider-verification/extract_changes.py --pr 7701
python3 .agents/skills/provider-verification/extract_changes.py --range A..B
```

It reports `.lr` schema changes (new resources, new fields) and flags the
provider `.go` files that changed. A PR can touch a provider's code without
touching its `.lr` (a pure bugfix); still verify those resources.

Doc-comment-only `.lr` changes (a PR that just adds doc-comments to existing
resources) do not need infrastructure — skip them, but say so in the report.

### 2. Build the affected providers

The merged PR code must be running locally. From the repo root:

```bash
make providers/build/<provider> && make providers/install/<provider>
```

Build every affected provider. If the PRs are **not** yet merged, check out the
PR branch first. If verifying a commit range, check out the head commit.

### 3. Check cloud auth

For each affected cloud, confirm credentials before provisioning anything:
`aws sts get-caller-identity`, `az account show`, `gcloud config get-value
project`, `oci iam region list`. If a cloud is not authenticated, stop and tell
the user — do not try to provision it.

### 4. Pre-flight: remove leftovers from prior runs

A run that crashed or was interrupted before teardown leaves tagged infra
behind — and it keeps billing until deleted. Clear it **before** provisioning
anything new. Everything this skill creates carries `project = mql-pr-verify`,
so leftovers are unambiguous. Two sources, cleanest first:

1. **Local scratch dirs with live state.** Any `~/dev/mql-verify-*/<cloud>/`
   whose `terraform state list` is non-empty is a prior run that never
   destroyed. Run `terraform destroy` there — intact state tears down in
   dependency order, which is more reliable than deleting resource-by-resource.

2. **Cloud tag sweep** (catches runs whose scratch dir or state was lost). For
   each authenticated cloud, list resources tagged `project = mql-pr-verify`,
   then delete them:

   ```bash
   # Azure — each run puts everything in one resource group; this deletes them.
   az group list --query "[?tags.project=='mql-pr-verify'].name" -o tsv \
     | xargs -r -I{} az group delete -n {} --yes --no-wait

   # AWS — sweep EVERY region, not just this run's; a prior run may have used
   # another. get-resources only *lists* — the tagging API cannot delete, and it
   # lags deletions by hours, so it also over-reports. To DELETE, prefer
   # `terraform destroy` from the leftover scratch dir; otherwise use a
   # tag-scoped nuke tool or per-service deletion (see cloud-notes teardown).
   for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
     echo "== $R =="
     aws resourcegroupstaggingapi get-resources --region "$R" \
       --tag-filters Key=project,Values=mql-pr-verify \
       --query 'ResourceTagMappingList[].ResourceARN' --output text
   done

   # GCP — Terraform tags land as labels
   gcloud asset search-all-resources \
     --scope=projects/<project> --query='labels.project=mql-pr-verify' \
     --format='value(name,assetType)'
   ```

**List what matched before deleting.** If a match was created within the last
few minutes it may belong to a **concurrent** run — pause and confirm rather
than deleting it. AWS and GCP have no single "delete the whole tagged set"
command: delete by resource (see cloud-notes for per-service gotchas), or
`terraform destroy` via the leftover scratch dir when one still exists.

Report what was removed (or that nothing was) in the final report's Teardown
section.

### 5. Generate Terraform

Goal: the **cheapest** real resources that make each changed field return
non-empty, non-error data. Smallest SKUs, smallest instances, free tiers where
they exist.

Read `references/cloud-notes.md` before writing any Terraform — it lists the
per-cloud gotchas (SKUs that no longer exist, APIs that need a quota project,
resources Terraform cannot create) that this process has already hit. It will
save you a failed `apply`.

Write Terraform into a scratch directory **outside the repo** (e.g.
`~/dev/mql-verify-<timestamp>/<cloud>/`), one stack per cloud. When more than
one cloud is involved, dispatch one subagent per cloud to write its stack in
parallel — each agent writes the `.tf`, runs `terraform init/validate/plan`,
and reports a per-resource hourly cost. Agents must not `apply`.

**Tagging is mandatory and enforced — not applied per resource.** A single
hand-applied tag is how leftovers escape: one resource created without it (or by
a crashed run) bills unnoticed for months. Close that hole two ways.

First, set the run's identity once, before writing any Terraform:

- `RUN_ID` — reuse the scratch-dir id (e.g. `mql-verify-<timestamp>`). It lets
  teardown and the reaper delete a whole run's resources as a unit, and lets
  concurrent runs tell their resources apart (replaces the "created in the last
  few minutes" guess).
- `EXPIRY` — an RFC3339 timestamp of `now + TTL` (default **8h**; raise it for
  known-slow stacks like Composer). This is the machine-readable contract the
  out-of-band reaper enforces — it deletes anything whose `EXPIRY` is in the past.

Second, apply the schema through each provider's **default tags**, so every
resource is tagged automatically and none can be created bare:

| Cloud | Mechanism |
|---|---|
| AWS | `default_tags { tags = {...} }` in the `aws` provider block |
| Azure | `default_tags` on the `azurerm` provider **and** one resource group per run |
| GCP | default `labels` on the provider / resources (lower-case keys) |

Schema — identical keys on every cloud:

```
project        = "mql-pr-verify"   # canonical value; never a per-effort variant
mondoo-run-id  = <RUN_ID>
mondoo-expiry  = <EXPIRY>           # reaper deletes when this is in the past
mondoo-created = <now, RFC3339>
owner          = <whoami / git user.email>
source         = "provider-verification"
```

Resources that genuinely cannot be tagged must live **inside** the per-run
container (resource group / VPC / project) so they are still deletable by run.
Note any that can't be tagged in the report.

### 6. Cost gate

Sum the 1-hour cost across every cloud's `terraform plan`. Present a per-resource
cost table and the total.

- **Total ≤ $2/hour**: state the cost and proceed.
- **Total > $2/hour**: STOP. Show the table and ask the user to approve before
  applying. Do not apply until they say yes.

### 7. Apply

`terraform apply -auto-approve` per cloud — run them in parallel in the
background; some resources are slow (see cloud-notes). Re-apply on transient
failures, but cap it at **2–3 attempts** — a failure that survives that many
re-applies is not transient. Treat it as a blocker or an environment
limitation and stop retrying. If a resource genuinely cannot be created,
remove it from the stack, note it, and continue — one bad resource must not
block the rest.

### 8. Verify with `mql run`

For **every** new or changed resource and field, run a query and confirm two
things: it returns **no error**, and it returns **appropriate data**.

```bash
mql run <provider> -c "<resource> { <changed fields> }"
```

- A new field that resolves to `false`/`""`/`[]` is fine **if** that genuinely
  reflects the resource's state (feature disabled, list empty). It is **not**
  fine if the field should have data — that is a bug.
- A query that errors, or `no data available` caused by an underlying API
  error, is a bug. Capture the exact error.
- Typed reference fields (`vpc()`, `kinesisStream()`, …) must resolve to the
  referenced resource, not error.

For resources Terraform cannot provision (ephemeral jobs, etc.), create them
best-effort via the cloud CLI (see cloud-notes) so the accessor still gets
exercised. If even that is impossible, verify the accessor resolves cleanly
(empty, no error) and say so.

**CLI-created resources are not in Terraform state, so `terraform destroy` will
not remove them.** Tag each with the same schema (step 5) and append its id and
delete command to a `cli-resources.json` manifest in the run's scratch dir, so
teardown (step 11) explicitly deletes them and nothing escapes. Anything you
cannot tag must go in the per-run container.

### 9. Triage bugs

A bug is any verification failure caused by **provider code**, including
preexisting bugs in code outside the PRs under test. For each:

- **Has a clear, verifiable fix**: fix it (see step 10).
- **No confident fix** (e.g. an SDK lagging a new API): do **not** guess a fix.
  Record it in the report and offer to open a tracking GitHub issue.

A failure caused by the cloud account (expired trial, missing quota, un-enabled
API) is **not** a provider bug — report it as an environment limitation.

### 10. Fix PR

If there are bugs with verifiable fixes, open **one combined PR** for all of
them, across every provider:

1. Work in a worktree branched from `main`.
2. Apply the fixes. Match existing patterns in the provider (see AGENTS.md).
3. `gofmt -w` changed files; rebuild the provider; **re-run the failing
   queries against the still-live infrastructure** to confirm each fix works.
4. Commit `*.permissions.json` if a fix changed it. No `.lr.versions` change
   unless a fix adds a schema field.
5. Commit (emoji-prefixed per AGENTS.md — `🐛`), push, `gh pr create`.

Verify fixes **before** teardown — the infrastructure is needed to prove them.

### 11. Teardown — always

Always destroy every stack at the end, even on failure, even when bugs were
found (the fix PR was already verified in step 10). Run `terraform destroy` per
cloud.

Destroy is fragile — handle the known failure modes in cloud-notes (orphaned
EFS mount targets blocking AWS subnets, OCI API circuit-breakers, resources
Terraform dropped from state). Fall back to CLI deletion when `terraform
destroy` cannot finish. When state is lost entirely, delete the whole run by its
`mondoo-run-id` tag rather than resource-by-resource.

**Verify per service, not via the tagging API.** AWS Resource Groups Tagging
(and GCP asset search) lag deletions by hours and keep listing resources that
are already gone — trusting them produces false "still leaked" alarms *and* can
mask a genuine miss. Confirm the delete against the owning service
(`describe-*` / `get-*` returning NotFound), and remember non-deletable historical
records (deregistered ECS/Batch definitions, terminated EMR clusters, canceled
signer profiles) will linger in the tag API at $0 — those are expected, not leaks.

Note anything that genuinely cannot be deleted (e.g. an App Engine app) in the
report — do not leave the user guessing.

**Teardown is not the only safety net.** It runs inside this agent process, so a
crash between apply and here orphans everything. The `mondoo-expiry` tag exists so
an out-of-band reaper (scheduled independently of any run) can delete expired
resources regardless of whether this run finished. Tearing down cleanly here is
still required — the reaper is the backstop, not the plan.

### 12. Report

Always end with this structure:

```
# Verification report — <PRs / commit range>

## Provisioned
<per-cloud resource count + total $/hour for the run>

## Results
| PR / area | Resource / field | Result | Detail |
(✅ pass / ⚠️ partial / ❌ bug, one row per changed resource or field group)

## Bugs
<each bug: file:line, the failing query, observed vs expected, and either
"fixed in PR #NNNN" or "no verified fix — offer to open an issue">

## Environment limitations
<failures caused by the account, not the code>

## Teardown
<confirmation everything was destroyed; anything that could not be>
```

After the report, if there are unfixable bugs, offer to open a tracking issue.

## Key rules

- **Cost gate is $2/hour total.** Below it, proceed. Above it, pause for
  approval. Always show the number.
- **One combined fix PR** for all bugs, regardless of how many providers.
- **Always tear down** — unconditionally, at the end.
- **Every resource carries the full tag schema** (`project`, `mondoo-run-id`,
  `mondoo-expiry`, `mondoo-created`, `owner`, `source`) via provider default
  tags. Untagged infra is invisible to both cleanup and the reaper — it is
  exactly how leaks happen.
- **Cheapest infra that works.** This is a verification run, not a deployment.
- **Honest reporting.** An empty result is a pass only when empty is correct;
  otherwise it is a bug. Never claim a field works without seeing real data.

## Reference

- `references/cloud-notes.md` — per-cloud Terraform/CLI gotchas, slow resources,
  and what cannot be provisioned or destroyed. Read it before steps 4, 5, 7, 11.
- `extract_changes.py` — diff → changed resources/fields, grouped by provider.
