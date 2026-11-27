# ADR 058: External-access details on IAM Access Analyzer findings, and external-access edges on data stores

## Status

Proposed. Date: 2026-11-27. Deciders: aws provider owners. Consulted: cnspec content owners.

## Context

IAM Access Analyzer's external-access analyzers report resources that a principal
outside the account or organization can reach. A review of sensitive stores asks: which
bucket, table or snapshot is reachable from outside, by whom, with which actions, under
which condition, and is it public? mql lists the findings but not their access details:

- `aws.iam.accessAnalyzer.finding` has id, resource ARN and type, owner account, status,
  timestamps, region and `analyzerArn`, and four unused-access fields; no principal, no
  public flag, no actions, no condition (`providers/aws/resources/aws.lr:3648-3696`).
- Findings are listed with `ListFindingsV2`, whose summary carries no access detail,
  per region and analyzer, filtered by status (`providers/aws/resources/aws_iam_accessanalyzer.go:276-340`).
  A refused region is logged and contributes nothing (`:303-307`).
- The unused-access fields read one `GetFindingV2` per finding, shared by four fields
  through an `Internal` cache, and skip the call for other finding types
  (`aws_iam_accessanalyzer.go:30-81`). A refused `GetFindingV2` is logged and the fields
  read empty (`:65-71`).
- `externalAccessFindings()` exists on `aws.s3.bucket`, `aws.iam.role`, `aws.kms.key`
  and `aws.sns.topic` (`aws.lr:14087`, `:3367`, `:2588`, `:6567`). All four filter the
  account's `findings()` by resource ARN only (`providers/aws/resources/aws_observed_exposure.go:16-59`),
  so they also return unused-access and internal-access findings on that ARN, and an
  account with no external-access analyzer answers `[]`, the same value as a resource
  nothing outside can reach. The function comment says so: "Returns an empty list when
  Access Analyzer is not enabled" (`:14-15`).
- DynamoDB tables, RDS snapshots, EFS file systems and EBS snapshots, which Access
  Analyzer also analyzes (`ResourceType` in the vendored SDK: `AWS::DynamoDB::Table`,
  `AWS::RDS::DBSnapshot`, `AWS::RDS::DBClusterSnapshot`, `AWS::EFS::FileSystem`,
  `AWS::EC2::Snapshot`), have no such edge (`aws.lr:15390`, `:15931`,
  `:2075`, `:21648`).
- The analyzer list gives each analyzer's type (`ACCOUNT`, `ORGANIZATION` for external
  access), status and region (`aws.lr:3578-3590`).
- `access-analyzer:GetFinding`, `ListAnalyzers` and `ListFindings` are in the permission
  manifest (`providers/aws/resources/aws.permissions.json:6-9`).
  AWS's Service Reference for IAM Access Analyzer (version v1.5, read 2026-11-26) has no
  `GetFindingV2` or `ListFindingsV2` action: it maps those operations to
  `access-analyzer:GetFinding` and `access-analyzer:ListFindings`, as the manifest's
  details already record (`:1161-1184`). The fields below need no new IAM action.

The aws provider is at `14.14.1` (`providers/aws/config/config.go:18`).

## Decision

**1. External-access fields on `aws.iam.accessAnalyzer.finding`.** New computed fields,
read from the finding's external-access detail; for a finding of any other type they are
null (scalars and maps) or empty (lists), without an API call:

| Field | Type | Source (`ExternalAccessDetails` and the v1 `FindingSummary` in `aws-sdk-go-v2/service/accessanalyzer` v1.57.12) |
|---|---|---|
| `principal()` | `map[string]string` | `principal`: principal kind (`AWS`, `Service`, `Federated`, `CanonicalUser`) to value, for example `{"AWS": "arn:aws:iam::111122223333:root"}` or `{"AWS": "*"}` |
| `isPublic()` | `bool` | `isPublic` |
| `actions()` | `[]string` | `action` |
| `condition()` | `map[string]string` | `condition`: condition key to value that limits the access |
| `sources()` | `[]dict` | `sources`: each `{type, accessPointArn, accessPointAccount}`, where `type` is `POLICY`, `BUCKET_ACL`, `S3_ACCESS_POINT` or `S3_ACCESS_POINT_ACCOUNT` |
| `resourceControlPolicyRestriction()` | `string` | `resourceControlPolicyRestriction`, for example `APPLICABLE`, `APPLIED`, `NOT_APPLICABLE`, `FAILED_TO_EVALUATE_RCP`; the set is not closed |
| `analyzer()` | `aws.iam.accessAnalyzer.analyzer` | the finding's analyzer, resolved against the already-listed analyzers |

`principal` stays a raw map. An external-access finding names a principal outside the
analyzer's zone of trust (another account, a service, a federated provider, the public),
which is not a modeled resource of the scanned account and cannot be resolved by
`NewResource`. `analyzerArn` is deprecated in favor of `analyzer()`
(`@maturity("deprecated")`, its `.lr.versions` entry unchanged).

**2. `aws.iam.accessAnalyzer.externalAccessFindings() []aws.iam.accessAnalyzer.finding`.**
The active findings of type `ExternalAccess` of `ACCOUNT` and `ORGANIZATION` analyzers.
It returns `llx.NotApplicable` ("no external-access analyzer is active") when no such
analyzer is `ACTIVE` in any region, and `llx.Forbidden` naming
`access-analyzer:ListFindings` when every region's call is refused. A refusal in some
regions keeps the other regions' findings and logs the denied ones. It shares one
listing helper with `unusedAccessFindings()`, parameterised by analyzer types and
finding type; `findings()` is unchanged.
An unused-access list (`unusedAccessFindings()`), when it is added, uses the same helper
and the same rule.

**3. Store edges.** `externalAccessFindings()` is added to `aws.dynamodb.table`,
`aws.rds.snapshot` (DB and cluster snapshots), `aws.efs.filesystem` and
`aws.ec2.snapshot`. Every store edge, old and new, reads the account's
`externalAccessFindings()` list (decision 2) and keeps the findings whose resource ARN is
the resource's:
- **Type filter, every edge.** Only `ExternalAccess` findings. For the four existing edges
  this is a correction: their description promises external or public access, and an
  unused-access finding on a role is neither.
- **Coverage.** When no external-access analyzer is `ACTIVE` in the resource's region (any
  region for `aws.iam.role`, a global resource), the edge returns `llx.NotApplicable`
  naming the region. The new edges do so unconditionally; the four existing edges do so
  only under `plugin.StructuredErrors()` and keep returning `[]` with the flag off
  (ADR 046 §9).

**4. One detail fetch, one error rule.** The external-access details come from one
memo per analyzer, filled by one paged `ListFindings` call (the v1 operation, whose
summary carries principal, action, condition, `isPublic`, sources and the RCP restriction;
read in the vendored SDK v1.57.12, `types.FindingSummary`) the
first time any finding of that analyzer reads a detail field, and keyed by finding id. A
finding whose id is not in the memo (created after the memo was filled) reads its detail
with `GetFindingV2`, as the unused-access fields do. The unused-access fields keep their
own `GetFindingV2` call. A refused detail read is cached with the value:
- the new fields return `llx.Forbidden` naming `access-analyzer:ListFindings` or
  `access-analyzer:GetFinding`, unconditionally;
- the existing unused-access fields (`lastAccessedAt`, `unusedServiceNamespace`,
  `unusedActions`, `unusedAccessKeyId`) return the same error under
  `plugin.StructuredErrors()` and keep today's empty values with the flag off.

The vendored SDK (v1.57.12) does not mark `ListFindings` deprecated. Its documentation
says `ListFindings` is supported only for external-access analyzers and that both
`ListFindings` and `ListFindingsV2` are authorized by `access-analyzer:ListFindings`; the
memo is only built for `ExternalAccess` findings, whose analyzers are `ACCOUNT` or
`ORGANIZATION`. If a later SDK deprecates `ListFindings`, the memo is dropped and every
detail read uses `GetFindingV2` (Option A).

**5. Versions, permissions and tests.** `.lr.versions` entries at `14.14.2` for every new
field. The manifest already lists both permissions; `make providers/build/aws`
regenerates `aws.permissions.json` and the PR commits any `source_file` change. Unit
tests in `aws_iam_accessanalyzer_test.go` and `aws_observed_exposure_test.go`: decoding of
an external-access detail with an `AWS` account principal, with `{"AWS": "*"}` and
`isPublic` true, with a condition and with an access-point source; null fields on an
unused-access finding without a call; one `ListFindings` pass for two findings of one
analyzer; the `GetFindingV2` fallback for a missing id; `Forbidden` on each refusal;
`NotApplicable` from the list and from an edge in a region without an analyzer; the type
filter dropping an `UnusedIAMRole` finding from a role's edge; the existing edges' `[]`
with the flag off. Each case is labelled measured or synthetic; the measured cases come
from an account with a bucket shared to a second account and a public bucket.

## Security implications

- **Threat model.** Read-only calls with the credentials the provider already holds; no
  new write path.
- **Data handling.** Principals, actions and condition values from a resource policy:
  account IDs, ARNs, service names, source IPs or VPC endpoint IDs in conditions. These
  are already visible in the resource policies mql returns (for example bucket policies).
  No data value of any store is read.
- **Authorization.** `access-analyzer:ListFindings` and `access-analyzer:GetFinding`,
  both already in the manifest. A missing permission is reported as `Forbidden` with its
  name.
- **Supply chain.** No new dependency; the Access Analyzer client is already used.
- **Residual risk.** Access Analyzer covers the resource types it supports and the
  regions where an analyzer runs. The coverage error of decision 3 makes the missing
  region visible; a resource type Access Analyzer does not analyze still has no edge, and
  internal access (inside the zone of trust) is out of scope.

## Performance implications

- **Expected impact.** Reading a detail field costs one paged `ListFindings` per analyzer
  with findings, at the service's page size (100, from the AWS documentation, not
  measured), instead of one `GetFindingV2` per
  finding. Store edges reuse the account list and the analyzer list, both already
  memoized for the scan; the coverage test is in memory. Scans that read none of the new
  fields are unchanged.
- **Evidence.** From the code paths and the API page size as remembered; not measured.
- **Scale assumptions.** An organization analyzer with 10^4 findings is 100 pages, once
  per scan, against 10^4 `GetFindingV2` calls for a per-finding read.
- **Regression budget.** At most one `ListFindings` pass per analyzer per scan, checked in
  the debug log of the live verification.

## Consequences

### Positive

- A check can say which sensitive store is reachable from outside, by whom and with which
  actions, and can tell "no analyzer here" from "nothing reachable".
- One listing helper serves external-access and unused-access lists.

### Negative

- Two listing operations (v2 for the lists, v1 for the details) for the same findings.
- The four existing edges answer differently with the flag on than off until v15.

### Follow-up

- Edges on further Access Analyzer resource types (Secrets Manager, SQS, Lambda, ECR, S3
  directory buckets) when a check needs them.
- A per-region coverage field on `aws.iam.accessAnalyzer` if content needs more than the
  analyzer list.

## Alternatives considered

### Option A - `GetFindingV2` per finding for the external-access details

One operation, as the unused-access fields use. Kept only as the fallback: a full read of
an account's external-access details costs one call per finding.

### Option B - A typed principal accessor

Rejected: an external principal is outside the scanned account by definition and is not a
modeled resource; an accessor would always be null.

### Option C - Change `findings()` to external access only

Rejected: `findings()` serves other checks (unused access, archive review), and a filter
there changes their verdicts. The unused-access list is added beside it for the same
reason.

### Option D - Leave the existing edges unfiltered

Rejected: an unused-access finding on a role read as external access is a false positive.

## References

- mql `providers/aws/resources/aws.lr`, `aws_iam_accessanalyzer.go`,
  `aws_observed_exposure.go`, `aws.permissions.json`, `providers/aws/config/config.go`
  (at `d8f47a409`)
- mql `docs/adr/046-structured-provider-errors.md` (§3, §8, §9)
- AWS IAM Access Analyzer API: `ListFindings`, `ListFindingsV2`, `GetFindingV2`,
  `ExternalAccessDetails`
