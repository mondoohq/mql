# ADR 046: Structured provider errors

## Status

Accepted

## Context

A provider fails in many different ways, and mql can tell almost none of them
apart. "I am not allowed to read this", "this does not exist", "this account
never enabled the service", "slow down", and "the provider crashed" all arrive
at the executor as the same thing: a string in a field, or a null.

That matters most for **access errors** — the caller lacks the permission to read
something. They are universal. An OS scan runs as a user who cannot read
`/etc/shadow`; every cloud refuses a call the role was not granted; SaaS APIs
answer 403 for a scope the token does not hold. A check that cannot read what it
is asserting about has not passed, and today it frequently looks like it did.

But access is one kind among several, and classifying it alone would leave the
next author to invent their own vocabulary for the one beside it. This ADR
defines the whole set, once.

### The vocabulary already exists — it is just written 143 times

There are 143 `func …(err error) bool` classifiers under `providers/`, written
independently, converging on the same handful of meanings:

| meaning | a few of the names in the tree |
|---|---|
| refused | `Is400AccessDeniedError`, `isAzureAccessDenied`, `IsForbidden` (×8), `IsPermissionError` (×3), `isNoPerm`, `isUnauthorized` |
| absent | `IsNotFound` (×10), `efsPolicyNotFound`, `isAbsentKey`, `ossConfigAbsent`, `ociZprAbsent` |
| does not apply here | `isServiceDisabled`, `isAzureFeatureUnavailable`, `isOrganizationsNotInUseError`, `IsMacieNotEnabledError`, `IsPlanRestricted`, `isOktaFeatureUnavailable`, `ociCloudGuardNotSubscribed` |
| wrong region for the call | `IsServiceNotAvailableInRegionError`, `azureProviderNotInRegion`, `bigqueryLocationUnsupported`, `ociRegionServiceUnavailable`, `esRegionUnavailable` |
| transient | `exchangeErrorIsTransient`, `httpNotReachable`, `isConnectionRefused`, `isServiceUnavailable` |
| our code is stale | `isRemovedAPIEndpoint`, `azureClassicAdministratorsRetired`, `isUnknownCommandErr`, `isOperationNotSupportedError` |

Two providers have already written this ADR's argument in comments.
`providers/gcp/resources/errors.go` builds a three-level nesting and warns that
"every code folded into a degrade-to-empty check is a real failure the user will
never see". `providers/azure/resources/shared.go` keeps `isAzureAccessDenied`
deliberately narrower than `isAzureFeatureUnavailable`, because on a collection
that *is* the finding, "nothing is configured" and "not allowed to look" must not
be the same answer.

So the distinction is understood per provider. What is missing is a shared type,
a wire format, and a consumer that acts on it.

### Scale

- 784 `Is400AccessDeniedError` call sites in aws, 187 gcp
  `isSkippable`/`isInapplicable`/`isServiceDisabled`, 47 azure.
- 4,124 explicit `StateIsNull` sites across all providers.

Most of those call sites end in a null. A scan run without permissions therefore
produces the same values as a scan of a system where the thing is genuinely
absent — and an empty collection is the most dangerous wrong answer a posture
check can receive, because assertions over it pass vacuously.

### Structure dies at the process boundary, twice

`TValue.ToDataRes` renders a field error to text
(`providers-sdk/v1/plugin/runtime.go:193-214`), and the executor rebuilds an
anonymous error from that text:

```go
// providers/runtime.go:680
raw = &llx.RawData{Error: errors.New(data.Error)}

// providers-sdk/v1/plugin/runtime.go:164, :184
if res.Error != "" {
    return nil, errors.New(res.Error)
}
```

`DataRes.error` is a `string` (`providers-sdk/v1/plugin/plugin.proto:91-96`), and
so is `llx.Result.error` (`llx/llx.proto:250-254`) — which is what recordings
persist (`providers-sdk/v1/recording/recording.go:251-253`) and what ships
upstream. Any type a provider builds is flattened on the way out and cannot be
recovered on the way in.

The consequence is visible downstream. cnspec detects throttling by matching the
rendered text:

```go
// cnspec policy/scan/reporter_aggregate.go:80
if err != nil && strings.Contains(strings.ToUpper(err.Error()), "TOOMANYREQUESTS") {
```

That is the same mistake `plugin.IsUnsupportedProviderError` makes on a wrapped
error, and the reason [ADR 045](045-iac-meta-target.md) introduced a status
detail instead.

### Two precedents, both deliberate, both partial

**[ADR 045](045-iac-meta-target.md) built the carrier.** `ErrorKind` and
`ErrorDetail` (`providers-sdk/v1/plugin/plugin.proto:57-75`) exist because "an
error value does not survive the process boundary", and `ErrorDetail` is named
for the general case explicitly so more kinds can move onto it without a second
message. `IsNoMatchError` reads three arms in order of authority — sentinel,
detail, message text — so a provider built before the detail existed still
classifies. That structure is what this ADR borrows; it applies it to the other
relevant calls. Today it is Connect-only: nothing normalizes a kind on `GetData`.

**`llx/skew.go` built the end-to-end path, for one kind.** A typed error
(`errFieldUnavailable`) with an `Is` method folding onto a sentinel
(`ErrVersionSkew`), a predicate (`IsUnavailable`), a runtime decision point
(`degradeUnavailableField`, `llx/builtin.go:949-990`), and distinct rendering —
`print.Disabled` rather than `print.Error` (`cli/printer/mql.go:416`, `:509`).
Version skew got exactly the treatment access errors need. Everything below
generalizes that shape.

### ADR 043 parked this work, pointing here

[ADR 043](043-mql-strict-mode.md) §3 lists provider-side null production as out
of scope and says why: strict mode "puts real pressure on the 771 AWS call sites
to be revisited. That is intended, and it is the largest piece of follow-on
work." This is that work. 043 governs what happens downstream of a null; this ADR
governs whether the null should have been produced at all.

### This is the v14 rc window

v14 has not released. The last stable tag is v13, and everything that exists
only in the rc is still ours to change without breaking anyone. Two pieces of
this ADR need exactly that window: the `ErrorDetail` move (§5) and the two new
proto fields on `DataRes` and `Result`. After GA the same changes are either
breaking or have to be carried twice, forever, which is the position the
taxonomy would inherit rather than fix.

That is the reason to settle this now rather than after v14 ships. It is not a
reason to rush the provider migration: phase 1 is the part that has to make the
window, and everything after it is ordinary work at ordinary pace.

## Decision

### 1. Nine kinds, named by their HTTP equivalent

Every classified failure is one of these. **The HTTP column names the
ErrorKinds, and it is also the SDK's default mapping.** The SDK maps an HTTP
status, or a gRPC status code for SDKs that speak gRPC, to its mql ErrorKind
(phase 2). A provider calls that mapping only after its own checks, because the
body can overrule the status (§2): the mapping is a starting point, never the
whole answer. No status is carried on the wire (§4). The column is here because
"403" is also the shortest way to say what `forbidden` means to a reader who has
to classify an error they have never seen before.

| kind | enum | HTTP | means | in the tree today |
|---|---|---|---|---|
| unauthenticated | `ERROR_KIND_UNAUTHENTICATED` | 401 | we are not who we need to be: no credentials, wrong credentials, expired or revoked token | `github/connection:220`, `keycloak/connection/client.go:90`, `notion` `isUnauthorized` |
| forbidden | `ERROR_KIND_FORBIDDEN` | 403 | we are authenticated and not permitted. **The access error**, and it includes an OS elevation failure: needing `sudo` and not having it is a permission we are asking for | `Is400AccessDeniedError` (784 sites), `isAzureAccessDenied`, `isNoPerm`, `os.ErrPermission`, `sudo.go:329` |
| not found | `ERROR_KIND_NOT_FOUND` | 404 | the provider could not answer because what it had to read is not there: no such bucket, no such file, no such key. A legitimate absence is a null value and not this kind (§3) | `IsNotFound` (×10), `isKmsNotFoundError`, `isRegistryKeyAbsent` |
| not applicable | `ERROR_KIND_NOT_APPLICABLE` | 501 | the question does not apply to this target: API not enabled, resource provider not registered, feature not in this plan or edition, service not offered in this region, resource not supported on this platform | `isServiceDisabled`, `isOrganizationsNotInUseError`, `IsPlanRestricted`, `IsServiceNotAvailableInRegionError`, `kernel.go:27` |
| gone | `ERROR_KIND_GONE` | 410 | the API we call existed and does not any more: retired endpoint, removed operation, command the target no longer has | `isRemovedAPIEndpoint`, `azureClassicAdministratorsRetired`, `isUnknownCommandErr` |
| too many requests | `ERROR_KIND_TOO_MANY_REQUESTS` | 429 | throttled. Carries `retry_after` when the API said so | handled in three providers (`github/connection/connection.go:297`, which folds it in with 403; `iru`; `ms365`), generic everywhere else |
| unavailable | `ERROR_KIND_UNAVAILABLE` | 503 | the target is temporarily not answering: 503, connection refused, DNS failure. Other 5xx statuses and timeouts give the user nothing to act on and stay unclassified | `isServiceUnavailable`, `httpNotReachable`, `isConnectionRefused` |
| malformed data | `ERROR_KIND_MALFORMED_DATA` | — | the target answered and what it said cannot be read: config file that does not parse, JSON that does not decode, a field in a shape the API does not document | `auditd.go:97,103` ("failed to parse auditd config"), and every parse error in `providers/os` that today reaches the user as bare text |
| asset vanished | `ERROR_KIND_ASSET_VANISHED` | — | the asset went away while we were scanning it | `mqlc/mqlc.go:1446`, read downstream by a string prefix (`nodes.go:506`) |

**Asset vanished is the one kind no provider produces.** The other eight are a
provider classifying its own target's answer; this one is raised by the compiler
when `c.Schema.Lookup` finds nothing for a resource type, and cnspec already
reads it — by matching the prefix `"could not find resource"` — to mean the asset
disappeared mid-scan. It is in the taxonomy because it is the same anti-pattern
in the same position, and because the alternative is a ninth vocabulary invented
beside this one. It is also the single kind whose scoring differs; see the cnspec
section.

Everything else is **unclassified**: `ERROR_KIND_UNSPECIFIED`, which is also what
an absent detail means. Unclassified is not a failure of the taxonomy, it is the
honest default, and it renders and scores as a hard error. A kind is a claim; a
provider that does not know makes no claim.

**An ErrorKind exists because there is something for the user to do.**
Unauthenticated and forbidden point at credentials and grants, not applicable
at what the target offers, too many requests at pacing, unavailable at a target
that is not answering. A failure that tells the user nothing to do, such as a
500, a 504 or a timeout, stays unclassified. That is the test for a new
mapping: name the user's action, or leave it out.

`ERROR_KIND_ASSET_VANISHED` is built where the error is raised
(`mqlc/mqlc.go:1446`) rather than by a classifier, so it needs no provider
migration and can land with phase 1.

`ERROR_KIND_NO_MATCH` (ADR 045) keeps value 1 and stays Connect-only. It is a
statement about a *target*, not about a call, and nothing on the data path
produces it.

#### The distinctions that will be argued about

- **not found vs not applicable.** Not found is "this instance is not there",
  not applicable is "this kind of thing does not exist here". A missing S3 bucket
  policy is not found. A project that never enabled the Compute API, an account
  that belongs to no organization, `kernel` on Windows, and a Zoom plan without
  the audit endpoint are all not applicable. The test: would the thing exist if
  someone created it? Then it is not found. Is the concept itself absent from
  this target? Then it is not applicable.
- **not applicable vs gone.** Not applicable is about the target; gone is about
  us. A retired API is our code being out of date and the addressee is Mondoo,
  not the user.
- **unauthenticated vs forbidden.** Credentials versus grants. They have
  different remediations and, usually, different scopes (§3): a 401 means every
  subsequent call on this asset will fail too. Ten providers fold `401 || 403`
  into one predicate today (`netlify`, `keycloak`, `artifactory`,
  `clickhousecloud`, `elasticsearch`, …); those split.
- **unavailable vs too many requests.** Both transient, both retriable, but a
  429 carries a server-stated wait and a 503 does not. Keeping them apart is what
  lets a scan back off correctly instead of hammering an API that just asked it
  not to.
- **malformed data vs unclassified.** Malformed data is a fact about the target
  that the user can act on ("this file is not valid YAML"). A decode failure
  caused by our own struct tags is a bug and stays unclassified.

### 2. Classify by what the target said, not by the status alone

A provider reads whatever its SDK hands it — an `azcore.ResponseError` status, a
`codes.PermissionDenied`, an exit code, an `errno` — and decides a kind. The kind
is the only thing recorded. Two rules follow, and both are already load-bearing
in the tree:

- **A status can be overruled by the body.** GCP answers 403 for an API that was
  never enabled; `isServiceDisabled` reads the message for "has not been used" /
  "not enabled" precisely because status alone would call it forbidden. That case
  classifies as **not applicable**. Azure answers 400 with
  `ResourceTypeNotSupported` for the same meaning
  (`azureFeatureNotApplicable`).
- **Pick the narrowest kind that is true.** gcp's `errors.go` already says this:
  the wider the classifier, the more real failures disappear into it. Not
  applicable is the widest of the nine and the easiest to abuse; when a call
  site cannot distinguish "not enabled" from "denied", it is denied.

A provider that cannot tell leaves the error unclassified. That is strictly
better than a wrong kind, because a wrong kind is believed by everything
downstream.

### 3. A classified failure stays an error

This is the decision ADR 043 anticipated. A classified error is an **error**,
not a labeled null. Three consequences:

- **The `Is400AccessDeniedError → return nil, nil` idiom ends.** A refusal is
  reported as an error carrying `ERROR_KIND_FORBIDDEN`. The 784 aws sites, the 47
  azure sites and the 187 gcp sites are the migration, and they are also the
  entire point: under-permissioned scans stop resembling clean ones.
- **This does not turn legitimate nulls into errors.** A field that is null
  because the thing is genuinely absent stays null — an optional Azure
  sub-resource that was never created is a *value*, and the provider is right to
  report it. `ERROR_KIND_NOT_FOUND` is for when the provider cannot answer the
  question, not for when the answer is "nothing". The rule is directional: a
  **refusal must never be reported as a null**, an absence may be. So
  `ERROR_KIND_NOT_FOUND` never labels a legitimate absence, and wherever it does
  appear the provider could not answer — which is unambiguously an error.
- **Strict mode does the rest.** Under ADR 043 an error propagates as itself and
  names the link that broke, while a null is absorbed. Producing errors instead
  of nulls is what makes strict mode reach access problems at all.

### 4. What rides beside the kind

An access error that says "forbidden" is a label. One that says "forbidden,
`ec2:DescribeInstances`, region `eu-west-1`" is a fix. Four fields:

- **`kind`** — §1.
- **`permissions`** — the permission the call needed, e.g.
  `iam:GetAccountPasswordPolicy`. Best supplied by the call site. Where it is
  not, the provider's own `*.permissions.json` is the fallback:
  `PermissionDetail` already carries `Permission`, `Service`, `Action` and
  `SourceFile` (`providers-sdk/v1/util/permissions/permissions.go:33-44`), so a
  failure in a known source file yields a candidate set. Repeated, because file
  granularity is a set and some calls genuinely need several grants. Accuracy is
  a quality-of-implementation matter, and an empty list is always allowed. On an
  OS asset the same field names the elevation the scan lacked (`root`, a `sudo`
  rule), which is the same sentence to the user: here is what to grant us.
- **`scope` + `scope_id`** — how far the failure reaches: `FIELD`, `RESOURCE`,
  `PARTITION` (a region, project, or subscription, named by `scope_id`), or
  `ASSET`. This is what lets a consumer aggregate 784 identical denials into one
  line, and what tells an unauthenticated failure apart from a field-level one:
  a 401 is `ASSET` and there is no point continuing.
- **`retry_after`** — milliseconds, from `Retry-After` or the SDK's own hint,
  for 429 and 503. Carried, not acted on: nothing in this ADR retries anything.
  `upstream.WithRetry` already takes this shape (`retryable bool, retryAfter
  time.Duration`), so whatever eventually consumes the hint has a signature to
  fit.

Deliberately **not** included: a structured upstream error code (`AccessDenied`,
`ResourceTypeNotSupported`) and the raw HTTP status. Both are already in the
error message, which is kept verbatim and is what a human reads when a kind is
not enough, and neither has a consumer that would branch on them — the kind is
what consumers act on, by design. A machine-readable status would only earn its
place if later translation work needs to reason about the original response
rather than about the kind; that is the one thing that would reopen it. Adding a
field then is cheap, and removing one that shipped is not.

### 5. The carrier: ADR 045's, moved down a layer

Same enum, same message, extended — not a second mechanism:

```proto
// llx/llx.proto
enum ErrorKind {
  ERROR_KIND_UNSPECIFIED       = 0;
  ERROR_KIND_NO_MATCH          = 1;  // ADR 045, Connect only
  ERROR_KIND_UNAUTHENTICATED   = 2;
  ERROR_KIND_FORBIDDEN         = 3;
  ERROR_KIND_NOT_FOUND         = 4;
  ERROR_KIND_NOT_APPLICABLE    = 5;
  ERROR_KIND_GONE              = 6;
  ERROR_KIND_TOO_MANY_REQUESTS = 7;
  ERROR_KIND_UNAVAILABLE       = 8;
  ERROR_KIND_MALFORMED_DATA    = 9;
  ERROR_KIND_ASSET_VANISHED    = 10;
}

enum ErrorScope {
  ERROR_SCOPE_UNSPECIFIED = 0;
  ERROR_SCOPE_FIELD       = 1;
  ERROR_SCOPE_RESOURCE    = 2;
  ERROR_SCOPE_PARTITION   = 3;
  ERROR_SCOPE_ASSET       = 4;
}

message ErrorDetail {
  ErrorKind kind = 1;
  ErrorScope scope = 2;
  // Names the partition for ERROR_SCOPE_PARTITION: a region, project, or
  // subscription. Empty for every other scope.
  string scope_id = 3;
  // Permissions the refused call needed. Possibly several, possibly none.
  repeated string permissions = 4;
  // Server-stated wait for 429 and 503. Zero means "no hint", not "retry now".
  int64 retry_after_ms = 5;
}
```

**It moves to `llx.proto`, and that is forced.** `plugin.proto` imports
`llx/llx.proto`; `llx.proto` imports nothing. `llx.Result` has to carry the
detail — it is what recordings persist and what ships upstream — so the message
has to live at or below `llx`, or the import cycles. `plugin` keeps Go aliases so
ADR 045's `plugin.ErrorDetail` and `plugin.ErrorKind_ERROR_KIND_NO_MATCH` keep
compiling.

Moving it changes the status-detail type URL from
`cnquery.providers.v1.ErrorDetail` to `mql.llx.ErrorDetail`. That is a
compatibility event for exactly one thing — `IsNoMatchError`'s detail arm against
a provider binary built before the move — and its third arm, the message text,
already covers that case. The rc window is what makes it free: v14 has not
released (`providers/aws/config/config.go`: `14.0.0-rc.1`), the last stable tag
is v13, and no released build carries the old type URL on this path. After GA
the choice is two carriers forever, which is the outcome ADR 045's comment was
written to avoid.

Three wire sites:

- **`DataRes`** gets `mql.llx.ErrorDetail error_detail = 4;`, beside the
  existing `error` string. This is the normal path: a provider reporting a field
  failure is not returning a gRPC status, so a status detail alone would never
  reach the executor.
- **`llx.Result`** gets `ErrorDetail error_detail = 4;`, so the kind survives
  into recordings, into upstream storage, and into assessments.
- **gRPC statuses** keep ADR 045's detail mechanism unchanged, for errors that
  are statuses: `Connect`, and the transport failures `handlePluginError`
  inspects.

Three in mql. cnspec adds two of its own, because a check's outcome travels as a
`Score` rather than as a `Result` — see the cnspec section.

**Not gRPC status codes as the vocabulary.** `codes.Unavailable` on the data path
already means "the plugin process crashed" (`providers/runtime.go:749-756`), and
`codes.PermissionDenied` would then be ambiguous between "the target refused the
provider" and "the runtime refused the provider". The status codes describe the
plugin transport; the kinds describe the target. They are different subjects and
need different words.

### 6. In-process: one typed error, in `llx`

Mirroring `llx/skew.go`, in a new `llx/errors.go`:

```go
// llx.Error carries a kind across the parts of the system that still hold a Go
// error rather than a proto.
type Error struct {
    Kind        ErrorKind
    Scope       ErrorScope
    ScopeID     string
    Permissions []string
    RetryAfter  time.Duration
    err         error // the upstream error, verbatim, for the message
}

func (e *Error) Error() string  { … }
func (e *Error) Unwrap() error  { return e.err }
func (e *Error) Is(target error) bool // folds onto the kind sentinel

var ErrForbidden, ErrUnauthenticated, ErrNotFound, … error

func Forbidden(err error, opts ...ErrorOption) error
func KindOf(err error) ErrorKind // UNSPECIFIED for anything untyped, including nil
```

`llx` rather than `plugin` because `llx` cannot import `plugin` and the executor
and the printer both need `KindOf`. Providers already import `llx` for
`llx.BoolDataPtr` and friends, so `return nil, llx.Forbidden(err,
llx.WithPermissions("ec2:DescribeInstances"))` adds no dependency. `plugin`
re-exports the constructors for authors who prefer one import.

The 143 existing classifiers keep their names and their per-provider knowledge.
What changes is what a call site does with a true answer: instead of `return
nil, nil`, it wraps. Five providers already have the right file to put the
mapping in (`gcp/resources/errors.go`, `azure/resources/shared.go`,
`databricks/resources/errors.go`, `ms365/resources/errors.go`,
`snowflake/resources/errors.go`); the rest grow one.

**Rehydration** is three sites, and missing any one of them silently drops the
kind back to a string:

- `providers/runtime.go:680` — the executor's own `GetData`.
- `providers-sdk/v1/plugin/runtime.go:164,184` — `CreateSharedResource` and
  `GetSharedData`.
- `providers/runtime.go:918-942` — `providerCallbacks.GetData`, the
  cross-provider path from [ADR 042](042-cross-provider-invocation.md), which
  must forward the detail rather than rebuild it.

`TValue.ToDataRes` is the matching site on the way out.

### 7. Rendering: a kind is not a stack trace

`cli/printer/mql.go` already proves the pattern by giving version skew
`print.Disabled` instead of `print.Error` (`:416`, `:509`). Extend that to the
kinds, and aggregate: a scan that hits 784 denials on one role should print one
line naming the kind, the scope and the permission, not 784. The grouping key is
`(kind, scope, scope_id, permissions)`, which is precisely why §4 carries them.

Errors also stop being anonymous in logs. Today a swallowed denial is a
`log.Debug` line in one of 784 shapes; with a kind it is one structured field.

### 8. Partial results: data and errors together

A list assembled from several partitions can succeed in some and be refused in
others. `aws.ec2.eips` queries every region; if one is denied, sixteen regions of
answers are true and one is missing. Neither half is disposable. Dropping the
data, reporting the list as an error, throws away what was read. Dropping the
error, returning the list as if complete, is §3's null in another shape: an
assertion over the list passes on data nobody collected.

**Today it is both, depending on the failure.** A region job that hits
`Is400AccessDeniedError` returns an empty slice and a `log.Warn`, so the denial
vanishes and the list looks complete (`providers/aws/resources/aws_ec2.go:191`).
Any other error in any region fails the whole list through
`poolOfJobs.HasErrors()` (`:160`), discarding every region that answered.

The carriers could hold both. `RawData`, `DataRes` and `Result` each have a
value and an error slot. Three places keep only one:

- `plugin.GetOrCompute` (`providers-sdk/v1/plugin/runtime.go:269-276`) marks
  any errored field null, and `TValue.ToDataRes` (`:200-207`) then sends the
  error with an empty value. The branch that would send both (`:213-215`) is
  unreachable from generated code.
- `providers/runtime.go:683-686` rebuilds a failed field as `RawData{Error: …}`
  and drops `data.Data`.
- Every consumer reads the error slot as "this failed", and ignores the value
  beside it. The executor stops a chain at the first errored binding
  (`llx/llx.go:885-902`), so `.where`, `.length` and `.all` all return the
  error. `IsTruthy`, `IsSuccess` and `Score` report invalid
  (`llx/rawdata.go:250-262`, `:448`). The printer prints only the error
  (`cli/printer/mql.go:424`, `:517`), JSON drops the value (`rawdata.go:62`),
  and cnspec scores it `ScoreType_Error` (`policy/executor/internal/
  nodes.go:503`).

So a value and an error in the existing slots already mean "failed",
everywhere. The error slot cannot be where a partial rides.

**A partial rides in its own field:**

```proto
// llx/llx.proto
// A part of a result that could not be read. The message is the upstream
// error, verbatim; the detail classifies it (§1-§4).
message CoverageGap {
  string error = 1;
  ErrorDetail detail = 2;
}

message Result {
  // … 1-4
  // The value in data is incomplete: these parts could not be read. Empty on
  // every complete result.
  repeated CoverageGap coverage_gaps = 5;
}

// providers-sdk/v1/plugin/plugin.proto
message DataRes {
  // … 1-4
  repeated mql.llx.CoverageGap coverage_gaps = 5;
}
```

A separate field is what makes this non-breaking, and why it needs no feature
flag. A consumer that does not read it (an older client, the server before it
learns the field, a recording made before it existed) sees the value exactly as
today and nothing else. Today's behavior is the fallback by construction, not by
care at every site.

**Provider side: one wrapper.** An accessor returns `res, llx.Partial(errs...)`.
`GetOrCompute` recognizes it: the field is set, not null, the data is kept, and
`ToDataRes` emits `coverage_gaps` instead of `error`. Generated code does not
change. `llx.Partial()` with no errors is nil, so a loop can return it
unconditionally. Each wrapped error is classified and names its partition:

```go
llx.Forbidden(err,
    llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, region),
    llx.WithPermissions("ec2:DescribeAddresses"))
```

The partition is what lets §7 print one line for a region that refused
eighty lists, rather than eighty.

**Consumer side: the result stands, the gaps ride along.** A partial does not
change what a query or a check evaluates to. It adds what could not be read. A
consumer that reads `coverage_gaps`:

- The executor carries a result's coverage gaps to everything computed from
  it. `eips.where(…)`, `eips.length` and `eips.all(…)` are partial when `eips`
  is. Several inputs union their coverage gaps, deduplicated on `(kind, scope,
  scope_id, permissions)`.
- A check scores on the data it has, exactly as today: a pass stays a pass,
  a failure stays a failure. The coverage gaps are attached to the score
  either way.
- A data query returns the value and its coverage gaps. The printer shows the
  value, then one dimmed line per `(kind, scope_id)` group. JSON carries the
  coverage gaps beside the value, never inside it, so the value's shape is
  unchanged for anything parsing it today.

What the attached errors buy is a measure of visibility. Aggregated over a
scan, they say how many results rest on incomplete data and which grants would
complete them, alongside the checks §3 turns into errors.

**The planned behavior change, through the v14 lifetime.** Partial results are
not behind the feature flag (§9) and have no version split: the field is
additive, and no score changes. What does change is the region loops. A
denied region that is dropped silently today becomes the same result with the
gap attached. A loop that fails the whole list
today, because one region was throttled or failed, becomes a valid result
with that region as a coverage gap: a pass or a failure on the data that was
read, where today it is an error.

That second change only holds up if the gap is visible where the result is
read. The rule, written and not enforced: providers convert their loops
together with the rest of this ADR, including surfacing coverage gaps in mql's
output and in cnspec's output. A loop converted before its gaps show up in both
turns a visible error into a result that looks complete.

The server is not part of the rule. It ignores `coverage_gaps` until it reads
them and keeps receiving every value and score, so nothing breaks while it
catches up. Until then a region that was throttled shows in the platform as the
pass or failure it evaluated to, without the gap beside it.

The SDK ships no region-loop helper. Loops differ per provider (regions,
projects, subscriptions, each with its own pool), so a provider that wants a
shared loop writes its own, on top of `llx.Partial`. What keeps partition, kind
and scope consistent across providers is `llx.Partial` and the `WithScope`
option, not a common loop.

### 9. The null-to-error change is opt-in through v14

§3 turns a refusal from a null into an error. That is the change that makes
scans that were quietly green go red, so it sits behind a feature flag,
`StructuredErrors`, and can be tried against real accounts throughout v14
before anyone has to take it. It becomes the default in v15. `RootedNamespace`
(ADR 031) is the precedent: a v15 behavior that is available early and is
opt-in during v14.

**The provider reads the flag.** The flag is all or nothing for a provider
process, so it is read from the features a Connect receives and held
process-wide; a call site asks `plugin.StructuredErrors()`. Each migrated call
site keeps its v13 branch behind it:

```go
if err != nil {
    if !plugin.StructuredErrors() && Is400AccessDeniedError(err) {
        return []any{}, nil // v13 behavior
    }
    return nil, classifyAwsError(err, "organizations:ListAccounts")
}
```

With the flag off the call site returns exactly what it returned in v13, and
every other error behaves as in v13. With the flag on it returns the classified
error. In v15 the `if !plugin.StructuredErrors()` branches are deleted.

**Not behind the flag:** the carrier and the SDK mapping (phases 1 and 2),
partial results and their coverage gaps (§8), rendering, and cnspec's coverage
attribution. With the flag off they just have fewer classified errors to
work with.

## cnspec

**Scoring is unchanged.** A check that ended in a classified failure is
`ScoreType_Error`, exactly as today, including `not applicable`; asset-vanished
keeps the `ScoreType_Unscored` it already gets (`policy/executor/internal/
nodes.go:549-557`). Remapping a kind onto `ScoreType_OutOfScope` or
`ScoreType_Skip` would change what compliance means, which is a separate decision
from being able to tell failures apart. The taxonomy does not need it to pay off.

**What the kind buys is attribution, and that is the point.** Today a scan that
could not read half of its subject reports the same shape of failure as a scan
that hit one broken API, and the operator has no way to ask why. With the kind on
the result, cnspec can answer it:

> 62 of 154 checks could not be assessed. 58 were blocked by missing permissions
> (12 permissions across ec2, iam and s3), 3 by APIs not enabled on this project,
> 1 by throttling.

That sentence is the deliverable. It turns "the scan is noisy" into a work item
with a list of grants attached, and it is what lets a user say *we are covering
40% of this policy and here is what we need to cover the rest*. The same
grouping answers it per fleet: 50 assets failing on one expired credential is one
line, not 50.

### The kind has to reach the score

Data queries are already covered: `StoreResultsReq.data` is a
`map<string, mql.llx.Result>`, so `Result.error_detail` (§5) ships upstream the
day phase 1 lands, with no cnspec change at all.

**Checks are not**, and checks are what a policy is made of. A check's outcome
travels as a `Score`, which carries a type and a `message` string, so the kind
dies at `policy/executor/internal/nodes.go:556` — two lines after the loop at
`:503-518` collected the typed errors. That is the same flattening as
`errors.New(res.Error)`, one layer up. Two fields fix it:

```proto
// cnspec policy/cnspec_policy.proto
message Score {
  // … 1-14 in use
  // Why this score could not be assessed. Empty on every score that ran.
  repeated mql.llx.ErrorDetail error_details = 15;
}

message ReportCollection {
  // …
  // Asset-level failures, structured. Sibling of the errors map above.
  map<string, mql.llx.ErrorDetail> error_details = 7;
}
```

**Repeated, not a single kind.** A check whose three datapoints failed
`forbidden`, `not applicable` and `unavailable` would otherwise have to pick one,
and every ranking we could invent is wrong for somebody's report. Repeated needs
no dominance rule and matches how the coverage sentence groups.

The cost is bounded and was checked rather than assumed. An empty repeated field
does not serialize, so every passing score costs zero. A realistic `forbidden`
detail — kind, scope, `scope_id`, one permission — is about 40 bytes, and details
dedupe within a score on `(kind, scope, scope_id, permissions)`, which `nodes.go`
already does for the message via `err.Deduplicate()`. A 300-check policy with 60
permission failures is 2.4 KB on an asset whose request also carries real query
values in `data`. Results are batched per asset (`collector.go:320`, `:345`), so
that is the whole payload, not a fleet-sized one. Interning the details into a
per-request table and referencing them by index would cut a 1,000-asset scan from
~2.4 MB to ~0.3 MB, changes no semantics, and is available if a measurement ever
asks for it — building it now would be optimizing 2.4 KB.

A check over a partial result (§8) fills the same field. Its score is the pass
or failure it evaluated to, and `error_details` carries the coverage gaps, so a
region that refused is counted in the coverage report without changing the
check's outcome.

`ReportCollection.error_details` is local-output only: asset errors do not travel
through `StoreResults`. It is what makes the fleet line one line, in the CLI and
in JSON.

### Two string matches this removes

- `policy/scan/reporter_aggregate.go:80` stops matching `"TOOMANYREQUESTS"`
  against rendered text and reads the kind. `AddScanError` groups asset errors by
  kind instead of keeping one opaque string per asset (`:78-104`).
- `nodes.go:506` stops matching the prefix `"could not find resource"` and reads
  `ERROR_KIND_ASSET_VANISHED`. The behavior it drives — `ScoreType_Unscored` — is
  unchanged; only the detection stops being textual.

The implementation is cnspec's. It is stated here because a taxonomy no consumer
reads is dead weight, and because coverage reporting is the reason to build the
taxonomy at all.

## What this does not change

- **Null semantics.** ADR 043 owns what happens when a null is dereferenced, and
  `?` is unaffected. This ADR only reduces how many nulls a provider invents.
- **`ERROR_KIND_NO_MATCH`.** Connect-only, unchanged.
- **Retry behavior.** Nothing at all. `retry_after_ms` is carried and no part
  of this ADR consumes it. Whether a target's 429 is retried, by whom and where,
  is separate work that this only supplies the framework for.
- **Score semantics.** Every kind scores as it does today — an error for the
  provider kinds, `Unscored` for asset-vanished. No kind moves a check out of the
  denominator that is not already out of it. A partial result (§8) does not
  change a score either; it only attaches the errors.
- **`.lr` schemas.** No resource, field, or annotation changes. A field that
  fails is the same field.
- **Existing recordings.** They carry no detail and replay as unclassified,
  which is the safe direction.

## Phases

The work runs in two tracks. **Building the machine** is core, SDK and cnspec
work, and it lands in order. **Migrating providers** is per provider and runs
on its own schedule: a migration step starts once the machine phases it needs
have landed, and no machine phase waits for a migration.

### Building the machine

1. **Vocabulary and carrier.** `llx.proto` enums and message, `plugin` aliases,
   `DataRes.error_detail`, `Result.error_detail`, `llx/errors.go`, rehydration at
   the three sites. Nothing is classified yet: every error is unclassified and
   behaves exactly as today. Verifiable on its own by round-tripping a kind
   through a mock provider.
2. **SDK classifiers.** The SDK's default mapping from HTTP status and gRPC
   status code to mql ErrorKind (§1).
3. **Partial results (§8).** `CoverageGap`, `Result.coverage_gaps`,
   `DataRes.coverage_gaps`, `llx.Partial`, the `GetOrCompute`, `ToDataRes` and
   `providers/runtime.go` changes, and executor propagation. It ends at
   `llx.Result`: attaching the gaps to scores is cnspec work, in phase 6. No
   region-loop helper (§8). Not behind the feature flag.
4. **The `StructuredErrors` feature flag (§9).** The flag, and the way a
   provider reads it.
5. **Rendering and aggregation.** CLI grouping, coverage gaps in mql's output,
   structured logs.
6. **cnspec coverage attribution.** `Score.error_details` and
   `ReportCollection.error_details`, kind-grouped reporting, attaching a
   result's coverage gaps to its score (§8), coverage gaps in cnspec's output,
   and the two string matches removed (`TOOMANYREQUESTS`,
   `could not find resource`).
7. **Permission fallback.** The `permissions.json` fallback for call sites that
   do not name their permission (§4).
8. **Asset-scoped short-circuit.** An `ASSET`-scoped failure, such as a 401 or
   an expired credential, means every remaining call on that asset fails the
   same way, so the scan can stop early and report once. Purely an
   optimization: the results are identical either way, which is why it lands
   last rather than competing with the rest.

### Migrating providers

Each step names the machine phases it needs.

9. **aws, azure, gcp: single calls.** Needs 2 and 4. Each cloud's mapping
   file, and every single-call site returns the classified error and names
   its permission, service by service. A refusal inside a region, project or
   subscription loop is not part of this step: it is a partial result. In aws
   that is about 340 of the 782 `Is400AccessDeniedError` sites, the ones
   inside a per-region job; nearly all gcp and azure sites are single calls
   and belong here.
10. **aws, azure, gcp: loops.** Needs 3, 5 and 6. Region, project and
    subscription loops convert to `llx.Partial`, both the
    silent ones and the ones that fail a whole list today, and so do per-item
    refusals while building a list (one item's tags or details). The gaps must
    already show in mql and cnspec (§8); the server follows on its own
    schedule.
11. **The long tail.** The remaining providers, plus a lint that flags an error
    swallowed into `nil, nil` right after a classifier predicate, the shape that
    produced the current state.
12. **The null audit.** §3 permits an absence to stay a null, and 4,124
    `StateIsNull` sites currently claim to be absences. Which of them are genuine
    and which are swallowed refusals is a per-site question that has to be asked
    of every provider, and it is the work that actually finishes what this ADR
    starts. Named as its own step because it is large, mechanical, and easy to
    declare done while most of it is untouched.

Phases 1 and 2 are independently useful: a kind that only reaches the CLI is
already better than a string, and step 9 without phase 6 still makes `mql shell`
honest for anyone who turns the flag on. Phase 1 is the only one that has to
make the v14 rc window.

## Implementation status

**Phase 1 landed.** Nothing is classified yet: every provider error is
unclassified and behaves exactly as before, which is what makes the carrier
verifiable on its own.

- **Wire.** `ErrorKind`, `ErrorScope` and `ErrorDetail` in `llx/llx.proto`;
  `Result.error_detail` and `DataRes.error_detail`. `plugin` keeps the old
  spellings as Go aliases and re-exports the constructors, so ADR 045's code
  compiles untouched and a provider needs one import.
- **Type.** `llx/errors.go`: `*llx.Error`, one constructor per kind, the
  `WithScope` / `WithPermissions` / `WithRetryAfter` options, `KindOf`,
  `ErrorDetailOf` and `ErrorFromDetail`.
- **Rehydration.** Four sites, not three. `providers/runtime.go:680` and
  `plugin/runtime.go:164,184` were in the plan; `llx.Result.RawData()`
  (`data_conversions.go`) is the fourth, and it is the one that carries a kind
  back out of a recording and out of upstream storage. `providerCallbacks.GetData`
  forwards the detail for the ADR 042 path.
- **Asset vanished.** `mqlc/mqlc.go:1446` now returns `llx.AssetVanished(...)`.
  The message is unchanged on purpose, so cnspec's existing prefix match keeps
  working until it reads the kind instead.

Two notes from phase 1:

- The sentinel for `ERROR_KIND_UNAVAILABLE` is `llx.ErrTargetUnavailable`. The
  version-skew sentinel in `llx/skew.go` is `llx.ErrVersionSkew` (message still
  `"unavailable"`): the two absences are genuinely different.
- Compatibility is confirmed in both directions by construction and by running a
  client built from this tree against a provider binary built before the change:
  an old provider sends no detail and reads as unclassified.

**Phase 2 landed** (#11011). The SDK's default mapping is in
`providers-sdk/v1/plugin/classify.go`.

**Phase 3 landed.** Partial results reach `llx.Result`; nothing produces one
yet, since loops convert in step 10.

- **Wire.** `CoverageGap`, `Result.coverage_gaps` and `DataRes.coverage_gaps`.
- **In memory.** `RawData.CoverageGaps` and `TValue.CoverageGaps`, both
  `[]*llx.Error`. A partial field keeps `Error` nil on the `TValue` too, so
  provider code that reads a sibling field and checks `Error` keeps the data.
  An unclassified gap keeps its partition on the wire, where `ErrorDetailOf`
  would drop it.
- **Provider side.** `llx.Partial` and `llx.CoverageGapsOf`; `GetOrCompute`
  unwraps a Partial, so a wrapped one still counts.
- **Runtime.** `llx.Runtime.WatchAndUpdate` did not change: its callback has
  no slot for gaps, so `providers.Runtime` hands a partial field over as an
  `llx.Partial` in the error argument, and the executor unpacks it.
- **Executor.** Gaps are never written onto computed values, because values
  are shared through the step cache and the runtime's field cache. When a
  result is delivered, the executor collects the gaps of everything it was
  computed from: the chunk's own value, its binding, its arguments, and what
  its block runs reported. `where`, `length`, `all`, `{ … }` and comparisons on
  them need no change.

**Phase 4 landed.** `StructuredErrors` is feature 24 in `features.yaml`,
status `new`, so it is off unless a client turns it on (`--features
StructuredErrors`, `MONDOO_FEATURES`, or the server).

- **Reading it.** `plugin.ReadFeatures` stores the flag in a process-wide
  `atomic.Bool` (`providers-sdk/v1/plugin/features.go`), and
  `plugin.StructuredErrors()` reads it. A provider has no code of its own for
  this: the SDK's gRPC server reads the features on every `Connect` and
  `MockConnect` before handing the request to the provider. A builtin or
  in-process provider never passes through that server, so
  `providers.Runtime` reads them in `Connect`, `UseBuiltinProvider` and
  `UseInProcessProvider`.
- **A Connect without features leaves the flag alone.** Not every Connect
  forwards the scan's features: delayed discovery connects with the asset
  alone (`discovery/delayed.go`). Letting such a request turn the flag off
  would switch a provider back to v13 behavior halfway through a scan. A
  request that carries features always decides, so a long-running process
  (`cnspec serve`) picks up the flag being turned off again, which reading it
  only once would not.

**Phase 5 landed.** mql's text and JSON output read the kind and the coverage
gaps. Nothing produces a classified error by default yet, so with the flag off
the output is what it was.

- **A failed field** leads with its kind, its partition and its permissions,
  then the target's message: `access denied (ec2:DescribeTags): User … is not
  authorized`. Not applicable is dimmed, like version skew; every other kind
  stays an error. Unclassified errors print as before
  (`cli/printer/errors.go`).
- **Grouping.** Below a result, one line per `(kind, scope, scope_id,
  permissions)` group that occurs more than once, with its count: `access
  denied x784 (ec2:DescribeTags)`. Each field still shows its own error; a
  group seen once is already fully written where it is.
- **Coverage gaps in text** follow the value, one dimmed line per
  `(kind, scope_id)` group, with the permissions of the group merged:
  `coverage gap: access denied in eu-west-1 (ec2:DescribeAddresses)`.
  Unclassified gaps print their message and sort last.
- **Coverage gaps in JSON** sit beside the values under one reserved key,
  `_coverageGaps`, mapping each query label to its gaps (`kind`, `scope`,
  `scopeId`, `permissions`, `retryAfterMs`, `error`). A complete result writes
  no key, so the output of every run today is byte-for-byte the same. Kind and
  scope use `ErrorKind.Name()` / `ErrorScope.Name()`, the proto name without
  its prefix, lowercased (`forbidden`, `too_many_requests`, `partition`).
- **Structured logs.** `*llx.Error` implements `zerolog.LogObjectMarshaler`
  (`kind`, `scope`, `scope_id`, `permissions`, `retry_after`; the message
  stays with `Err`). `providers.Runtime` writes one debug line per classified
  field error and one per coverage gap, with provider, resource, id and field,
  so no provider needs its own logging for it.

**Step 9 for aws is open** (#11012). It returns classified errors
unconditionally; it gets the v13 branches of §9 and can merge now that phase 4
has landed.

## Consequences

**Good:**

- An under-permissioned scan stops looking like a clean one. This is the reason
  the ADR exists, and it is the same win ADR 043 named as its largest.
- "Not allowed to look" and "nothing is configured" become different answers,
  everywhere, rather than in the two providers whose authors thought about it.
- An access error can name the permission to grant, which turns a report into a
  remediation.
- Aggregation becomes possible: one line per (kind, scope, permission) instead of
  hundreds of log-and-continue lines.
- **Coverage becomes reportable.** "We assessed 40% of this policy, and here are
  the grants that would cover the rest" is a sentence nobody can write today, at
  any layer, because the reason a check failed is not recorded anywhere a
  reporter can read.
- The 143 classifiers stop being 143 private vocabularies and become mappings
  onto one.

**Costs and risks:**

- **~1,000 call sites change behavior.** Scans that were quietly green go red.
  That is correct and it will be reported as a regression, which is why it is
  opt-in through v14 (§9) and the default in v15. The v15 release notes have to
  say so.
- **A wrong kind is worse than none.** Everything downstream believes it. The
  narrowest-true rule (§2) and the unclassified default are the mitigation, and
  the review burden lands on the provider mapping files.
- **`not applicable` will be over-used**, exactly as gcp's `isInapplicable`
  comment warns, because it is the widest of the nine and the easiest to reach
  for when a call site is hard to classify. It no longer changes a score, so the
  damage is a coverage report that blames the target for a gap we caused. It is
  the kind to watch in review.
- **A proto message changes packages.** Moving `ErrorDetail` and `ErrorKind`
  down to `llx` is a compatibility event, bounded by the v14 rc window and
  covered by `IsNoMatchError`'s text arm, but it is not free — and the window
  closes at GA.
- **The kind has to be plumbed through six hops** — provider, `DataRes`,
  executor, `RawData`, `Result` or `Score`, upstream — and dropping it at any one
  of them fails silently, degrading to today's behavior. That is a testable property and should
  have a round-trip test per layer rather than trust.

## Alternatives considered

- **gRPC status codes as the vocabulary.** Free on the wire and already
  understood. Rejected: `codes.Unavailable` on the data path already means the
  plugin crashed (`providers/runtime.go:749`), and most field errors are not
  statuses at all — they ride in `DataRes.error`, where there is no code to read.
- **A null that carries the kind.** Keeps today's degrade behavior and labels it,
  so nothing goes red on upgrade. Rejected: it reintroduces the question ADR 043
  spent its length answering (what does `&&` do with a labeled null), and a
  labeled null still passes a vacuous assertion. The label has to make the value
  not exist, which is what an error does.
- **Keep `ErrorKind` in `plugin.proto` and add a second carrier for `llx`.**
  Avoids the type-URL move. Rejected: it is the "second message" ADR 045's
  comment was written to prevent, and the two would drift within a release.
- **One Go error type per kind.** `errors.As(err, &ForbiddenError{})` reads well.
  Rejected: nine types, nine constructors, and every consumer needs a type switch
  where a single `KindOf` would do — and the wire needs an enum regardless, so
  the types would be a second representation of the same fact.
- **Classify centrally in the SDK from HTTP status.** One implementation instead
  of 143. Rejected: it is wrong exactly where it matters, because the body
  overrules the status (§2) and only the provider knows its own API's dialect.
  The SDK supplies the helpers; the provider supplies the judgment.
- **Sentinel strings, matched downstream.** The status quo, and cnspec's
  `TOOMANYREQUESTS` match is what it looks like at scale. Rejected for the reason
  ADR 045 gave: message text is not a contract, and wrapping breaks it.
- **Do access errors only, defer the rest.** The narrowest change, and it is what
  was originally asked for. Rejected: the next author hits not-found the week
  after and invents a second mechanism. The kinds are cheap once the carrier
  exists; the carrier is the work.
