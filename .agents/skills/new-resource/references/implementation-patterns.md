# Implementation patterns for MQL resources

The Go shapes behind the rules in the root `AGENTS.md` §2 Step 3. Each pattern says when it applies and shows the code; the rules themselves (when `StateIsNull` is mandatory, why an `init` must not fall through) stay in `AGENTS.md`.

## Pattern A: immediate mapping with `CreateResource`

For listing APIs where the data arrives with the list call. Call the API, loop, map each item, and set `__id` (ARN, UUID, or composite key) so the runtime can cache it:

```go
res, err := CreateResource(runtime, "aws.ec2.instance", map[string]*llx.RawData{
    "__id":  llx.StringData(arn),
    "arn":   llx.StringData(arn),
    "state": llx.StringData(string(instance.State.Name)),
})
```

`CreateResource` skips the resource's `init`, so anything whose identity is computed in `init` must go through `NewResource` instead (Pattern B).

## Pattern B: lazy loading with `NewResource` + `init`

For references (`aws.ec2.instance("i-123")`) and expensive calls. Return a reference and let the `init` fetch on demand:

```go
mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
    map[string]*llx.RawData{"id": llx.StringDataPtr(a.cacheVpcId)})
```

The `init` (`initAwsVpc`) checks its args, fetches, and populates the resource. Two things to get right:

- **Read the target's `init` first.** It defines which arg keys it accepts (`arn`, `id`, or both), and they differ per resource. Passing the wrong key makes `NewResource` return an error, which most accessors log-and-continue past, so the symptom is an empty list rather than a failure.
- **Return a not-found error when the lookup misses.** `return args, nil, nil` after a miss creates a blank resource with unset fields:

```go
// WRONG: no match found; runtime creates a blank resource with unset fields
for _, r := range apis.Data {
    if match(r) { return args, r, nil }
}
return args, nil, nil

// CORRECT
return nil, nil, fmt.Errorf("aws.apigatewayv2.api with arn %q not found", wantArn)
```

`return args, nil, nil` is only correct for the "args already complete" fast path at the top (`if len(args) > 2`). Intermediate failures (an ARN that fails to parse) return the error too.

## Pattern C: cross-references through a cached list

For linking resources (GCP address → network) without N+1 API calls. `NewResource` runs the target's `init` **before** the runtime cache is consulted, so resolving a parent per child turns one list into N calls. When the parent collection is already fetched, scan it in memory:

```go
// N+1: init runs per endpoint, before the cache is checked
NewResource(runtime, "neon.branch", map[string]*llx.RawData{"id": llx.StringData(branchID)})

// one call: the project's branch list is fetched once and reused
branchByID(runtime, projectID, branchID)   // walks project.GetBranches()
```

A worked GCP example (`initGcpProjectComputeServiceNetwork` filtering `computeSvc.GetNetworks()`) is in `DEVELOPMENT.md` → Referencing MQL resources.

## Pattern D: `Internal` structs for cached values

The generator embeds any `mql<ResourceName>Internal` struct into the generated resource struct. Use it to carry values from the creation context that a computed method needs later:

```go
type mqlAwsDocumentdbSnapshotInternal struct {
    cacheVpcId    *string
    cacheKmsKeyId *string
}

// in the creator, after CreateResource:
mqlSnapshot := resource.(*mqlAwsDocumentdbSnapshot)
mqlSnapshot.cacheVpcId = snapshot.VpcId

// the typed reference, resolved on demand:
func (a *mqlAwsDocumentdbSnapshot) vpc() (*mqlAwsVpc, error) {
    if a.cacheVpcId == nil || *a.cacheVpcId == "" {
        a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
        map[string]*llx.RawData{"id": llx.StringDataPtr(a.cacheVpcId)})
    if err != nil {
        return nil, err
    }
    return mqlVpc.(*mqlAwsVpc), nil
}
```

Run `./mqlr generate` a **second time** after adding an `Internal` struct; the first pass does not see it. Same on removal, or the stale embed fails the build with `undefined: mql<Name>Internal`. Name cache fields so they cannot collide with a generated accessor (`cachePath`, not `path`).

**`securityGroupIdHandler`** (`providers/aws/resources/aws.go`) is a reusable embedded struct that turns a list of security group IDs into typed `[]aws.ec2.securitygroup` references:

```go
type mqlAwsRdsProxyInternal struct {
    securityGroupIdHandler  // provides securityGroups() automatically
    region    string
    accountID string
}
```

## Null singular accessors

Every `return nil, nil` from a method returning a single resource pointer sets the state first, or the runtime does not know the field resolved:

```go
func (a *mqlAwsRoute53Record) healthCheck() (*mqlAwsRoute53HealthCheck, error) {
    if healthCheckId == "" {
        a.HealthCheck.State = plugin.StateIsSet | plugin.StateIsNull
        return nil, nil
    }
    ...
}
```

Applies to empty IDs, access-denied fallbacks, nil API responses, and `!a.Field.IsSet()` branches. Slice, map and scalar returns are unaffected.

## Lazy fields that need a detail API

When the list API returns a summary (`ListDataCatalogs` without `description` or `parameters`), do not set the missing fields to empty values. Declare them computed in the `.lr` (`description() string`) and fetch the detail call once, shared across fields:

```go
type mqlAwsResourceInternal struct {
    fetched bool
    attrs   map[string]string
    lock    sync.Mutex
}

func (a *mqlAwsResource) fetchAttributes() (map[string]string, error) {
    if a.fetched { return a.attrs, nil }
    a.lock.Lock()
    defer a.lock.Unlock()
    if a.fetched { return a.attrs, nil }
    // ... call the detail API ...
    a.fetched = true
    a.attrs = resp.Attributes
    return a.attrs, nil
}
```

## Running commands: the `command` resource, never `os/exec`

```go
// WRONG
cmd := exec.CommandContext(ctx, "lsblk", "--json", "--fs")
output, err := cmd.Output()

// CORRECT
o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
    "command": llx.StringData("lsblk --json --fs"),
})
if err != nil {
    return nil, err
}
cmd := o.(*mqlCommand)
if exit := cmd.GetExitcode(); exit.Data != 0 {
    return nil, errors.New("command failed: " + cmd.Stderr.Data)
}
output := cmd.Stdout.Data
```

The `command` resource carries execution context, auth, and connection handling across local, SSH, and container connections. `providers/os/resources/lsblk.go` is a full example.

## Discovery: resolving the asset and applying filters

Resolve a discovered asset by ARN, and only inject a non-empty value, since an empty `args["arn"]` defeats the init's later `args["arn"] == nil` guard:

```go
if assetArn := getAssetIdentifier(runtime); assetArn != "" {
    args["arn"] = llx.StringData(assetArn)
}
```

Filters go in the lister, gated so the tag lookup stays lazy when no tag filter is set:

```go
if conn.Filters.General.HasTags() {
    tags := /* fetch tags for this resource */
    if conn.Filters.General.IsFilteredOutByTags(tags) {
        continue
    }
}
```

- Tags already in hand, or one call: copy `providers/aws/resources/aws_s3.go`.
- No batch tags endpoint: use `fetchTagsConcurrently` in `aws.go` (bounded concurrency, per-item failures tolerated). Seed fetched tags onto the resource so discovery does not re-fetch, but only for a tag set that was actually read; use the comma-ok form on the result map so a failed tag call is not published as "no tags".

## Pagination

Use the SDK paginator when the client has one. AWS SDK v2 generates `New<Operation>Paginator` for most list and describe calls; it follows the token for you and stops when the API does:

```go
paginator := rds.NewDescribeDBParameterGroupsPaginator(svc, &rds.DescribeDBParameterGroupsInput{})
for paginator.HasMorePages() {
    page, err := paginator.NextPage(ctx)
    if err != nil {
        return nil, err
    }
    for _, pg := range page.DBParameterGroups {
        // map each item
    }
}
```

`providers/aws/resources/aws_rds.go: parameterGroups`. Check the SDK package for a `New*Paginator` before writing a loop by hand. Only when there is none (DAX `DescribeClusters`), loop on the marker or token until the API stops returning one:

```go
var nextToken *string
for {
    resp, err := svc.DescribeClusters(ctx, &dax.DescribeClustersInput{NextToken: nextToken})
    if err != nil {
        return nil, err
    }
    // map resp.Clusters
    if resp.NextToken == nil {
        break
    }
    nextToken = resp.NextToken
}
```

`providers/aws/resources/aws_dax.go: getDaxClusters`. Test a hand-written walk with `httptest`, including a server that ignores its cursor, so a stuck page cannot multiply records up to the cap.

## AWS: multi-region fan-out

A regional service is listed once per region in scope and the results concatenated. New listers use `perRegion` (`providers/aws/resources/aws_regional.go`), which runs the closure per region from `conn.Regions()` (region filters already applied) at bounded concurrency:

```go
func (a *mqlAwsRds) parameterGroups() ([]any, error) {
    conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
    return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
        svc := conn.Rds(region)
        res := []any{}
        // paginate, CreateResource with "region": llx.StringData(region)
        return res, nil
    })
}
```

- Return the SDK error from the closure as is. `perRegion` classifies it (`classifyError` in `aws_disposition.go`): a service absent from the region contributes nothing, a denied region is recorded as a coverage gap, and one failed region no longer discards the others. No `Is400AccessDeniedError` branch inside the closure.
- The second argument is the AWS service id used for that classification (`"rds"`, `"ecr"`, `"macie2"`).
- Carry `region` on every resource and into `__id` when the natural id is not an ARN; the same name exists in every region.

Most existing listers still use the older builder/collector pair: a `get<Thing>` method returning one `jobpool.NewJob` per region, run by `jobpool.CreatePool(jobs, 5)` (`providers/aws/resources/aws_dax.go: daxClusters`, `getDaxClusters`). Its closures handle refusals themselves under the per-region exception in AGENTS.md §2 Step 3 (log and skip the partition). When editing one, keep its shape or migrate the whole lister to `perRegion`; don't mix the two in one function.

## AWS: EC2 tag filters, server side and client side

EC2 `Describe*` inputs take `Filters`, so include-tag filters can be pushed to the API and AWS returns only the matches. Exclude tags have no server-side form and are always applied to each item:

```go
params := &ec2.DescribeSecurityGroupsInput{
    Filters: conn.Filters.General.ToServerSideEc2Filters(), // include tags only
}
paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, params)
for paginator.HasMorePages() {
    page, err := paginator.NextPage(ctx)
    ...
    for _, group := range page.SecurityGroups {
        if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(group.Tags)) {
            continue
        }
        ...
    }
}
```

`providers/aws/resources/aws_ec2.go: getSecurityGroups`; definitions in `providers/aws/connection/filters.go`.

| API | include tags | exclude tags |
|---|---|---|
| EC2 `Describe*` with a `Filters` input | `ToServerSideEc2Filters()` | `MatchesExcludeTags()` per item |
| anything else | `IsFilteredOutByTags()` per item, gated on `HasTags()` (Discovery section above) | covered by `IsFilteredOutByTags()` |

## Azure: resource IDs

Child listers and detail calls need the subscription, resource group and parent names that are already in the parent's ARM ID. Parse it, don't split strings:

```go
resourceID, err := ParseResourceID(a.Id.Data)
if err != nil {
    return nil, err
}
site, err := resourceID.Component("sites")
if err != nil {
    return nil, err
}
// resourceID.SubscriptionID, resourceID.ResourceGroup
```

`providers/azure/resources/resourceid.go`. `Component` is case-insensitive because ARM IDs are; pass the segment name as it appears in the ID (`sites`, `virtualMachines`, `managedEnvironments`).

## Azure: ARM pagers

ARM clients return a pager from `NewList*Pager`. Loop on `More()`, and propagate the `NextPage` error:

```go
client, err := web.NewWebAppsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
    ClientOptions: conn.ClientOptions(),
})
if err != nil {
    return nil, err
}
pager := client.NewListSlotsPager(resourceID.ResourceGroup, site, &web.WebAppsClientListSlotsOptions{})
res := []any{}
for pager.More() {
    page, err := pager.NextPage(ctx)
    if err != nil {
        return nil, err
    }
    for _, entry := range page.Value {
        // map entry
    }
}
```

`providers/azure/resources/web.go: slots`. Build the client with `conn.ClientOptions()` so the connection's request pipeline (the API trace policy) applies to it.

## Azure: diagnostic settings

A resource that supports Azure Monitor diagnostic settings exposes them by passing its own ARM ID to the shared helper, not by building a new client:

```go
func (a *mqlAzureSubscriptionKeyVaultServiceVault) diagnosticSettings() ([]any, error) {
    conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
    return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}
```

Declared in the `.lr` as `diagnosticSettings() []azure.subscription.monitorService.diagnosticsetting`. `getDiagnosticSettings` is in `providers/azure/resources/monitor.go`; `providers/azure/resources/keyvault.go` and `web.go` call it.
