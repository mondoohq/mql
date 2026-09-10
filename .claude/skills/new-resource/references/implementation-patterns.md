# Implementation patterns for MQL resources

The Go shapes behind the rules in the root `CLAUDE.md` §2 Step 3. Each pattern says when it applies and shows the code; the rules themselves (when `StateIsNull` is mandatory, why an `init` must not fall through) stay in `CLAUDE.md`.

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

Loop on the marker or token until the API stops returning one:

```go
var marker *string
for {
    result, err := svc.DescribeDBParameterGroups(ctx, &rds.DescribeDBParameterGroupsInput{Marker: marker})
    if err != nil {
        return nil, err
    }
    for _, item := range result.Items {
        // process each item
    }
    if result.Marker == nil {
        break
    }
    marker = result.Marker
}
```

Test the walk with `httptest`, including a server that ignores its cursor, so a stuck page cannot multiply records up to the cap.
