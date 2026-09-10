# CLAUDE.md for mql

Rules for working in mql. Procedures live in the skills (§1.5), reference material in [DEVELOPMENT.md](DEVELOPMENT.md), subtree rules in scoped files like `llx/CLAUDE.md`.

## 1. Project

**mql** (formerly cnquery) queries 1,300+ resources across AWS/Azure/GCP, Kubernetes, containers, OS internals and APIs using MQL (Mondoo Query Language). It defines resources, implements MQL, gathers data.

**cnspec** sits on top: policy assertions, vuln checks, scanning, SBOM.

Resource work (fields, new assets) happens in mql only.

## 1.5 Skills

Skills carry the procedures and the traps. This file carries the rules. Invoke the matching skill; don't rebuild its steps.

| skill | use when |
|---|---|
| `new-resource` | adding/changing a resource or field in an existing provider, or a resource returns null/empty and the schema is the suspect. `references/implementation-patterns.md` has the Go patterns (`CreateResource`/`NewResource`, `Internal` structs, lazy loading, discovery filters). |
| `new-provider` | provider doesn't exist yet (hands off to `new-resource`) |
| `provider-verification` | proving a PR or commit range against provisioned cloud infra |
| `provider-bug-review` | auditing a shipped provider by reading code: nil handling, pagination, `__id` collisions |
| `provider-api-call-dedup` | scan is slow, times out, or trips rate limits |
| `provider-release` | bumping provider versions, preparing a release |
| `update-provider-deps` | upgrading vendored SDKs, finding what the new version unlocks |
| `staged-discovery` | adding staged/phased discovery |
| `check-querypack-deprecations` | checking `content/` query packs for deprecated resources or fields |

## 2. Resource development

`.lr` schema (`providers/aws/resources/aws.lr`) → `mqlr` codegen → Go implementation. **Procedure: the `new-resource` skill.** Rules it assumes:

### Step 1: `.lr` doc-comments

Every top-level resource (anything queried directly, including singular records like `aws.ec2.instance` and roots like `aws`) needs, directly above `resource {`:

1. **Title.** One-line noun phrase. No leading article, no trailing verbs ("static analysis"). Max 150 runes (`lrcore.MaxTitleLength`, enforced). Can't start with "deprecated" (enforced), use `@maturity("deprecated")`.
2. **One empty `//` line.**
3. **Description.** What's queryable: fields, sub-resources, derived predicates, the audits enabled. Start with the noun, not a verb (never `Examine`/`Iterate`/`Use`). If the resource is keyed by a field, name it as the selection key with an example. Can't start with "Deprecated." or "Deprecated:" (enforced); only `Deprecated in favor of ...` and `Deprecated, please use ...` pass.

```
// Section of the Arista EOS running-config
//
// A single named section of the running-config. The `name` field selects the
// section as it appears in the running-config, for example
// `arista.eos.runningConfig.section(name: "interface Ethernet1")`.
arista.eos.runningConfig.section { ... }
```

**Shape, enforced for resources and fields:** either one line (title only), or title + blank `//` + description. Two contiguous comment lines with no blank `//` fail at parse time (`lrcore/lr.go: validateDocCommentStructure`). The parser is positional: line 1 is `title`, the rest is `desc`. A title over 150 runes means part of it belongs in the description.

```
// Budget type
//
// One of COST, USAGE, RI_UTILIZATION, RI_COVERAGE, SAVINGS_PLANS_UTILIZATION, or SAVINGS_PLANS_COVERAGE.
budgetType string
```

`.lr` prose rules:

- No em dashes. Period, comma, parens or colon.
- Bare field names (`serviceAccount`), never `serviceAccount()`.
- No parent-navigation hints ("read from the parent device as ...").
- No jargon ("Singleton"), no mechanism ("typed reference", "lazy-loaded", "fetched on-demand", "phase 1/phase 2"), no cross-cloud analogies ("the Azure equivalent of AWS Macie"). Per-discriminator dict shape lists are schema, keep those.
- Cross-reference a sibling only when useful (raw view → typed view).
- Private resources and row types (`*.entry`): one line is enough.
- Check SDK/API docs before listing enum values; the set may not be closed.

### Step 1.5: Typed-reference gate (before codegen)

A raw ID/URL string where an accessor belonged is the most expensive fix later: `projectId string` → `project() openstack.project` is breaking. For every new field: does the value identify another modeled resource? Then it's an accessor.

| You wrote (stop) | Ship instead |
|---|---|
| `projectId string` / `userId string` | `project() <provider>.project` / `user() <provider>.user` |
| `vpcId string` / `subnetIds []string` | `vpc() aws.vpc` / `subnets() []…subnet` |
| `roleArn string` | `iamRole() aws.iam.role` (not `role`, ambiguous) |
| `networkUrl string` (GCP self-link) | `network() …network` (same for `subnetworkUrl`, `routerUrl`, `sslPolicyUrl`, `securityPolicyUrl`, `interconnectUrl`, `vpnGatewayUrl`) |

- Raw string only for the resource's own `id`, or an opaque scalar naming no modeled resource (hash, discriminator, free-form `name`). Unsure → accessor: stash the raw value in a `cache*` field on `Internal`, resolve with `NewResource`.
- Name accessors with a domain word, **never a `Ref`/`Refs`/`Typed` suffix**. If a raw field holds the clean name, pick a word saying what the reference is (`managedSecurityGroup()` beside a `loadBalancerSecurityGroup` dict). Shipped `*Ref` accessors stay for compatibility, they aren't precedent.
- Deprecate the raw `*Id`/`*Arn` field once an accessor carries the same value (`@maturity("deprecated")`). Keep it only if it's a token list the accessor can't round-trip.
- Model both directions when both are useful; the reverse edge often carries the audit (`deployKey.sites` finds a key no site uses).
- Resolve references through a cached list, not per-item lookups: `NewResource` runs the target's `init` before the cache, so a parent per child turns one list call into N. Scan the already-fetched parent collection.

No linter catches this.

### Step 2: Codegen

Regenerate after every `.lr` change:

```bash
make providers/mqlr   # once, if ./mqlr is missing
./mqlr generate providers/aws/resources/aws.lr --dist providers/aws/resources
make mql/generate     # everything (slow)
```

- Two naming traps look like Go bugs. A resource named `<parent>.<field>` queried by its dotted path is an empty husk (`cannot convert primitive with NO type information`). A list field whose path equals its element resource type compiles as a single resource (`is not a list type`; use a plural field over a singular element resource). `new-resource` indexes both by symptom.
- A new `Internal` struct needs a second `mqlr generate`; after removing one the stale embed lingers until you regenerate (`undefined: mql<Name>Internal`).
- Never hand-edit generated `.lr.go` files.

**Schema-change report (ADR 040 part 5).** Codegen diffs the committed `*.resources.json` and logs each delta additive or breaking (type changed, resource/field/alias removed, became private or mandatory, list type changed, init signature moved). `WARN breaking schema change` isn't "fix your code", it means choose: deprecate-and-add instead of mutating (§5), or a migration lens once phase 2 lands. Say which in the PR. `--fail-on-breaking` gates it (off by default). Fires once, since generation writes the new schema and a second run compares new against new. Git holds the baseline: if you missed the warning, revert the generated files and regenerate.

### Step 3: Implementation

Patterns and samples: `.claude/skills/new-resource/references/implementation-patterns.md`. Rules:

- `CreateResource` for listing APIs (set `__id`); `NewResource` for references resolved on demand via `init`. Only `NewResource` runs `init`, so an `__id` computed there stays empty under `CreateResource` and parameterized resources collide in the cache.
- Read the target's `init` before writing an accessor. Arg keys aren't uniform (`initAwsEc2Instance` takes `arn` only, `initAwsVpc` takes `arn` or `id`). Wrong key errors, and most accessors log-and-continue, so it surfaces as a silently empty list. Verify against real data.
- A singular resource accessor returning `nil, nil` must first set `a.Field.State = plugin.StateIsSet | plugin.StateIsNull`, or the runtime doesn't know the field resolved and may panic or re-fetch. Every path counts: empty ID, access denied, nil response, unset optional. Slices, maps, scalars unaffected.
- Never let a singular resource's `init` fall through to `return args, nil, nil` on a failed lookup. That builds a blank resource with unset fields, surfacing as `llx: encountered a primitive with no type information, coercing to null` with no attribution. Return a not-found error (`fmt.Errorf("aws.apigatewayv2.api with arn %q not found", wantArn)`). `return args, nil, nil` is only the args-already-complete fast path (`if len(args) > 2`).
- Never hardcode empty/default values for fields the list API doesn't return. Declare them computed (`description() string`), fetch the detail API on demand, cache on `Internal` (double-check locking; one fetch can feed several fields).
- Never use `os/exec`. Go through the `command` resource so execution works over local, SSH and container connections (`providers/os/resources/lsblk.go`).
- Resolve discovered assets by ARN, never asset name (that's a display name). Inject `getAssetIdentifier(runtime)` only when non-empty, since an empty `args["arn"]` defeats the init's nil guard. Exception: name-driven APIs like IAM `GetUser`, where discovery sets the asset name to the resource name; use `getAssetName(runtime)`.
- Always paginate when the API supports it; loop on the marker/token until nil.
- `convert.SliceStrPtrToStr` and `convert.SliceStrPtrToInterface` panic on nil elements. Write a nil-safe loop if the SDK slice can hold nil pointers.
- `Is400AccessDeniedError(err)` for permission problems (return a `nil` result, not an error). Real errors for temporary failures (rate limits, network). Log and continue on region/permission problems for one resource rather than failing the query.

### Step 3.5: Discovery-filter gate

A resource that becomes a discovery target must have its **lister** consult `conn.Filters`. The `case Discovery<Thing>:` branch in `discovery.go` and the filters are two separate edits, and the second gets forgotten: the service then accepts `--filters tag:...` and silently ignores it. Filter in `get<Thing>`, never in `discovery.go`, so MQL queries and discovery agree.

- Gate the tag lookup on `conn.Filters.General.HasTags()` to keep it lazy; skip on `IsFilteredOutByTags(tags)`.
- No batch tags endpoint → `fetchTagsConcurrently` in `aws.go`. Seed fetched tags onto the resource only for a tag set you actually read, comma-ok on the result map.
- Region filters need nothing (`conn.Regions()` applies them). Use service-specific filter structs where they exist (`conn.Filters.Ecr`, `conn.Filters.S3`).

The bug is an absence, so grep for it:

```bash
grep -rL "conn\.Filters" providers/<provider>/resources/*.go | grep -v _test
grep -n "case Discovery" providers/<provider>/resources/discovery.go
```

### Step 3.6: Pure-Go unit tests

Every PR ships unit tests for the pure Go logic it adds: anything that computes, parses or decodes, where a bug compiles and returns a confident wrong answer.

- struct-tag decoding of every API record (a mistyped tag yields a zero value, so `blockPublicConnections` reads `false` on a project that blocks them)
- optional values (absent pointer reads safely, absent timestamp is null, not year 1)
- derived predicates, including empty and absent cases
- pagination walks and their stuck-cursor guards (`httptest`)
- error classifiers (`IsForbidden` must not match a transport error)
- parsers and helpers

Skip functions whose whole body is one SDK call plus a `CreateResource`. Decode tests in `resources/decode_test.go`, client tests in `connection/client_test.go`, following `providers/vercel`. Run `go test ./...` inside `providers/<name>/`.

### Step 3.7: A test that cannot fail is worse than no test

Name the implementation edit that would make the test fail. Can't? Delete it.

| Cannot fail | Why it proves nothing |
|---|---|
| `assert.NotEmpty(t, res)` alone after `x.TestQuery(...)` | Non-empty for any query that compiles; asserts only that MQL parsed |
| `assert.GreaterOrEqual(t, len(x), 0)`, `assert.NotNil` on an always-returned slice | No failing input exists |
| `assert.NoError` on a field a stronger sibling already reads by value | The sibling fails first and says more |
| Expected value read from the same `const`/`var`/map the implementation reads | Both sides move together (an enum constant as the expectation is fine) |
| Asserting on a struct the test just built, or round-tripping twice | Agrees with itself by construction |
| Fixture generated by running the code and pasting the output | Pins current bugs, fails on every legitimate improvement |

Not weak, keep them: `assert.True/False` on a derived predicate, `assert.Error` on malformed input, `assert.Empty/Nil` on the absent case ("null, not zero" breaks often), `assert.Contains` on a discovery list verified against real images (keep the comment saying where each entry came from).

Delete bad tests you find in files you edit and name them in the PR. Never delete a test just because it fails.

### Step 4: Verification

Unit tests complement interactive verification, they don't replace it. After each provider change:

```bash
make providers/build/<provider> && make providers/install/<provider>
mql run <provider> -c "<query from the ticket>"
```

`make mql/install` once, or when mql core changes. `go run apps/mql/mql.go` only if you're also modifying core. To test a build without clobbering the installed provider, or to A/B against `main`, use the `PROVIDERS_PATH` recipe in `new-resource`. Against real cloud infra: `provider-verification`.

## 3. Build, test, debug

`make prep/tools` once (protolint, mockgen, gotestsum, golangci-lint, copywrite). Then:

```bash
make mql/install                                              # build + install the mql binary
make providers/build/<p> && make providers/install/<p>        # rebuild one provider
make test/go/plain                                            # unit tests (excludes providers)
make test/lint                                                # lint
```

The rest is in [DEVELOPMENT.md](DEVELOPMENT.md): full build matrix, `test/generate` mocks, integration and race targets, builtin-provider debugging with Delve on a remote VM, Go workspaces for cnspec, Prometheus metrics. Version bumps: `provider-release`.

- GitHub MCP for tickets/PRs, Notion MCP for internal docs.
- AWS/Azure CLIs are usually authenticated; if not, stop and ask.
- Run the MQL queries in a ticket during development, again during verification.
- Read `providers/<name>/README.md` for auth and usage before working on a provider.
- Unit tests can use the mock providers in `providers-sdk/v1/testutils` and the recording/replay system.
- To step through a provider, make it builtin (DEVELOPMENT.md → Debug providers) and attach a debugger instead of printing to stdout.

## 4. Architecture (what provider work touches)

Providers are gRPC plugins (hashicorp/go-plugin), each its own Go module, spawned by `providers.Coordinator`; the core provider (`asset`, `time`, `regex`) is always builtin. MQL text → `mqlc` → `llx` bytecode → executor calls `provider.GetData(connection, resource, field, args)` → `llx.RawData`, cached per resource field. Component map and codegen chain: DEVELOPMENT.md → Architecture overview. `llx/` builtin rules: `llx/CLAUDE.md`.

**Caching and `__id`.** Cache key is `resourceName + "\x00" + __id`, checked before fetching. `__id` must be unique and stable (ARN, UUID, composite key). Empty or duplicated ids break caching: `CreateResource` returns the cached first instance for a repeated id, so the second declaration silently reports the first one's values.

Hide synthetic `__id` values, don't expose them as `id` fields. When a sub-resource's key is purely internal (`<parentId>/confidentialCompute`), don't declare `id string` in the `.lr`; pass the key via the magic `"__id"` argument to `CreateResource` and omit the `id()` Go method. A public `id string` is for ids someone might write `.where(id == "...")` against (an ARN, a GCP resource name). A sibling exposing such an `id` is a pre-existing deviation, not precedent (`gcp.project.binaryAuthorizationControl.policy`).

**Null semantics.** A null operand of `&&` or `||` is falsy (ADR 040 part 4): `null && anything` is `false`, `null || x` is `x`, `null == null` is `true`. An init-miss stub whose booleans stay `StateIsNull` now fails a `{ a && b }` assertion. Explicit `false` is still better: it states a measured fact where null says nothing was read.

## 5. Schema and code conventions

- Copyright header on every `.go`, `.lr`, `.proto`, enforced by `copywrite`. First year fixed at 2024, second is the current year:
  ```
  // Copyright Mondoo, Inc. 2024, <current year>
  // SPDX-License-Identifier: BUSL-1.1
  ```
- `.lr.versions`: every resource and field has an entry, at the next patch version after the provider's `Version` in `providers/<name>/config/config.go` (at `13.1.1`, new fields are `13.1.2`). Don't copy the highest version in the file, it may predate a major bump. Exception: a new unreleased provider puts every entry at its initial `Version`. Removing a field doesn't remove its entry, delete the line by hand. Don't bump `Version` in a feature PR, the release flow does that.
- Never change a shipped field's type. Deprecate the old one, add a new one; decline review-bot suggestions to mutate in place.
- Deprecate with `@maturity("deprecated")`: title stays a plain noun phrase, description leads with `Deprecated in favor of ...` or `Deprecated, please use ...`, `.lr.versions` entry stays at its original version. `@maturity("preview")` marks fields whose shape may still change.
- `@replaced_by("<full schema path>")` when there's a single destination. It's a pointer, not a transform: the old name keeps resolving, and anything that restructures a value or calls an API is a Go lens (ADR 040). Generation fails if the target doesn't exist or isn't reachable from an asset root. Annotation order: `@defaults`, `@context`, `@maturity`, `@replaced_by`, `@global`, `@root`.
  ```
  // Hostname for this OS
  //
  // Deprecated in favor of os.base.hostname, reachable as `_.hostname`.
  hostname() @maturity("deprecated") @replaced_by("os.base.hostname") string
  ```
- Sub-resource only with a clear natural id (ARN, name-with-region; synthetic `<parentArn>/leaf` doesn't count), or to hold typed references to other modeled resources. Otherwise flatten scalars onto the parent with a prefix (`linuxMaxSwap int`, `fargatePlatformVersion string`), `map[string]string` for name/value lists (`environmentVariables`, `resourceRequirements["GPU"]`), `[]dict` for small heterogeneous structs where no field warrants its own audit query. A sub-resource costs a struct, `__id` stability, serialization, tests, and a versions entry per field.
- `isPublic()` means "reachable from the internet" on ~20 resources. Don't reuse it for another kind of open (an unrestricted policy); use `hasWildcardPolicy()` or similar.
- Match SDK types faithfully: `*bool` → `bool` via `llx.BoolDataPtr()`, two-state enums → `bool`, `*type` intermediates with `llx.*DataPtr` to preserve nil. Follow how the resource's existing fields handle pointers.
- Skip deprecated SDK fields and methods (`// Deprecated:`); they return empty on modern instances because the data moved. Comment if you must keep one.
- Always commit `*.permissions.json` when `make providers/build/<provider>` changes it. A new AWS client's permissions only land if the client is mapped in `awsConnectionMethodToService` (plus `awsServiceNameOverrides` when the IAM prefix differs from the SDK package); for GCP, a `Get<Resource>` gRPC method needs a `gcpPermissionOverrides` entry for the plural form. Miss either and the perms silently drop.
- Every provider that accepts connections declares an asset root (ADR 031): `@root` on the resource, `option root = "<resource>"` in the `.lr`, `Root:` in `config/config.go`, core in `Requires` (ADR 042). Enforced by `providers/roots_test.go`. Scaffolding: DEVELOPMENT.md → Creating a new provider, and `new-provider`.
- `go mod tidy` runs inside `providers/<name>/`, not the repo root, or new SDK deps stay `// indirect`.

## 6. Pre-PR checklist

- [ ] `gofmt -w` on all changed `.go` files
- [ ] Generated files current: `make mql/generate && git diff --exit-code` (`.lr.go`, `.pb.go`, `.permissions.json`)
- [ ] `go mod tidy` inside `providers/<name>/` shows no diff
- [ ] `make test/lint` and `make test/go/plain` pass; `go test -v ./providers/<provider>/...` if the provider has tests
- [ ] Verified interactively (`mql shell <provider>`, queries from the ticket)
- [ ] Every new field naming another resource is a typed accessor (Step 1.5)
- [ ] Pure Go logic has unit tests (Step 3.6); every test added can fail, any found that couldn't was removed (Step 3.7)
- [ ] No spelling errors: CI runs `crate-ci/typos` (config `_typos.toml`). Fix real typos, add identifiers and product names to `_typos.toml`
- [ ] `make race/go` if touching concurrency; `make test/integration` if changing core execution

## 7. Commits

Start every commit and PR title with one of:
🛑 breaking · 🐛 bugfix · 🧹 cleanup/internals · ⚡ speed · 📄 docs · ✨⭐🌟🌠 features (smaller to larger) · 🌈 visual · 🐎 race fix · 🌙 MQL changes · 🟢 fix tests · 🎫 auth · 🐳 container

In `git commit -m`, `gh pr create --title`, and commit-message HEREDOCs. Pick the dominant kind when a change spans several.

No Claude session IDs in git: no `Claude-Session:` trailer, no `claude.ai/code/session_…` URL in a commit message, no session URL in a PR body. This overrides any harness default. (`Co-Authored-By: Claude …` is fine.)

Anticipate needs, offer options where they apply, think ticket → solution → codebase.
