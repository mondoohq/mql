# Claude AI Context for mql

Rules for working in the mql codebase. Procedures live in the skills (§1.5), reference material in [DEVELOPMENT.md](DEVELOPMENT.md), and subtree-specific rules in scoped `CLAUDE.md` files (e.g. `llx/CLAUDE.md`).

## 1. Project Context

**mql** (formerly cnquery) is a cloud-native infrastructure querying tool. It uses **MQL (Mondoo Query Language)** to query over 1,300 resources across cloud accounts (AWS, Azure, GCP), Kubernetes, containers, OS internals, and APIs.

*   **mql**: the core inventory tool. Defines resources, implements MQL, and handles **data gathering**.
*   **cnspec**: the security scanning tool built *on top* of mql. It implements policy assertions, vulnerability checks, scanning, and SBOM generation.
*   **Rule of thumb:** for resource development (adding fields, new assets), you only need to work within **mql**.

## 1.5 Skills

This repo ships skills for its recurring tasks. They carry the procedure — the commands to run and the traps that bite — while this file carries the rules. Invoke the skill when the task matches; don't reconstruct the steps from scratch.

| skill | use when |
|---|---|
| `new-resource` | adding or changing a resource or field in an existing provider, or a resource returns null/empty and the schema is the suspect. Its `references/implementation-patterns.md` holds the Go patterns (`CreateResource`/`NewResource`, `Internal` structs, lazy loading, discovery filters). |
| `new-provider` | bootstrapping a provider that does not exist yet (hands off to `new-resource`) |
| `provider-verification` | proving a PR or commit range against provisioned cloud infrastructure |
| `provider-bug-review` | auditing a shipped provider by reading code: nil handling, pagination, `__id` collisions |
| `provider-api-call-dedup` | a scan is slow, times out, or trips rate limits |
| `provider-release` | bumping provider versions and preparing a release |
| `update-provider-deps` | upgrading vendored SDKs and finding what the new version unlocks |
| `staged-discovery` | adding staged/phased discovery to a provider |
| `check-querypack-deprecations` | checking `content/` query packs against deprecated resources or fields |

## 2. Resource Development Rules

Resources are defined in `.lr` files (e.g. `providers/aws/resources/aws.lr`), generated into Go with `mqlr`, and implemented in the provider's Go code. **Use the `new-resource` skill for the procedure.** The rules below are what the skill assumes you know.

### Step 1: Schema (`.lr`) doc-comments

Every top-level resource (anything users query directly, including singular records like `aws.ec2.instance` and namespace roots like `aws`) has a two-part doc-comment immediately above the `resource {` line:

1. **Title.** A one-line noun phrase naming *what the resource is*: no leading article, no trailing verbs like "static analysis". **Must not start with "deprecated"** (enforced); use `@maturity("deprecated")` instead. **Max 150 characters** (`lrcore.MaxTitleLength`, rune-counted, enforced).
2. **Single empty `//` line.**
3. **Description.** Multi-line prose on what is queryable: fields, sub-resources, derived predicates, the audits it enables. **Lead with the noun being exposed, not a verb** (never open with `Examine`/`Iterate`/`Use`). When the resource is keyed by a field, name it as the selection key with a concrete example. **Must not start with "Deprecated." or "Deprecated:"** (enforced); the only accepted leading forms are `Deprecated in favor of ...` and `Deprecated, please use ...`.

```
// Section of the Arista EOS running-config
//
// A single named section of the running-config. The `name` field selects the
// section as it appears in the running-config, for example
// `arista.eos.runningConfig.section(name: "interface Ethernet1")`.
arista.eos.runningConfig.section { ... }
```

**Doc-comment shape (enforced by the parser, for resources AND fields):** a comment is **either** one line (title only) **or** title, blank `//`, multi-line description. Two contiguous comment lines with no blank `//` between them are **rejected at parse time** (`lrcore/lr.go: validateDocCommentStructure`). The parser is positional: line 1 is `title`, everything after is `desc`. If a title doesn't fit in 150 characters, some of it belongs in the description.

```
// Budget type
//
// One of COST, USAGE, RI_UTILIZATION, RI_COVERAGE, SAVINGS_PLANS_UTILIZATION, or SAVINGS_PLANS_COVERAGE.
budgetType string
```

**Prose rules:**
- No em dashes anywhere in `.lr` files. Use a period, comma, parentheses, or colon.
- Reference a field by its bare name (`serviceAccount`), never the call form (`serviceAccount()`).
- Don't reference the parent as a navigation hint ("read from the parent device as ...").
- No developer jargon ("Singleton"), no implementation mechanism ("typed reference", "lazy-loaded", "fetched on-demand", "phase 1/phase 2"), no cross-cloud analogies ("the Azure equivalent of AWS Macie"). Per-discriminator dict shape lists are schema, not mechanism; keep them.
- Cross-reference siblings only when it helps the reader (raw view → richer typed view).
- Private resources and pure sub-row types (`*.entry`) typically need only a single-line comment.
- When listing enum values, check the SDK/API docs for completeness; don't assume the set is closed.

### Step 1.5: Typed-reference gate (before codegen)

**Shipping a raw ID/URL string where a typed accessor belonged is the most expensive mistake to fix later**: replacing `projectId string` with `project() openstack.project` is a breaking change. Before codegen, scan every new field: does this value identify or point at another modeled resource? If yes, it MUST be a typed accessor.

| You wrote (stop) | Ship this instead |
|---|---|
| `projectId string` / `userId string` | `project() <provider>.project` / `user() <provider>.user` |
| `vpcId string` / `subnetIds []string` | `vpc() aws.vpc` / `subnets() []…subnet` |
| `roleArn string` | `iamRole() aws.iam.role` (not `role`, to avoid ambiguity) |
| `networkUrl string` (GCP self-link) | `network() …network` (likewise `subnetworkUrl`, `routerUrl`, `sslPolicyUrl`, `securityPolicyUrl`, `interconnectUrl`, `vpnGatewayUrl`) |

- Keep a raw string **only** when it is the resource's own `id`, or a genuinely opaque scalar that names no modeled resource (a hash, a discriminator, a free-form `name`). When in doubt, prefer the accessor: store the raw value in a `cache*` field on the `Internal` struct and resolve it with `NewResource`.
- **Name the accessor with a domain word, never a `Ref`/`Refs`/`Typed` suffix.** When a raw field occupies the clean name, pick the word that says what the reference *is* (`managedSecurityGroup()` beside a `loadBalancerSecurityGroup` dict). Shipped `*Ref` accessors stay for compatibility and are not precedent.
- **Deprecate the raw `*Id`/`*Arn` field when a typed accessor carries the same value** (`@maturity("deprecated")`). Keep the raw field only when it's a list of tokens the accessor can't round-trip.
- **Model both directions when both are useful.** The reverse edge often carries the audit (`deployKey.sites` finds a key no site uses).
- **Resolve references through a cached list, not a per-item lookup.** `NewResource` runs the target's `init` *before* the cache is consulted, so resolving a parent per child turns one list into N API calls. Scan the already-fetched parent collection instead.

This is a manual gate; no linter catches it.

### Step 2: Code generation

You must regenerate after modifying `.lr` files:

```bash
make providers/mqlr   # once, if ./mqlr is missing
./mqlr generate providers/aws/resources/aws.lr --dist providers/aws/resources
make mql/generate     # everything (slow)
```

- **Two naming traps look like Go bugs:** a resource named `<parent>.<field>` queried by its dotted path becomes an empty husk (`cannot convert primitive with NO type information`), and a list field whose path equals its element resource type compiles as a single resource (`is not a list type`; use a plural field over a singular element resource). The `new-resource` skill indexes these by symptom.
- **`Internal` structs need a second `mqlr generate`** after being added, and the stale embed lingers after removal until you regenerate (`undefined: mql<Name>Internal`).
- Never hand-edit generated `.lr.go` files.

**Schema-change report (ADR 040 part 5).** Codegen diffs the committed `*.resources.json` against the new schema and logs every delta as additive or breaking (type changed, resource/field/alias removed, became private or mandatory, list type changed, init signature moved). A `WARN breaking schema change` line is not a "fix your code" instruction; it means the change needs a decision: deprecate-and-add instead of mutating (§5), or a migration lens once phase 2 lands. Say which you chose in the PR. `--fail-on-breaking` turns it into a gate (off by default). **It fires once**: generation writes the new schema, so a second run compares new-against-new. The committed file in git is the baseline; if you missed the warning, revert the generated files and regenerate.

### Step 3: Implementation rules

Patterns and full code samples are in `.claude/skills/new-resource/references/implementation-patterns.md`. The rules:

- **`CreateResource` for listing APIs (set `__id`); `NewResource` for references resolved on demand via an `init`.** Only `NewResource` runs `init`; `CreateResource` skips it. An `__id` computed in `init` stays empty under `CreateResource`, and parameterized resources collide in the cache.
- **Read the target's `init` before writing a typed accessor.** Accepted arg keys are not uniform (`initAwsEc2Instance` takes `arn` only; `initAwsVpc` takes `arn` or `id`). The wrong key errors, and most accessors log-and-continue, so it surfaces as a **silently empty list**. Verify against real data.
- **Never `return nil, nil` from a singular resource accessor without setting `a.Field.State = plugin.StateIsSet | plugin.StateIsNull` first.** Otherwise the runtime doesn't know the field resolved and may panic or re-fetch. Applies to every `nil, nil` path (empty ID, access denied, nil response, unset optional). Slices, maps and scalars are unaffected.
- **Never let a singular resource's `init` fall through with `return args, nil, nil` when its lookup found nothing.** That creates a blank resource whose fields are *unset*, surfacing client-side as `llx: encountered a primitive with no type information, coercing to null` with no attribution. Return a not-found error (`fmt.Errorf("aws.apigatewayv2.api with arn %q not found", wantArn)`). `return args, nil, nil` is only correct for the "args already complete" fast path (`if len(args) > 2`).
- **Never hardcode empty/default values for fields the list API doesn't return.** Declare them computed (`description() string`), fetch the detail API on demand, and cache the result in an `Internal` struct (double-check locking; one fetch can feed several fields).
- **Never use `os/exec` directly.** Delegate through the `command` resource so execution works across local, SSH and container connections (see `providers/os/resources/lsblk.go`).
- **Resolve discovered assets by ARN, never by asset name.** Inject `getAssetIdentifier(runtime)` only when non-empty (an empty `args["arn"]` defeats the init's nil guard). The name is a display name. Exception: name-driven APIs (IAM `GetUser`) where discovery sets the asset name to the resource name; use `getAssetName(runtime)` then.
- **Always paginate** when the API supports it; loop on the marker/token until it is nil.
- **`convert.SliceStrPtrToStr` and `convert.SliceStrPtrToInterface` panic on nil elements.** Write a nil-safe loop when the SDK slice may hold nil pointers.
- Use `Is400AccessDeniedError(err)` for permission issues (return `nil` result, not error); return real errors for temporary failures (rate limits, network). Log and continue for region/permission issues on a single resource rather than failing the whole query.

### Step 3.5: Discovery-filter gate

**If a resource becomes a discovery target, its lister must consult `conn.Filters`.** Wiring the `case Discovery<Thing>:` branch in `discovery.go` and wiring the filters are separate edits, and the second is the one that gets forgotten: the service then accepts `--filters tag:...` and silently ignores it. Apply filters in the **lister** (`get<Thing>`), never in `discovery.go`, so MQL queries and discovery stay consistent.

- Gate the tag lookup on `conn.Filters.General.HasTags()` so it stays lazy; skip on `IsFilteredOutByTags(tags)`.
- No batch tags endpoint: use `fetchTagsConcurrently` in `aws.go`. Seed fetched tags onto the resource **only for a tag set you actually read**; use the comma-ok form on the result map.
- Region filters need nothing (`conn.Regions()` applies them). Service-specific filter structs (`conn.Filters.Ecr`, `conn.Filters.S3`) are consulted instead where they exist.

Because the bug is an absence, grep for it:

```bash
grep -rL "conn\.Filters" providers/<provider>/resources/*.go | grep -v _test
grep -n "case Discovery" providers/<provider>/resources/discovery.go
```

### Step 3.6: Pure-Go unit tests

**Every PR ships unit tests for the pure Go logic it adds**: everything that computes, parses, or decodes, where a bug compiles and returns a confident wrong answer. Test struct-tag decoding of every API record (a mistyped tag yields a zero value, so `blockPublicConnections` reads `false` on a project that blocks them), optional-value handling (absent pointer → safe reading, absent timestamp → **null**, not year 1), derived predicates (including empty and absent cases), pagination walks and their stuck-cursor guards (`httptest`), error classifiers (`IsForbidden` must not match a transport error), and parsers/helpers. Skip functions whose whole body is one SDK call plus a `CreateResource`. Put decode tests in `resources/decode_test.go` and client tests in `connection/client_test.go`, following `providers/vercel`. Run `go test ./...` inside `providers/<name>/`.

### Step 3.7: A test that cannot fail is worse than no test

**Before you keep a test, name the edit to the implementation that would make it fail.** If you can't, delete it. Fingerprints of a test that cannot fail:

| Pattern | Why it proves nothing |
|---|---|
| `assert.NotEmpty(t, res)` alone after `x.TestQuery(...)` | Non-empty for any query that compiles; asserts only that MQL parsed |
| `assert.GreaterOrEqual(t, len(x), 0)`, `assert.NotNil` on an always-returned slice | No failing input exists |
| `assert.NoError` on a field a stronger sibling already reads by value | The sibling fails first and says more |
| Expected value read from the same `const`/`var`/map the implementation reads | Both sides move together (naming an *enum constant* as the expectation is fine) |
| Asserting on a struct the test just built, or round-tripping through the function twice | Agrees with itself by construction |
| Fixture generated by running the code and pasting the output | Pins current bugs, fails on every legitimate improvement |

**Not weak, keep them:** `assert.True/False` on a derived predicate, `assert.Error` on malformed input, `assert.Empty/Nil` on the absent case ("null, not zero" is frequently broken), `assert.Contains` on a discovery list verified against real images (keep the comment saying where each entry came from).

Delete bad tests you find in files you edit and name them in the PR. Never delete a test merely because it is failing.

### Step 4: Verification

Unit tests complement rather than replace interactive verification. After each provider change:

```bash
make providers/build/<provider> && make providers/install/<provider>
mql run <provider> -c "<query from the ticket>"
```

`make mql/install` is needed once, or when mql core changes; only use `go run apps/mql/mql.go` when you are also modifying core. To test a build without clobbering the installed provider, or to A/B against `main`, use the `PROVIDERS_PATH` recipe in the `new-resource` skill. To prove a PR against provisioned cloud infrastructure, use `provider-verification`.

## 3. Build, Test, Debug

`make prep/tools` once (protolint, mockgen, gotestsum, golangci-lint, copywrite). Then:

```bash
make mql/install                                              # build + install the mql binary
make providers/build/<p> && make providers/install/<p>        # rebuild one provider
make test/go/plain                                            # unit tests (excludes providers)
make test/lint                                                # lint
```

Everything else (full build matrix, `test/generate` for mocks, integration and race targets, provider version bumps, builtin-provider debugging with a debugger or Delve on a remote VM, Go workspaces for cnspec, Prometheus metrics) is in [DEVELOPMENT.md](DEVELOPMENT.md). Version bumps are the `provider-release` skill.

**Tips:** use the GitHub MCP for tickets/PRs and the Notion MCP for internal docs. AWS/Azure CLIs are usually authenticated; if not, stop and ask. If a ticket contains MQL queries, run them during development and verification. Check `providers/<name>/README.md` for auth and usage before working on a provider. Unit tests can use the mock providers in `providers-sdk/v1/testutils` and the recording/replay system. To step through a provider, make it builtin (DEVELOPMENT.md → Debug providers) and attach a debugger rather than printing to stdout.

## 4. Architecture (what you need for provider work)

Providers are gRPC plugins (hashicorp/go-plugin), each its own Go module, spawned by `providers.Coordinator`; the core provider (`asset`, `time`, `regex`) is always built in. MQL text → `mqlc` compiles to `llx` bytecode → the executor asks `provider.GetData(connection, resource, field, args)` → `llx.RawData`, cached per resource field. The component map and codegen dependency chain are in DEVELOPMENT.md → Architecture overview. Rules for `llx/` builtins live in `llx/CLAUDE.md`.

### Resource caching & `__id`

Each resource instance's cache key is `resourceName + "\x00" + __id`; the runtime checks the cache before fetching. `__id` must be unique and stable (ARN, UUID, composite key). Empty or duplicated ids break caching: `CreateResource` returns the **cached first instance** for a repeated id, so the second declaration silently reports the first one's values.

**Hide synthetic `__id` values; don't expose them as `id` fields.** When a sub-resource's key is purely internal (`<parentId>/confidentialCompute`), do NOT declare `id string` in the `.lr`. Pass the key via the magic `"__id"` argument to `CreateResource` and omit the `id()` Go method. Reserve a public `id string` for ids a user might write `.where(id == "...")` against (an ARN, a GCP resource name). An existing sibling that exposes such an `id` is a pre-existing deviation, not precedent. Example: `gcp.project.binaryAuthorizationControl.policy`.

### Null semantics

**A null operand of `&&` or `||` is falsy** (ADR 040 part 4): `null && anything` is `false`, `null || x` is `x`, `null == null` is `true`. An init-miss stub whose booleans stay `StateIsNull` now **fails** a `{ a && b }` assertion. Setting explicit `false` is still better practice: it states a measured fact where null states that nothing was read.

## 5. Schema & Code Conventions

- **Copyright header** on every source file (`.go`, `.lr`, `.proto`), enforced by `copywrite`. The first year is fixed at 2024, the second is the current calendar year, comma-separated:
  ```
  // Copyright Mondoo, Inc. 2024, <current year>
  // SPDX-License-Identifier: BUSL-1.1
  ```
- **`.lr.versions`:** every resource and field has an entry. New entries use the **next patch version** after the provider's `Version` in `providers/<name>/config/config.go` (at `13.1.1`, new fields are `13.1.2`). Don't trust the highest version already in the file; it may predate a major bump. **Exception:** a brand-new, unreleased provider puts every entry at its initial `Version`. Removing a field does not remove its entry; delete the line by hand. **Don't bump `Version` in a feature PR**; the release flow does that.
- **Never change a shipped field's type.** Deprecate the old field and add a new one; decline review-bot suggestions to mutate in place.
- **Deprecate with `@maturity("deprecated")`**, title stays a plain noun phrase, description leads with `Deprecated in favor of ...` or `Deprecated, please use ...`. Keep the existing `.lr.versions` entry at its original version. `@maturity("preview")` marks fields whose shape may change.
- **Name the replacement with `@replaced_by("<full schema path>")`** when there is a single destination. It is a pointer, not a transform: the old name keeps resolving; anything that must restructure a value or call an API is a Go lens (ADR 040). Generation fails if the target doesn't exist or can't be reached from any asset root. Annotation order: `@defaults` → `@context` → `@maturity` → `@replaced_by` → `@global` → `@root`.
  ```
  // Hostname for this OS
  //
  // Deprecated in favor of os.base.hostname, reachable as `_.hostname`.
  hostname() @maturity("deprecated") @replaced_by("os.base.hostname") string
  ```
- **When to create a sub-resource:** only with a **clear natural id** (ARN, name-with-region; synthetic `<parentArn>/leaf` does not count) or to **hold typed references** to other modeled resources. Otherwise flatten scalars onto the parent with a prefix (`linuxMaxSwap int`, `fargatePlatformVersion string`), use `map[string]string` for name/value lists (`environmentVariables`, `resourceRequirements["GPU"]`), and `[]dict` for small heterogeneous structs no field of which warrants its own audit query. A sub-resource costs a struct, `__id` stability, serialization, tests and a versions entry per field.
- **`isPublic()` means "reachable from the internet"** on ~20 resources. Don't reuse it for another kind of "open" (an unrestricted policy); pick `hasWildcardPolicy()` or similar.
- **Match SDK types faithfully:** `*bool` → `bool` with `llx.BoolDataPtr()`, two-state enums → `bool`, `*type` intermediates with `llx.*DataPtr` to preserve nil. Follow how the resource's existing fields handle pointers and conversions.
- **Skip deprecated SDK fields and methods** (`// Deprecated:`); they return empty on modern instances because the data moved. Comment if you must keep one.
- **Always commit `*.permissions.json`** when `make providers/build/<provider>` changes it. A new AWS client's permissions only land if the client is mapped in `awsConnectionMethodToService` (plus `awsServiceNameOverrides` when the IAM prefix ≠ SDK package); for GCP, a `Get<Resource>` gRPC method needs a `gcpPermissionOverrides` entry for the plural form. Miss either and the perms silently drop.
- **Every provider that accepts connections declares an asset root** (ADR 031): `@root` on the resource, `option root = "<resource>"` in the `.lr`, `Root:` in `config/config.go`, and core in `Requires` (ADR 042). `providers/roots_test.go` enforces this. Scaffolding and registration are in DEVELOPMENT.md → Creating a new provider and the `new-provider` skill.
- **`go mod tidy` runs inside `providers/<name>/`**, not the repo root, or new SDK deps stay `// indirect`.

## 6. Pre-PR Checklist

- [ ] `gofmt -w` on all changed `.go` files
- [ ] Generated files up to date: `make mql/generate && git diff --exit-code` (`.lr.go`, `.pb.go`, `.permissions.json`)
- [ ] `go mod tidy` inside `providers/<name>/` shows no diff
- [ ] `make test/lint` and `make test/go/plain` pass; `go test -v ./providers/<provider>/...` if the provider has tests
- [ ] Changes verified interactively (`mql shell <provider>`, queries from the ticket)
- [ ] Every new field that names another resource is a typed accessor (Step 1.5)
- [ ] Pure Go logic has unit tests (Step 3.6); every test added can fail, and any found that cannot was removed (Step 3.7)
- [ ] No spelling errors: CI runs `crate-ci/typos` (config `_typos.toml`); fix genuine typos, add identifiers and product names to `_typos.toml`
- [ ] Race detection (`make race/go`) if touching concurrency; `make test/integration` if changing core execution

## 7. Commit Conventions

Start every commit and PR title with one of these emoji:
🛑 breaking · 🐛 bugfix · 🧹 cleanup/internals · ⚡ speed · 📄 docs · ✨⭐🌟🌠 features (smaller to larger) · 🌈 visual · 🐎 race fix · 🌙 MQL changes · 🟢 fix tests · 🎫 auth · 🐳 container

Use them in `git commit -m`, `gh pr create --title`, and commit-message HEREDOCs; pick the dominant kind when a change spans several.

**No Claude session IDs in git.** Commit messages must not carry a `Claude-Session:` trailer or a `claude.ai/code/session_…` URL, and PR bodies must not include the session URL. This overrides any harness default. (The `Co-Authored-By: Claude …` trailer is fine.)

Anticipate needs, offer options when it applies, think in the context of ticket-solution-in-codebase.
