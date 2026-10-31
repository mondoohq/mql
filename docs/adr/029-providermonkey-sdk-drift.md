# ADR 029: providermonkey — Automated SDK Drift Detection for Providers

## Status

Proposed

## Context

mql ships 57 providers, each its own Go module wrapping an upstream cloud or SaaS SDK. Across the fleet there are **377 distinct third-party direct module paths** (518 provider→module edges). `providers/aws` alone declares 129 direct requires, `providers/azure` 70, `providers/gcp` 62 — dominated by monorepo-style service submodules (`aws-sdk-go-v2/service/*`, `azure-sdk-for-go/sdk/resourcemanager/*`, `cloud.google.com/go/*`).

These SDKs move continuously. They add fields, deprecate methods, retract broken releases, and cut new majors. Today we track exactly one dimension of that movement — the version string — and we track it well. Everything else is invisible to CI.

### What the existing automation does, and does correctly

`.github/workflows/update-deps.yaml` runs weekly and invokes `providers-sdk/v1/util/version/version.go mod-update --latest` across every provider module, then `mod-tidy`, then opens a PR.

It is important to state plainly: **this works.** We verified it experimentally rather than assuming.

Starting from a worktree at `ec18c9ad0` (the 2026-07-22 deps-update commit) and running the mutator directly:

| Provider | Direct deps stale before | `go get` errors | Exit | Direct deps stale immediately after |
|---|---|---|---|---|
| `digitalocean` | 3 | 0 | 0 | **0** |
| `aws` | 130 attempted | 0 | 0 | **0** |

Both runs were measured with `go list -m -u -json all` at the same instant as the update, so upstream drift between mutation and verification is zero. Within its scope, `mod-update` is correct and complete.

### The gap is scope, not correctness

The tool's scope is deliberately narrow, and the boundary is explicit in code.

`version.go:152-156` skips indirect dependencies by design:

```go
for _, require := range modFile.Require {
    // Skip indirect dependencies
    if require.Indirect {
        continue
    }
```

And `go get -u` structurally cannot cross a major version, because in Go a new major is a *different module path* (`example.com/m` vs `example.com/m/v2`). No amount of `--latest` will discover a `/v2`.

So after the verified-perfect aws run above — 130 updates, zero errors, zero direct deps left stale — the resulting module graph still contained:

```
DEPRECATED cloud.google.com/go/pubsub@v1.3.1                        (use .../pubsub/v2)
DEPRECATED github.com/aws/aws-sdk-go-v2/feature/s3/manager@v1.17.10 (superseded by feature/s3/transfermanager)
DEPRECATED github.com/cncf/udpa/go@v0.0.0-20210930031921            (use github.com/cncf/xds/go)
DEPRECATED github.com/golang/protobuf@v1.5.4                        (use google.golang.org/protobuf)
DEPRECATED go.opentelemetry.io/otel/exporters/jaeger@v1.17.0        (no longer supported)
RETRACTED  modernc.org/libc@v1.74.3
```

That last one is not cosmetic. The author's retraction message reads:

> *"freeaddrinfo leaks a locked `___lock` entry; deadlocks name resolution, fixed in v1.74.4"*

A fleet-wide scan confirms **all 57 providers currently resolve `modernc.org/libc@v1.74.3`**. The fix, `v1.74.4`, was published 2026-07-27 16:37 UTC — hours *after* that week's Monday cron. Nothing will notice until the following Monday, and even then only incidentally, because nothing in CI ever asks the question.

This is the actual finding, and it generalizes: **we have a mutator and no verifier.** The mutator answers *"did we bump the version numbers we know how to bump?"* — correctly. Nothing answers *"is the resulting dependency graph healthy?"* The value of a verifier here is not catching a broken mutator; it is asking the questions the mutator was never designed to answer.

Current fleet measurements (`go list -m -u -json all`, all 57 modules):

| Signal | Count |
|---|---|
| Distinct deprecated modules in the graph | 13 |
| Providers resolving a retracted version | **57 / 57** |
| Direct modules already on a major `>= v2` (where new-major drift applies) | 83 |

### Static analysis is switched off for providers

A second, independent gap. `.golangci.yaml:7-10` is:

```yaml
linters:
  default: none
  enable:
    - depguard
```

and `.github/workflows/reusable-lint-providers.yml:95` runs `golangci-lint run --timeout=30m $extra_args` with **no `-c` flag** — so all 57 provider modules are linted with that root config. `.github/.golangci.yaml` does enable `staticcheck` and `unused`, but it is only applied to the root module via the opt-in `test/lint/extended` Makefile target.

Net effect: **staticcheck SA1019 (use of a deprecated function, method, field, or package) and `unused` never run against provider code.** Developers have nonetheless hand-written 7 `nolint:staticcheck` and 4 `nolint:unused` suppressions for violations CI cannot see — evidence the checks are wanted, just not wired up.

Relatedly, `.golangci.yaml:20-21` already carries a hand-curated deprecated-dependency denylist:

```yaml
- pkg: github.com/mitchellh/mapstructure
  desc: no longer maintained; use github.com/go-viper/mapstructure/v2 v2.2.1 instead
```

That is this ADR's job, performed manually.

### Existing constraints any such tool must respect

- **`CLAUDE.md:536-554`** — *"Never change a shipped field's type — it's customer-breaking. Deprecate the old field and add a new one instead."* Field removal is breaking and gated on a major release.
- **ADR 002:29-32** establishes the one-major-cycle deprecation window (`v14`).
- **`CLAUDE.md:539`** — *"Skip deprecated SDK fields and methods... deprecated fields often return empty/zero... modeling them adds dead schema."* This forbids an "expose every SDK field" crawler.
- **`@maturity("deprecated")`** already exists as a first-class `.lr` annotation, validated by `resources.ValidateMaturity()` and carried through `resources.proto` into `ResourceInfo.maturity` / `Field.maturity`. It is already used by 20+ providers.

## Decision

Introduce **`providermonkey`**, an internal CLI at `apps/providermonkey/` that runs on a schedule and reports SDK drift across all provider modules.

It is structured as **six independent tiers ordered by decidability**, each emitting the same JSON envelope. This ordering is the central design decision: findings differ enormously in confidence, and mixing a toolchain-exact fact with a 60%-precision heuristic in one report destroys trust in both.

`providermonkey` **never deletes a resource, field, or SDK call.** Per the constraints above, its only permitted mutations are additive or annotative.

### T0 — Fleet inventory *(exact; zero false positives)*

`go list -m -u -json all` per module, in parallel (measured: ~9s/module, <2 min fleet-wide). Reports `Update`, `Deprecated`, `Retracted` straight from the Go toolchain — including for indirect dependencies, which `mod-update` skips by design.

**T0 is also the verifier for the existing cron.** Run it immediately after `mod-update` in `update-deps.yaml`; if a *direct* dependency still reports an available `Update`, the mutation did not achieve its goal — fail loudly instead of opening a quietly-incomplete PR. Today that check would pass, which is exactly why it should be locked in now, before a regression makes it fail silently.

Independently, T0 gates on any `Retracted` module and reports `Deprecated` ones. This is the tier that catches `modernc.org/libc`.

### T1 — New-major detection *(exact)*

Probe `proxy.golang.org/<escaped-path>/vN+1/@v/list`; HTTP 404 means no such major. 83 direct modules already sit on `/v2+`, so this is live surface. Generalize the logic already proven in `.claude/skills/update-azure-deps/probe.py` — including the `!`-escaping for uppercase paths (`Azure` → `!azure`) — and retire the per-cloud special case.

### T2 — Deprecated SDK API usage *(exact)*

Enable staticcheck SA1019 against provider modules. SA1019 covers deprecated functions, methods, packages **and struct fields** (its `facts/deprecated` analyzer walks `*ast.StructType` field docs; SA1019 checks composite-literal keys). It requires dependency *source*, which the module cache already provides.

Run it under `providermonkey` rather than by flipping the shared lint config, so an initial backlog does not block every unrelated PR on day one.

### T3 — Footprint-directed drift *(exact for API surface)*

The tier that answers *"is our code still doing the right thing against this SDK?"*

Naively diffing whole SDK versions is unusable: `aws-sdk-go-v2` v1.42→v1.43 produces thousands of irrelevant changes. Worse, `apidiff.Change` carries no structured symbol reference — verified in `golang.org/x/exp/apidiff/apidiff.go:42,90`:

```go
Change{Message: m, Compatible: false}
```

The identifier is baked into a `fmt.Sprintf`'d string, so changes cannot be reliably attributed back to our code by post-filtering.

Invert it — compute our **usage footprint** first, then diff only that:

1. `packages.Load` the provider with `NeedTypes|NeedSyntax|NeedTypesInfo|NeedDeps`.
2. Walk `TypesInfo.Uses`, collecting every `types.Object` whose `Pkg().Path()` belongs to an SDK module. This is the exact, complete set of SDK symbols we touch — hundreds, not tens of thousands.
3. `go mod download` the candidate version; `packages.Load` it with `NeedTypes` only.
4. For each footprint symbol, `Scope().Lookup(name)` in the new package and compare via `types.Identical`. Missing → breaking. Signature changed → breaking. Present but newly carrying a `// Deprecated:` doc → newly deprecated.

`apidiff.Changes` is retained only to render human-readable prose for symbols the footprint already flagged.

This is what catches the silent breakages currently enumerated by hand in the `update-azure-deps` skill — `*string` → `*time.Time` field retypes, sync → LRO (`Update` → `BeginUpdate`) flips, `*Identity` → `*ManagedServiceIdentity` renames. Each is a `types.Identical` failure on a symbol we demonstrably use.

### T4 — Our own dead code *(exact, with caveats)*

Use `unused`, **not** `golang.org/x/tools/cmd/deadcode`. Providers are plugins: `deadcode` computes reachability from `main` and would report every exported resource method as dead. `unused` encodes "packages use exported symbols" rules and has the correct false-positive profile here.

Second half, higher value: audit `.lr` against the committed `.lr.versions`. A field already marked `@maturity("deprecated")`, whose replacement exists, introduced long enough ago, is a concrete `v14` removal-window candidate under ADR 002.

### T5 — Schema coverage *(heuristic; advisory only)*

Detecting "the SDK grew a field we don't expose" is **not mechanically reliable today**, and this ADR does not claim otherwise:

- There is **no machine-readable link** between an MQL resource and the SDK type it wraps. `resources.proto` has no `sdk_type` on `ResourceInfo` or `Field`. The `aws.s3.bucket` → `s3.Bucket` convention holds across all 57 providers but is unenforced and invisible to a compiler.
- **~40% of fields are `convert.JsonToDict(...)` blob passthrough.** We can see *which* struct was serialized, not which nested fields thereby became visible. Opaque by construction.
- Computed fields (`llx.StringData(region)`) are indistinguishable from SDK reads (`llx.StringDataPtr(bucket.Name)`) without semantic analysis.

Realistic ceiling: **60-70%** of unmapped fields detected with high precision. Ships last, opt-in per provider, advisory-only, never a gate. It must surface *non-deprecated* new surface only, so as not to contradict `CLAUDE.md:539`.

### Output and workflow

**One idempotent tracking issue per provider**, updated in place, tiers as checklist sections. 173 findings across 18 providers as individual PRs would bury the repo.

Auto-PRs are reserved for three narrow, policy-safe mutations:

1. Add `@maturity("deprecated")` to a `.lr` field (then `make providers/mqlr`).
2. Add a `depguard` deny rule when T0 finds a deprecated module — automating what `.golangci.yaml:20-21` does by hand.
3. Bump a version string when T1 finds a new major.

Reuse `scripts/changed-providers.sh` for scoping and the proven `peter-evans/create-pull-request` + `CNQUERY_DEPLOY_KEY_PRIV` pattern from `update-deps.yaml`.

Scheduling: T0/T1 nightly (the `libc` case shows weekly is too slow for retractions); T2/T3 weekly, gated on T0/T1 finding something; T4/T5 monthly.

### Placement

Follow the existing convention: a thin `apps/providermonkey/main.go` with logic in a `cmd/` subpackage, cobra, no goreleaser target — mirroring `apps/gen-docs`. Subcommands per tier (`inventory`, `majors`, `deprecated`, `drift`, `deadcode`, `coverage`), plus `scan` and `report`.

## Consequences

### Positive

- The retracted `modernc.org/libc@v1.74.3` deadlock — currently in all 57 providers — becomes a hard CI failure rather than an indefinite silent liability.
- Indirect-dependency health becomes visible for the first time; `mod-update` skips it by design and always will.
- Existing weekly automation gains a real success criterion instead of relying on `exit 0`.
- SA1019 and `unused` finally reach provider code, retiring 11 hand-written suppressions for invisible violations.
- New majors become discoverable, which `go get -u` structurally cannot do.
- The `update-azure-deps` skill's hand-maintained breaking-change table becomes a per-provider mechanical check.

### Negative / risks

- **T2 backlog.** Enabling SA1019 across 57 modules will surface an unknown initial volume. Mitigated by running it reporting-only outside the shared lint config.
- **T3 cost.** `NeedDeps` loading is multiplicative; `aws` with 129 direct modules is the worst case. Mitigated by footprint-directing the diff and by gating T3 behind T0/T1.
- **T5 imprecision is permanent** without a schema change (below). It must never become a gate, or it will train reviewers to ignore the whole report.
- **Another scheduled workflow** to own and keep green.
- `apidiff` is an `x/exp` package with no compatibility guarantee. Mitigated by using it only for message rendering; the load-bearing comparison is `go/types`.

### Follow-up: the schema change that makes T5 decidable

Add an optional `@sdk("<pkg>.<Type>")` annotation to `.lr`, propagated into `ResourceInfo`/`Field` alongside `maturity`. The `.lr` file is already the single source of truth and the parser already handles `@`-decorators, so the change is small.

That one annotation converts T5 from a 60%-precision heuristic into a decidable check, and lets T3 attribute an upstream breaking change directly to the MQL fields it threatens. This ADR does not block on it, but every week without it adds unannotated surface.

### Explicitly out of scope

- **Release-note breaking-change parsing.** Unstructured prose across four different SDK conventions; T3's type-level diff is strictly better evidence.
- **Anything Renovate already does.** Renovate with `postUpdateOptions: [gomodUpdateImportPaths, gomodTidy]` handles in-major bumps and import rewriting. It does **not** probe for new majors. If Renovate is adopted, T1's mutation half can be dropped — its detection half is still required.
