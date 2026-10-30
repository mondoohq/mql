# ADR 042: Cross-Provider Invocation

## Status

Proposed

## Context

Providers in mql are independent Go modules that run as separate gRPC
subprocesses (except `core`, which is built in). Despite that isolation, a
resource implemented in one provider routinely needs data from a resource
owned by another provider. The `os` provider builds the `network` provider's
`socket` and `tls` resources to model open ports; a dozen language-package
resources build the `core` provider's `cpe`; `aws` and `k8s` build `network`'s
`certificates`. This is real, load-bearing, in-production behavior.

### Relationship to ADR 030 / ADR 031

[ADR 030](030-asset-tree-anchored-relationships.md) and
[ADR 031](031-in-query-cross-asset-traversal.md) address a different axis:
**cross-*asset*** resolution, where asset A's resource tree points at a
*separate* asset B (`…mcpServers.first.running.tools`), resolved through a
typed `asset<root>` value backed by recording or a fresh connect. This ADR
addresses **cross-*provider*, same-asset** invocation: P2 answering for the
asset P1 is already connected to. No new asset is created, and the two axes are
orthogonal in code surface — 031 touches `types/`, `mqlc/`, `llx/`, and
recording; this ADR touches the provider schema, the coordinator gate, and
plugin lifecycle.

They meet at one point, and this ADR owns it. ADR 031 originally carried a
v14/v15 rule deprecating "undeclared cross-provider calls," but supplied only
one declaration form: the typed field forward-reference (`running
asset<mcp>`), which covers cross-asset references only. That left every
same-asset `CreateSharedResource` call — 37 sites across `os`, `k8s`, `aws`,
`oci`, and `vsphere` — inside the scope of an enforcement rule with no declaration
form available to satisfy it. **This ADR is therefore the authority on
cross-provider call legality**: it defines the declaration form for same-asset
calls, and carries the v14/v15 enforcement timeline for both forms (see
[Enforcement timeline](#enforcement-timeline-v14--v15)). ADR 031 retains the
namespace half of its original rule (global namespace → root chaining) and
defers legality here.

### How it works today

A provider calls, on its SDK-side runtime, one of:

- `Runtime.CreateSharedResource(name, args)` — instantiate a resource by name.
- `Runtime.GetSharedData(name, id, field)` — read a field by name.

Neither call names a provider or a connection. The request round-trips over
gRPC back to the coordinator process
(`providers-sdk/v1/plugin/runtime.go:150`), lands in
`providerCallbacks.GetData` (`providers/runtime.go:828`), and the coordinator
`Runtime` resolves it:

1. `lookupResource` asks the aggregated schema which provider owns the name:
   `coordinator.Schema().Lookup(name)` (`providers/runtime.go:1018`,
   `providers-sdk/v1/resources/schema.go:125`). Every `ResourceInfo` carries a
   `Provider` string, plus `Others` for names defined by more than one
   provider.
2. If the owning provider is not already connected, the coordinator lazily
   starts it and calls `Connect` with a **clone of the primary provider's
   asset** (`crossProviderAsset()`, `providers/runtime.go:268`).
3. It dispatches `GetData` to that provider's connection.

The two calls take **different paths**, and only one of them is gated:
`CreateSharedResource` goes through `lookupResourceProvider`
(`providers/runtime.go:1018`), which checks the whitelist at `:1095`.
`GetSharedData` and every query-driven field access go through
`lookupFieldProvider` (`:1142`), which starts a foreign provider at `:1244`
with **no check at all**.

### What we want to remove

**1. The hardcoded whitelist.** Before step 2, the coordinator gates the
lookup against a literal slice baked into core
(`providers/runtime.go:1049`):

```go
crossProviderList := []string{
    "go.mondoo.com/mql/providers/core",
    "go.mondoo.com/mql/providers/network",
    "go.mondoo.com/mql/providers/os",
    ...
}
if info.Provider != providerConn && !stringx.Contains(crossProviderList, info.Provider) {
    return ..., errors.New("incorrect provider for asset, not adding " + info.Provider)
}
```

This is exactly backwards for a distributed provider model. A provider is a
self-contained, independently-versioned, independently-shipped artifact, but
whether it may participate in cross-calling is decided by a constant in a
*different* module (core). Adding a cross-callable provider means editing core
and re-releasing it.

Worse, when this ADR was written the list's own `FIXME: DEPRECATED` markers were
inverted. Of the nine whitelisted providers, only `core` matched the
`go.mondoo.com/mql/providers/*` block. `network`, `os`, `ms365`, and `azure`
matched **only** the block marked "remove in v12.0"; `networkdiscovery`, `ai`,
`ipinfo`, and `yara` matched **only** the block marked "remove in v14.0". Eight
of nine were kept alive exclusively by entries scheduled for deletion, and
honoring the v14 marker would have broken four providers outright. The module
path is not a usable identity here — see the Decision.

Two things have since changed. The v14 provider-ID change moved every shipped
provider onto the version-less `go.mondoo.com/mql/providers/*` block, so all
nine now match the non-deprecated entries; and both legacy blocks were retagged
to v15 to match this ADR's timeline. They are still required — a v14+ engine
routinely runs against provider binaries released before the ID change, which
report their old IDs — so they retire with the whitelist itself, not before.

**2. The half-built parallel mechanism.** *(Removed in v14, ahead of the rest of
this ADR.)* `Provider.CrossProviderTypes` let a provider declare asset
connection types it was willing to serve resources for. Its own doc comment
called it "only a hotfix." It was **read by nothing** — the struct field, its
comment, and three declaration sites (`providers/network/config/config.go`,
`providers/defaults.go`, and the enterprise repo's `networkdiscovery`). Every
declaration was also wrong: `network` named three IDs no provider had, followed
by a "DEPRECATED" block that a module-path sweep had rewritten into a
byte-identical duplicate of the first three, and the `defaults.go` entry was a
hand-edit in a generated file that `providerTemplate`
(`providers-sdk/v1/util/defaults/defaults.go`) silently drops on the next
regeneration.

It rotted because nothing read it *and* nothing checked it. Deleting it was
independent of the rest of this ADR, so it went with the provider-ID change
rather than shipping one more release of a field naming providers that do not
exist. The "nothing checked it" half is now covered by
`TestProviderIDsAreConsistent` (`providers/defaults_test.go`), which pins
`config.go` `ID` against `option provider` and the `defaults.go` entry.

### Cross-calling is a dependency, not a permission

The mechanism to reach for here is **dependency declaration**, not consent:

- **A provider "provides" its resources by shipping a schema.** Referencing
  another provider's resources is all cross-calling *is*. There is no separate
  offer to make, and no reason for the target to opt in.
- **Several providers may provide the same resource.** `certificate` may come
  from `network` or from someone else, so the consumer must be able to name
  which one it means.
- **Extension is the reverse edge and needs no permission.** Any provider may
  add `certificate.myfield`. The origin (`network`) never learns; the schema
  already knows the field is only ever answered by the extending provider. What
  the extender needs is *access to the origin resource*, which is a dependency
  on `network` — declared by the extender, in the same way.

So both directions are declared by the **consumer**:

- **peer** dependency: I call resources owned by another provider
  (`os` → `network.socket`).
- **source** dependency: I extend another provider's resources
  (`my-provider` → `certificate.myfield`).

## Decision

Delete the centralized whitelist and `CrossProviderTypes`. Replace them with a
**consumer-side dependency declaration** in the provider's own schema, and turn
the coordinator's gate from a policy authority into a dependency check.

### Two phases, two artifacts

The dependency story splits cleanly into a build phase and an execution phase,
and they need different things:

| | needs | source |
|---|---|---|
| **build** | the peer's schema, to type-check references and detect the minimum version | the peer's `.lr` + `.lr.versions`, read directly |
| **execution** | the peer's identity and version floor, to find, fetch, and dispatch to it | the consuming provider's `config.go`, carried into its manifest |

The `.lr` file is **purely a build-time artifact**. Nothing at runtime reads it,
and nothing at runtime needs to: by then the question is not "does this resource
exist" but "which provider answers for it, is it installed, and is it new
enough."

This is deliberately scoped to peers that are present in the build environment.
Every cross-provider reference today satisfies that: all 37 call sites are
in-repo (`os` 18, `k8s` 2, `aws` 1, `oci` 1, `vsphere` 1), and the enterprise
repo has **no live cross-provider calls at all** -- no `.lr` imports, no
qualified peer type references, and `yara`'s two `CreateSharedResource("file")`
calls commented out above a `TODO` recording that they never worked. Its only
cross-provider surface is four `extend asset` blocks (`junos`, `fortios`,
`panos`, `networkdevices`), and `extend` resolves without loading the extended
resource's schema at all. Resolving a
peer that is not in the build environment is therefore not a use case we have,
and is left out until it is one.

### Declaring a peer

Two declarations, checked against each other.

**In the `.lr`, for the build:**

```
option provider = "go.mondoo.com/mql/providers/os"
import network

os.rootCertificates {
  []network.certificate(content)
  files []file
}
```

The import names the peer; resolution reads `providers/network/resources/network.lr`
and its `.lr.versions`, both of which are **committed**. (`*.resources.json` is
*not* — `.gitignore:19,23` excludes every provider except `core`. It carries the
same data, but only as a local build artifact, so it cannot be the build input.)

Reading committed source is what makes **same-PR co-evolution** work: when a PR
adds a resource to `network` and a caller in `os` in one change, the caller sees
it immediately, with no intermediate artifact and no build ordering between the
two providers. This is exactly how today's path-based import behaves, and it is
the property worth preserving.

The name replaces today's filesystem path
(`import "../../network/resources/network.lr"`). The path was never the
identifier — `resolve.go` already reduces it to a bare name
(`packName := strings.TrimSuffix(path.Base(importPath), ".lr")`) and everything
downstream keys on that name. Dropping the path deletes a derivation step rather
than adding a mechanism, and `Resolve`'s injected `readFile` is already the seam
where resolution plugs in.

The providers root a name resolves against is derived from the importing file's
own location — `providers/<name>/resources/<name>.lr` sits two levels below it —
so nothing needs configuring in the normal case. A tree that does not follow that
layout passes `--providers-root` to `mqlr generate`.

Where two providers share a name, the import binds a local alias:

```
import nw1 from "go.mondoo.com/mql/providers/network"
```

Usage is then normal (`nw1.certificate`). An import name that collides with a
local top-level resource namespace is a **build error** pointing at the alias
form; silent shadowing in either direction is worse than a one-line fix. No
collision exists today across the six current importer/import pairs
(`aws`, `oci`, `mondoo`, `os` -> `network`; `k8s` -> `os` and `network`).

**In `config.go`, for execution** — the declaration of record:

```go
Requires: []plugin.ProviderDep{
    {ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "13.3.0"},
}
```

The ID is what the runtime matches and fetches against; the name is what the
installer resolves (`Install(upstream.Name, …)`), so both are carried.

**The build cross-checks the two.** It reads `option provider` from the peer's
`.lr` and fails if it does not match the declared ID. That check is the whole
reason the two declarations can coexist without drifting — the failure mode that
killed `CrossProviderTypes`, whose `network` entry has named three non-existent
provider IDs for two major versions because nothing ever compared it to reality.

**`core` is declared like any other peer.** It is not a special provider at
build time, and it does not get an implicit import: a schema that names a core
type writes `import core`, and one that does not never loads core at all.

That is a smaller change than it sounds. Only two providers reference core types
-- `os` (13 `core.cpe`) and `vsphere` (1) -- so the whole migration is two lines.
`mondoo`'s `import core` was dead and is removed rather than converted.

The alternative, loading core whenever a schema happens to mention it, was
built and discarded. It made 79 providers pay for two, and it broke providers
built outside this tree, which have no `core.lr` under their own providers root
and no reason to want one. Worse, it hid a real error: the import is what tells
codegen that the `core.` in `core.cpe` is a pack qualifier rather than part of
the name, so a missing import silently emits `types.Resource("core.cpe")` for a
resource actually called `cpe`. Auto-supplying the import conceals that; an
explicit one makes it a build error naming the missing import.

Core's **runtime** globality is untouched and is a separate question: its
resources stay resolvable everywhere, which is the namespace rule ADR 031
keeps. Only the build-time declaration becomes explicit.

**Extensions may name the peer too.** `extend core.asset` is the qualified form
of `extend asset`. The qualifier is checked against the peer's resource list and
then stripped, so the result is byte-identical to the bare form. The bare form
stays legal and unchecked -- it is what every extension in this repo and in the
enterprise providers uses -- but it is also unverifiable: `extend asset` with a
typo silently defines a new resource, where the qualified form fails the build.
Naming the peer is what makes the check possible.

**The import is the declaration for both kinds of use.** A peer is reached two
ways -- as a type in the `.lr`, and as a string literal in Go -- and one import
licenses both. `os` uses `core` in both directions at once: it names `core.cpe`
as a type 13 times in `os.lr` *and* makes 14 Go-side `CreateSharedResource("cpe")`
/ `GetSharedData("cpe")` calls. Neither kind of use implies the other, so a peer
called only from Go still needs the import even though nothing in the `.lr`
mentions it, and the reference scan that derives version minimums has to read
both sources (see Version constraints).

#### Fix the dependency ID while we are here

**Status: done.** Landed ahead of the rest of this ADR, alongside the v14
provider-ID change, for the reason given below.

`Schema.Dependencies` already existed and was already derived from imports, but
the `Id` it recorded was wrong. `lrcore/schema.go` built it as
`strings.TrimSuffix(ast.packPaths[dep], "/resources")` — the peer's **Go package
path**, not its provider ID. When this ADR was written the two differed:

| source | value (pre-v14) |
|---|---|
| `network.lr` `option provider` | `go.mondoo.com/cnquery/v9/providers/network` |
| `network/config/config.go` `ID` | `go.mondoo.com/cnquery/v9/providers/network` |
| `os.resources.json` → `dependencies.network.id` | `go.mondoo.com/mql/v13/providers/network` |

The one field that exists to name a peer at runtime held a string no provider
answered to, and `Lookup`'s name-based fallback silently absorbed it on every
run.

It now reads the peer's `option provider`, captured during import resolution as
`LR.packProviders`. This is also the proof that the `.lr` carries everything the
build phase needs to hand off — including the runtime identity.

**Why it could not wait for the rest of this ADR.** The v14 change that made
every provider ID version-less also made `go_package` minus `/resources` and
`option provider` byte-identical for all 81 providers. The wrong derivation
therefore started returning the right answer, and the bug became invisible —
undetectable by inspection and untestable against real providers, while still
being one divergence away from returning garbage again. The fix is pinned by
`TestSchemaDependencyID` in `lrcore/lr_test.go`, whose fixture deliberately
gives the peer a `go_package` unrelated to its provider ID so the assertion
cannot pass on the derived value.

### Version constraints

The minimum is **detected at build and reconciled with what the author
declared**, rather than being either purely computed or purely hand-written.

Detection: collect each peer's reference set — `.lr` type references **plus**
`CreateSharedResource`/`GetSharedData` string literals in Go, since the largest
call group (`os` → `cpe`) exists only in Go — then resolve each reference against
the peer's `.lr.versions` (committed, one entry per resource and field) and take
the maximum.

Reconciliation against `config.go`:

- **Missing** → create it.
- **Lower than detected** → the declaration is wrong; suggest, or fix it
  directly.
- **Higher than detected** → accept silently. Deliberately over-constraining is
  legitimate and the author may know something the scan does not.

The **maximum is optional and usually unset** — we have no good rules yet for
predicting where a peer's API will break. It is authored when someone has a
reason.

**Build checks existence; runtime checks version.** This split matters because
the two phases see different truths. Mid-PR, a newly added resource in `network`
carries the next-patch version in `.lr.versions` (say `13.4.0`) while
`network`'s `config.go` still says `13.3.0` — CLAUDE.md forbids bumping it in a
feature PR. A version comparison at build would compute `min(network) = 13.4.0`,
compare against the locally-built `13.3.0`, and fail with the resource sitting
right there. So the build asks only *does `network.newthing` exist in the peer's
schema*, which is exact when both providers are in one tree. The version
constraint is checked at runtime against the **installed** peer, the only place
a version can genuinely disagree with reality.

The co-evolution case then resolves correctly through the rules above: detected
min (`13.4.0`) exceeds the declared min, so the build raises `os` to `13.4.0`,
which is right — `os` really does need it.

**This imposes no release ordering.** Providers ship together:
`release-providers.yml` defaults to `providers/*/` under one concurrency group
and runs `version update --increment=patch` across all of them in a single PR,
triggered on release publish. The arithmetic closes exactly — a new `network`
resource is recorded in `.lr.versions` at the next patch (`13.3.1`), the build
writes `os` that same floor, and the release bumps `network` by one patch to
`13.3.1` — so the floor equals the released version and both are published in
the same event. Nothing is released during the merge-to-release window, so
there is no interval in which a shipped `os` names an uninstallable `network`.

The one case that does break is a **manually dispatched partial release** that
names `os` and omits `network`. That is not an ordering constraint but a
subset-selection hazard, and the release tooling can check it: refuse a
provider set that leaves a declared floor unsatisfiable.

Two edges. A namespace-only root such as `openpgp` or `pkix` carries no version
because it has no fields, and must be treated as **not a valid reference
target** rather than as version 0, so a typo like `network.pkix` fails instead of
validating. And when the installed peer is *older* than the declared floor, the
reference is simply absent from its schema — that must report "your installed
peer predates the required version," not "resource not found."


### Peer versus source is derived

Nothing declares which kind a dependency is. A provider that writes
`extend <peer resource>` has a source dependency on that peer; one that only
references its resources has a peer dependency. The parser already records this
as `IsExtension` (`providers-sdk/v1/resources/schema.go:38`).

The distinction matters for installation, not for permission — see below. The
source direction carries more weight than it first appears: extending an ADR 031
**root** resource is how a provider declares it supports a whole class of asset,
which is what replaces the whitelist for user-issued queries.

### Resolution is lazy; peers are optional

A declared peer is **not** an install requirement. If the call path is never
taken, the peer is never needed, and the coordinator already behaves this way:
`addProvider` → `GetRunningProvider` starts a provider only when a lookup
reaches it. When a lookup does reach one, the declaration is what tells us
which provider to resolve and at what version.

For validation runs, an opt-in flag resolves and installs every declared peer
up front.

**Source dependencies never need forcing.** An extending provider is only
reached when someone queries the extended field, at which point the origin is
present by definition — it owns the resource being extended.

### The gate becomes a dependency check

One predicate, used by **both** dispatch paths:

```go
// allowsCrossCall reports whether the connected provider declared a dependency
// on the provider that owns `resource`.
func (r *Runtime) allowsCrossCall(owner string, resource string) (declared bool, legacy bool)
```

- `providers/runtime.go:1095` — replaces the
  `stringx.Contains(crossProviderList, …)` test.
- `providers/runtime.go:1244` — the same predicate in `lookupFieldProvider`,
  which has no check today.

**Matching is on provider ID**, and works precisely because of the ID fix above.
`info.Provider` is stamped from the owning `.lr`'s `option provider`
(`lrcore/schema.go`), and a provider's `config.go` `ID` is the same string — so
once `Requires` declares that ID and the build verifies it against the peer's
`.lr`, gate matching is an exact comparison with no normalization.

This holds as of v14. Before the fix a third string was in play — the
`packPaths`-derived `go.mondoo.com/mql/v13/providers/network` in
`Schema.Dependencies` — which matched neither of the other two. Reading
`option provider` collapsed the three to one, which is what makes ID viable as
the key instead of falling back to `Name`. `Name` is still carried, because
installation resolves by name (`Install(upstream.Name, …)`), not by ID — and
because it is what lets a v14+ engine resolve a dependency declared by a
provider built before the ID change.

The legacy whitelist keeps its own ad-hoc string matching for the v14 union
window, and is deleted with it.

Three existing pre-gate bypasses are preserved unchanged: the
`info.Provider == ""` bridging case (`:961`), the already-connected
short-circuit (`:970` / `:1161`), and `plugin.StaticProvider` (`:974` /
`:1150`).

### The two directions cover two populations

The gate sees two kinds of traffic, and the declaration model's two directions
map onto them exactly — peer for one, source for the other.

**Population 1 — provider calls provider.** `os` building `network.socket`. A Go
call site exists and the calling provider declares a **peer** dependency.

**Population 2 — a user query names another provider's resource on the current
asset.** There is no call site and no calling provider; the *user* made the call
at the keyboard. This is not hypothetical, and it is why `ai`, `ipinfo`, `yara`,
and `networkdiscovery` are whitelisted at all — no in-repo Go code calls any of
them:

```
$ mql run local -c "ipinfo.city"
ipinfo.city: "Los Angeles"

$ mql run local -c "aws.regions"
incorrect provider for asset, not adding go.mondoo.com/mql/providers/aws
```

Both run against the same `local` (os) asset and take the same path —
`llx/llx.go:713` → `Runtime.CreateResource` → `lookupResourceProvider` → the gate
at `:1020`. `ipinfo` resolves because it is whitelisted; `aws` is rejected by the
same check that gates Go-side calls.

Population 2 is what **typed roots** are for, and it is served by the **source**
direction. Every connection declares a root resource (ADR 031), and a provider
that supports some class of asset says so explicitly by **extending that root**.
That extension is a source dependency: declared by the extending provider,
needing no permission from the root's owner, with the schema already knowing the
field is only ever answered by the extender. `ipinfo` extends the root a local
connection exposes, and the gate then sees a declared dependency rather than a
whitelist entry.

So the whitelist's two jobs are replaced by the two directions of one model:

| population | who declares | direction |
|---|---|---|
| provider calls provider | the calling provider | peer |
| user query on an asset | the augmenting provider | source (root extension) |

Both are consumer-side declarations in the sense that matters: the provider that
wants the relationship declares it, and the provider being reached never
consents and never learns.

Extending a root converts a global name into a field on that root, which is a
user-visible change to how these queries are written — and is precisely ADR 031's
namespace rule ("v15: root-chaining with only `core` global"). It therefore rides
the same v14-warn / v15-enforce window as everything else here. No shipped
content in `content/` uses these providers, so the in-repo migration surface is
zero and the warn window exists for customer queries and policies.

### What the coordinator keeps doing

Brokering stays centralized, and should. The coordinator is the only process
that sees all providers; it owns lazy start, connection reuse, the asset clone,
and dispatch. The change is narrow: it stops being the *authority on policy*
(the hardcoded list) and becomes a *reader of declarations*. Providers never
talk to each other directly; every cross-call still flows through the
coordinator, so recording/replay, upstream config, and feature flags continue
to work unchanged.

### Enforcement timeline (v14 → v15)

Moved here from ADR 031 point 5, because the rule is enforced at the
coordinator gate (`providers/runtime.go:1095`) — this ADR's surface — and
because it is unenforceable without the declaration form defined above.

- **v14:** an undeclared cross-provider call still resolves, but warns. The
  gate accepts a declared dependency **or** the legacy whitelist, and logs when
  only the legacy path matched. On the field path (`:1244`), which allows
  everything today, the predicate is **log-only**. This surfaces every missing
  declaration without breaking a single user.
- **v15:** undeclared cross-provider calls no longer resolve, on both paths. The
  whitelist is deleted, including both legacy-ID blocks. (`CrossProviderTypes`
  is already gone — it went with the v14 provider-ID change, since nothing read
  it and keeping it bought nothing.)
- **Stays legal in both:** providers **extending** each other's resources with
  new fields, and any call covered by a declaration — a peer import (population
  1, this ADR), a root extension (population 2, via ADR 031), or a typed field
  forward-reference such as `running asset<mcp>` (cross-asset, ADR 031).

All declaration forms share one enforcement date, so the v15 cutover must not
land until every cross-called provider carries one. That set is smaller than it
looks: the enterprise repo has **no live cross-provider calls** and its four
`extend` blocks all use the bare `extend asset` form, which needs no import and
does not load the extended resource's schema. They keep working untouched; they
would only need `import core` if they moved to the qualified `extend core.asset`
form or started naming a core type. The whitelist can retire from `mql` alone;
what the enterprise providers need is root extensions for population 2, not peer
declarations.

ADR 031 keeps the **namespace** half of its original point 5: the global
namespace narrows to `core` and everything else chains off a typed root. That
migration is 031's to sequence, and population 2 rides it.

## Consequences

**Positive**

- A provider's dependencies ship with the provider. Adding a cross-callable
  provider touches no core code and needs no core release.
- The declaration is a dependency, so it carries version information the
  consent model had no place for. A call to a field that does not exist at the
  version you claim to support becomes a build error rather than a runtime null.
- Both dispatch paths get one predicate. Today `CreateSharedResource` is gated
  and `GetSharedData` is not, which means half of cross-provider traffic is
  already unpoliced.
- ADR 031's v15 rule becomes enforceable. It currently deprecates a class of
  call for which no declaration form exists, which would strand 35 shipped call
  sites.
- The module-path problem disappears. Name matching is immune to the
  cnquery→mql rename and to `/vN/` variants, and the inverted `FIXME:
  DEPRECATED` blocks stop being load-bearing.
- Declarations are introspectable: `mql providers list` can show what a provider
  depends on, and CI can diff declarations against actual usage.
- The `.lr` stays a build-time artifact and the manifest a runtime one, so
  neither phase carries data it cannot act on.
- It fixes `Schema.Dependencies[].Id`, which today records a Go package path
  where a provider ID belongs.

**Negative / risks**

- **`.lr` grammar change.** The import form changes for every provider that has
  one. In practice the peer schema is loaded the same way whichever form named
  it, so the existence checks in `lrcore/go.go` needed no rebuild -- but they did
  need extending: an unknown pack qualifier previously fell through to treating
  the whole dotted name as a local resource, which is what let a missing import
  emit `types.Resource("core.cpe")` silently. Two `TODO`s in that file recorded
  the gap.
- **Peers must be in the build environment.** Resolution reads the peer's `.lr`
  directly, so a provider outside the build tree cannot be depended on. No such
  case exists today, and supporting one means shipping a resolvable schema
  artifact — deferred until there is a use case.
- **Retroactive ambiguity.** Installing a second provider that also provides
  `certificate` can change what an existing query means. Mitigated by the
  consumer always naming the peer, so the reference is resolved by declaration
  rather than by whatever happens to be installed.
- **Late constraint failure.** Lazy resolution surfaces a version mismatch
  mid-query rather than at connect. Mitigated by validating eagerly at connect
  for peers that are already installed; only genuinely unresolved peers fail
  late.
- **Detected minimums can outrun releases.** A co-evolution PR raises a caller's
  floor to the peer's unreleased next-patch version, so the peer must be released
  at or before the caller. Between merge and that release the declared floor
  names a version nobody can install.
- **Population 2 is a user-visible change.** Queries like `ipinfo.city` on a
  local asset become root-chained. No shipped content is affected, so the blast
  radius is customer queries and policies, covered by the v14 warn window.
- A missing declaration turns a working cross-call into a runtime error at v15.
  Mitigated by the v14 warn window and the CI check.

## Implementation status

**Steps 1-4 of 5 have landed; step 5 is the v15 cutover and is deliberately
not done.** What exists today:

**Declaration, build side (step 1).**

- The `.lr` grammar accepts all three import forms (name, aliased-by-provider-ID,
  legacy path), resolved by name under a providers root derived from the
  importing file, with `--providers-root` to override.
- The six in-tree imports use the name form. `core` is an ordinary declared peer.
  Qualified `extend <pack>.<resource>` is supported and checked; the bare form
  stays legal and unchecked.
- An unresolvable pack-qualified type is a build error naming the missing import,
  closing the hole where a missing import silently emitted
  `types.Resource("core.cpe")`.
- `Schema.Dependencies[].Id` records the peer's `option provider` (landed earlier,
  with the v14 provider-ID change), and now records `core` like any other peer.
  The guard that keeps a builtin from being downloaded moved to the install
  decision, where it applies to every builtin rather than to the name `core`.

**Declaration, execution side (step 2).**

- `Requires []ProviderDep{ID, Name, MinVersion, MaxVersion}` on the manifest.
- Detection derives each peer's floor from its `.lr.versions`, reading both `.lr`
  type references and Go `CreateSharedResource`/`GetSharedData` literals -- the
  largest call group (`os` -> `cpe`) exists only in Go.
- Reconciliation against `config.go` (parsed with go/ast) yields create / raise /
  accept / unused. Reported by `mqlr generate`, gated by `--fail-on-dep-drift`,
  which every provider passes today.
- Declared floors sit at `lrcore.SupportedBaseline` (`13.0.0`) rather than at the
  raw introduction versions, which are all `9.x`.
- `os`, `k8s`, `aws`, `oci` and `vsphere` carry declarations; `mondoo`'s
  `import network` was dead and was removed.

**Enforcement (step 3).**

- The resource-path gate is `declared || legacy`, and logs every call that only
  the legacy whitelist allowed. Each of those is a missing declaration; when the
  log goes quiet for a release the whitelist can go.
- The field path carries the same predicate as a warning only. It allows
  everything today, so enforcing it now would break callers the resource-path
  gate never saw; the log measures that population first.
- A started peer is checked against the caller's declared floor. This is the
  runtime half of the split: the build checks a referenced resource *exists*,
  the runtime checks the installed peer is *new enough*.
- Declarations ride on `RunningProvider`, so neither gate pays a coordinator
  lookup per call.

**Checks (step 4).**

- `--fail-on-dep-drift` fails a provider build on an undeclared peer, a floor
  below what the references need, or an import nothing references. It is on by
  default through `LR_DEP_FLAGS`, so every provider build in CI enforces it;
  `LR_DEP_FLAGS=` disables it locally mid-change.
- A call naming a resource that is neither this provider's nor a declared
  peer's is attributed against the whole tree and reported with the import it
  needs. Attribution parses every provider, so it runs only when there is
  something to attribute -- which today there never is.
- Declared floors are validated eagerly when dependencies are ensured, so a
  version mismatch surfaces as an install problem rather than mid-query.

What does **not** exist yet:

- **The whitelist still exists.** Both gates now consult declarations, but the
  legacy whitelist remains a valid way to pass the resource-path gate, and the
  field path only logs. Deleting the whitelist and enforcing the field path is
  the v15 cutover (step 5).
- **v15 cutover** -- deleting the whitelist, and sequencing with ADR 031's typed
  fields and the enterprise providers -- is untouched (step 5).

## Migration plan

1. **Done.** Added the name-based `import` form and the alias form to the `.lr`
   grammar, alongside the existing path form, and migrated the six existing
   imports. Made `core` an ordinary declared peer (`import core` in `os.lr` and
   `vsphere.lr`; `mondoo`'s was dead and went away), added the qualified
   `extend <pack>.<resource>` form, and made an unresolvable pack-qualified type
   a build error instead of a silently mis-named resource. `Schema.Dependencies[].Id`
   was fixed earlier, alongside the v14 provider-ID change.
2. Add `Requires` to the manifest, plus the build step that detects each peer's
   minimum from `.lr.versions` and reconciles it with `config.go` (create when
   missing, fix when low, accept when high). Add the `option provider` vs
   declared-ID cross-check.
3. **Done.** The resource-path gate accepts `declared || legacy` and warns when
   only the legacy path matched; the field path carries the same predicate but
   is log-only, since it allows everything today. A started peer is checked
   against the caller's declared floor (`checkPeerVersion`), which is the
   runtime half of the build-checks-existence split. Declarations are carried on
   `RunningProvider` so the check costs no coordinator lookup on the field path.
4. **Done.** `--fail-on-dep-drift` covers both halves -- a call with no import
   and an import with no call -- and runs on every provider build via
   `LR_DEP_FLAGS` in the Makefile, so CI gets it without a separate job.
   Declared floors are validated eagerly for peers that are already installed
   (`validateDeclaredPeers`), which is the mitigation named under Late
   constraint failure.
5. After one release with zero "legacy-only" log hits, delete the hardcoded
   whitelist and `CrossProviderTypes`. This is the v15 cutover, and it must be
   sequenced with ADR 031's typed-field declarations and with the enterprise
   providers' declarations so all forms are enforced together.

Steps 1–4 are the v14 line. Step 5 is v15.

## Future work

Neither of these is in scope, and both are named here so the design leaves room
for them.

**Generic resources ("virtual packages").** Today a consumer names a concrete
peer. In future a consumer will be able to depend on a *generic* resource — an
interface, shipped as a JSON-only provider that defines the contract and holds
the context for it, which several concrete providers may satisfy. Depending on
a generic resource works like depending on a peer, and resolution picks whichever
installed provider satisfies the interface. This is the same shape as an Arch
Linux virtual package, and it is what lets a policy ask for `certificate`
without caring who supplies it.

**Reverse calls.** A lazily-started peer is currently connected with a `nil`
callback (`providers/runtime.go:1107` and `:1253`), so it physically cannot call
back into the coordinator. Provider-level dependency cycles are legitimate and
expected; what must be guarded is re-entering the **same resource instance** —
the `(resource, __id)` pair that already forms the runtime cache key. Passing a
real `providerCallbacks` is what makes that guard necessary, and both are
deferred to a follow-up.

## Alternatives considered

- **Offering-side consent declarations** (the earlier draft of this ADR). Each
  provider would declare `Offers` with a mode and a set of caller connection
  types, and the coordinator would gate on that consent. Rejected: providing a
  schema is already the offer, so the consent layer is redundant; extension
  explicitly does not need the origin's permission; and a consent model has no
  place to put version constraints, which is the part that actually prevents
  wrong answers.
- **Keep the whitelist, move it to a config file.** Still centralized, still a
  release-coupled edit, and still carries no version information. Rejected.
- **Declare dependencies in only one of the two places.** `config.go` alone
  leaves the build with no way to resolve `network.certificate`; the `.lr` alone
  leaves the runtime with no provider ID to fetch and dispatch against. The two
  phases genuinely need different data, so both declarations exist — and the
  build cross-checks them, which is the safeguard `CrossProviderTypes` never had.
- **Constraints on the `.lr` import line.** Rejected: the `.lr` is a build-time
  artifact and the constraint is a runtime fact, so it would put the version
  where nothing reads it. Detection reads `.lr.versions`; the declaration lives
  in `config.go`.
- **Resolve peers through `*.resources.json`.** It carries both schema and
  version data, but `.gitignore:19,23` excludes it for every provider except
  `core`, so it is a local build artifact. Depending on it would break fresh
  clones, impose a build ordering between providers, and silently serve a stale
  schema — and it would break same-PR co-evolution, the case the `.lr` route
  exists to preserve.
- **Direct provider-to-provider gRPC (skip the coordinator).** Breaks
  recording/replay, upstream config propagation, and connection reuse, and
  would require every provider to discover every other provider's socket.
  Rejected; brokering through the coordinator is the right call.
