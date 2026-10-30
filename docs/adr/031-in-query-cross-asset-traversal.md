# ADR 031: Typed asset roots and cross-asset resolution

## Status

Proposed

## Context

[ADR 030](030-asset-tree-anchored-relationships.md) added a native `asset` value
(returned by `running` on `*.mcpServer` resources) and opt-in `mcp-servers`
discovery, and explicitly deferred *live cross-asset traversal*:

```
claude.code.mcpServers.where(name == "dummy").running.tools
```

Investigating that traversal surfaced a bigger realization: cross-asset
resolution should not be a special case bolted onto MQL — it should be the **core
model**. Rather than a flat global resource namespace per runtime, **every asset
exposes a typed root resource**, an `asset` value is **typed to that root**, and
resolving into another asset is just chaining off its root. `running.tools` is the
first concrete application of that foundation.

### The direction (north star)

- **Every asset has a root resource type.** After connecting to (or otherwise
  resolving) an asset, its resources chain off a typed root instead of the flat
  global namespace we have today. The small set of truly global resources (the
  `core` provider) stays global; everything else hangs off a root.
- **`asset` values are typed to a root.** `running` returns `asset<mcp>` — an
  asset value parameterized by the `mcp` root resource type — so `.tools`,
  `.prompts`, … type-check and chain against that schema.
- **Composition is recursive.** A resource in one asset's tree can itself be an
  `asset<root>` that is the typed root of the *next* runtime. Federation nests
  arbitrarily: `A … .running.<…>.running.<…>`.
- **Resolution is backend-agnostic — recording can jump in.** Resolving
  `asset<root>.field` does NOT require a live local connection. The recording
  layer (especially **upstream** recording) can serve the data for an asset we
  can't or won't connect to locally. Live connect is one backend; recorded data
  (local or upstream) is another. The **ADR-030 anchor is the identity** the
  recording layer keys on.
- **The root says what you can ask.** A root is not a convenience handle, it is
  the type that bounds the query. That is what makes a platform-specific root
  worth having, and what lets a bundle derive which assets it applies to instead
  of being told by hand.

## Mechanics (grounded in the current code)

**The connect-and-query primitives exist** (discovery uses them today):
`Coordinator.RuntimeFor(asset, DefaultRuntime())` (`providers/coordinator.go:141`) +
`Runtime.Connect(&plugin.ConnectReq{Asset, Features})` (`providers/runtime.go:349`),
provider selected by connection `Type` via `EnsureProvider(ConnType)`
(`runtime.go:313`); canonical recipe in `discovery/discovery.go:52`
`createRuntimeForAsset`. Runtimes dedupe per asset by Mrn/PlatformIds
(`coordinator.go:191`); the caller closes B's runtime (`Runtime.Close()`
`runtime.go:94`, as `discovery/asset_explorer.go:250` does).

**Recording already holds multiple assets keyed by identity.** `EnsureAsset` keys
by Mrn/PlatformIds (`providers-sdk/v1/recording/recording.go:337`) and
`GetAssetData(assetMrn)` exists (`recording.go:547`); `providers.Runtime` already
resolves fields **recording-first** before hitting the provider
(`runtime.go:606`).

**A recording-backed runtime for another asset already exists.** The `mock`
provider is exactly that: `Connect` picks the provider for the recorded asset,
`MockConnect`s it, and points the runtime at a recording (`providers/mock.go:196`) —
and for an asset with an MRN it builds an `Upstream` recording for *that* MRN
(`mock.go:136`), which is the upstream-jump-in case, already shipped. Two
consequences: recorded and live resolution are the same code path with a different
connection on the target asset, and the missing piece on the local leg is small —
`Connect` takes `assetRecordings[0]` (`mock.go:182`) rather than the asset it was
asked for.

**The wall — llx cannot originate a connect.** A builtin reaches only
`e.ctx.runtime`, typed `llx.Runtime` (`llx/runtime.go:11`), which has no
coordinator and no `Connect`; `llx` does not import `providers`. So federation
must be driven from **`providers.Runtime`** (host-side, reaches coordinator +
`exec` + recording), not from llx.

**Execution reads field types from the runtime's own schema.**
`runResourceFunction` takes `fieldType` from `runtime.Schema().Lookup(...)`
(`llx/builtin.go:854`), not from the chunk. A bundle therefore executes correctly
against a schema *more concrete* than the one it compiled against. This is what
makes both compile-time degradation and root narrowing single-pass.

**Cross-provider routing today is same-asset only.** `lookupFieldProvider`
(`runtime.go:1066`) + the StoreData bridge (`runtime.go:591`) route a field to its
owning provider, but every sibling connect derives from `crossProviderAsset()` — a
clone of **A's** connection (`runtime.go:264`). Cross-*asset* resolution does not
exist; this ADR adds it.

**No `mcp`/`ai` provider in this repo** — `Type:"mcp"` is served by the enterprise
`ai` provider, so live `.tools` needs it installed; in-repo automated tests can't
depend on it (verification is interactive). Recording-backed resolution can be
tested in-repo.

## Decision

Adopt the typed-root model. The earlier "widen `llx.Runtime` with a dynamic
`RunOnAsset`" option is dropped as the target: it would entrench an untyped escape
hatch we'd have to unwind.

### 1. Typed asset values, root referenced by name

Extend the type system so `types.Asset` is parameterized by a root resource *type
name*: `Asset("mcp")`, mirroring `Resource(name)`. The declaring provider
references the root **by name only** — `os` declares `running asset<mcp>` without
needing the `mcp` schema at build or codegen time. The name is a forward
reference: we know the next resource is supposed to be an `mcp` even though `mcp`
is not defined in the `os` schema. This is a declared cross-provider type
reference, legal under the v14/v15 rules in point 7.

**The root name is not in the value.** It is a type parameter, so it rides the
*type* and reaches the executor on the chunk the compiler emits. The value payload
stays the ADR-030 anchor `(resourceType, resourceId)`, plus the target stub of
point 5. **No identifiers for resolving the target MRN are needed on the value**:
the target is found through the reverse edge recorded on the target asset itself
(`inventory.Asset.Relationships`, written by
`providers/os/resources/mcp_discovery.go:92`), matched on the anchor plus the host
asset. Anchor stays the correlation key; secrets are never in the value.

### 2. Compile-time behavior: always know the name, degrade on the schema

Because the root name is declared at the field, the compiler always knows the
chain's root type. If the referenced schema is **loaded** (e.g. `ai` installed) →
`.tools`/`.prompts` type-check statically. If **absent** → **degrade and warn**:
the root is known, the member is emitted untyped, and its type resolves from the
executing runtime's schema. That is the compile-here / run-there case, and it works
because of the execution property above.

The limit: a degraded member is only usable as a terminal value.
`running.tools.first.name` needs a real type to compile, because blocks and further
chaining do. Arguments are refused rather than passed unchecked, since there is no
init signature to check them against. A CLI call to an *uninstalled connector* is
the separate, pre-existing "provider not installed" failure, out of scope here.

### 3. Root taxonomy

The root is grounded in the **connection**, not the platform: different connection
types expose different roots. It is declared twice, because the two consumers ask
at different times:

- **Statically**, as `Root string` on **`plugin.Provider`**
  (`providers-sdk/v1/plugin/start.go`), so it lands in the provider's
  `<name>.json` and is readable from the coordinator **without starting the
  provider or connecting**. For a provider serving several platforms this can
  only be the union (`os.any`), and it is what a disconnected compile gets.
- **By the connection**, as `ConnectRes.Root`, which is what the connection
  actually exposed. Only connecting reveals the platform, so only the connection
  can say `os.linux` rather than the union. `Runtime.AssetRoot()` prefers it and
  falls back to the declaration.

The connection's answer is a **refinement**, not a disagreement: the concrete
root is a member of the declared union. That is why `mql shell local` bounds a
query by the platform it is actually on — `_.registrykey` fails to compile with
`this asset is rooted at os.linux; registrykey is available on os.windows`
instead of answering with an unset field. A disagreement means a root outside the
union, which is the cross-asset case in point 5 and is an error there.

Not on `Connector`, which is where this ADR first put it: the runtime resolves the
root from the connection *type* it holds (`conf.Type`), and types do not map onto
connectors — the `os` provider ships **8 connectors covering 14 connection types**
(`docker-image`, `tar`, `registry-image` have no connector of their own, because
one connector mints several types at parse time). A provider that grows two roots
gets a per-connection-type override, additive to this field.

For the `os` provider the taxonomy is:

```
os.base                universal root: what every OS has
├── os.unix            unix-family facilities
│   ├── os.linux       linux-only (kernel, LSM, storage stacks)
│   └── os.macos       macOS-only
└── os.windows         Windows-only
os.any                 the union receiver; what the provider declares
```

- **`os.base` is the universal root.** Everything present on every OS.
- **Family roots embed their parent** and carry only OS-provided facilities of
  that family.
- **`os.any` is the compile-time receiver**, carrying the union of all roots. It is
  what the provider declares and what `_` resolves to.
- **Nothing is attached to bare `os`.** It is not declared at all: the schema
  builder creates it as an `IsExtension` namespace node for every dotted name
  (`lrcore/schema.go`), which is exactly the empty namespace we want.

**Placement is the metadata.** There is no `@platform` annotation and there must
not be one. To add a resource you have to place it, and placement is the claim
about where it exists — a claim that cannot drift from the schema, unlike an
annotation. The classification already exists in the code as
`platform.IsFamily(...)` guards (21 implementation files in `os`; e.g.
`kernel.go:25` guards linux/darwin/bsd/aix, so `kernel` is unix-family), so
placement is derived, not invented. A resource with no family guard is universal by
construction.

**Attachment is by alias, not by field.** `alias os.base.packages = packages`, and
the schema builder's bridging turns a dotted resource name into an implicit field
on its parent, so `os.base.packages` becomes a field of `os.base` and `_.packages`
resolves. Three reasons this beats fields with Go accessors:

- **It carries arguments.** `file`, `command`, `service`, `python` and ~30 more
  take init args, which a field accessor cannot pass. `_.file("/etc/hostname")`
  works only because the alias resolves to the resource itself.
- **Nothing moves.** An alias adds a name; every global path keeps working, so the
  namespace migration happens in the direction that cannot break content.
- **No `.lr.versions` entries and no generated Go.** Aliases share one
  `ResourceInfo` with their target.

Two limits: aliases must stay **contiguous** in the `.lr` (a comment between two of
them fails the parse, and one directly above the block is read as its doc-comment,
so the explanation lives on the root's doc-comment instead), and the alias name
appears as a second key in `resources.json`, which consumers already detect by
comparing the key against the entry's `id`.

**The axes are orthogonal, so leaves compose.** The real taxonomy is family ×
asset kind (host, container, image, filesystem): `packages` and `files` are valid
on an image, `uptime`, `services` and `processes` are not. The kind axis subtracts
the same set on every family, and the family axis is indifferent to kind, so mixins
compose with multi-embed rather than enumerating N×M duplicated roots (verified: a
resource with `embed os.base` and `embed os.live` parses and carries both). A
third, non-orthogonal axis (privilege, connection capability) would be a redesign;
none is foreseen.

**Build-time guards**, enforced in `lrcore` at generate time next to
`validateTypeParameters`. Each stops generation, so a provider that violates one
cannot be published:

- **One member name across roots carries one type.** Otherwise the union cannot
  type it.
- **A root member does not shadow a different global resource.** A root member
  that is an alias of the global of the same name is the normal case and is fine;
  a root member that means something *else* under a global's name is what makes
  the two namespace precedences in point 7 disagree. Forbidding it is what lets
  v15 flip the precedence without changing what any query means.
- **A root member is not named like a language construct** (`props`, `if`,
  `switch`, `return`, `_`, …). With a binding in place the bound identifier is
  tried before those, so such a member would shadow the language itself. Applies
  to root resources only; an ordinary resource may still carry such a field.

### 4. Root narrowing

`_` compiles against `os.any`, and the compiler **narrows** as members are
accessed: reading only universals leaves every root compatible, reading
`iptables` leaves `os.linux`. The narrowed set is recorded on the bundle as
`compatible_roots`, by the same accumulator pattern `mqlc/provenance.go` already
uses (`raiseMinimum` narrows a lattice as members are touched). At run time
`mqlc.SupportsRoot` answers whether an asset can execute it, and `ExecuteCode`
refuses one that cannot with `ErrRootMismatch` — a scoping answer the caller can
recognize, not a failure.

**Refusing is opt-in**, under `RootedNamespace` or by a caller asking
`SupportsRoot` itself. "Not applicable to this asset" and "this check failed" are
different answers, and a caller that cannot yet tell them apart would report the
first as the second; the scanner-side handling that skips the asset instead lands
with the cnspec work that consumes `compatible_roots`. Until then v14 execution is
unchanged and a mismatched member degrades as it does today.

Which resources are roots is stated in the schema by `@root`, the same way
`@global` states reachability without one. Narrowing needs the root *family*, not
just the declared union, and a diagnostic that names "the root that does carry
this" needs it too.

Three rules keep it honest:

- **Only members read off a root narrow anything.** A member of an ordinary
  resource says nothing about which asset a query is about, and neither does the
  global namespace — so v14 content that never touches a root records no
  requirement and runs everywhere, exactly as before.
- **The union is never in the set.** It carries every member by construction, so
  counting it would make every intersection non-empty. A bundle compiled against
  the union is still compatible with an asset that reports it, which is what a
  provider does before it refines its root per connection.
- **An empty intersection records nothing.** Content that deliberately spans
  platforms — one branch per platform — has no single root carrying all of it.
  Refusing it, or marking it runnable nowhere, would break that pattern, so it
  runs and each member degrades where it does not apply.

This is single pass. The chunk stays typed `os.any` and is never patched — which
matters, because checksums are computed incrementally as chunks are added, so
retyping the root retroactively would invalidate every checksum downstream. The
concrete root decides the *requirement*, never the dispatch.

Consequences worth stating:

- **Applicability becomes derived.** Today a policy declares
  `filters: asset.family.contains('linux')` by hand, and it can drift from what the
  query actually touches. Narrowing derives it from the query body.
- **Not-applicable is not passing.** Today `iptables` on Windows returns null and a
  policy scores it, which is the ADR-040/043 hazard where null becomes a passing
  verdict. Under narrowing the query is skipped instead, so reporting has to
  distinguish skipped from passed — the existing filter mechanism is that rail.
- Replacing cnspec's explicit filters with the derived requirement is a
  **v14-lifetime target, out of scope here**; explicit filters remain the fallback
  until then.

### 5. Cross-asset resolution in `providers.Runtime`, over one path

Resolving `asset<root>` means: find the target asset, get a runtime for it, ask
that runtime for the root resource. The backing is not a second mechanism — it is
**which connection the target asset carries**:

- **Recording (local file or upstream)** — the target is connected with a `mock`
  connection, which `providers/mock.go:118-208` already implements, including
  building an `Upstream` recording for a requested MRN. This is the
  un-connectable / no-coordinator path, and often the primary one.
- **Live connect** — the target carries its real connection (`mcp`) and
  `RuntimeFor` + `Connect` reach it.

Both are `Coordinator.RuntimeFor(target, parent)` + `Connect`, so recording-first
ordering is preserved by *choosing the target asset's connection*, not by two
resolution code paths.

**Identity persists, reachability is asked for.** `RuntimeFor` needs an
`inventory.Asset` with a connection, and the anchor alone does not carry one. An
earlier draft of this ADR put the target's connection stub on the `asset` value
itself; that is rejected. The value persists into recordings and upstream on
every `running` read, and identity is all that belongs in the stored data model
(ADR 030) - a connection config is not identity, it is how to reach a thing.

So the host asks for it, at the moment it connects and never before:
`ResolveAsset(resource_type, resource_id)` on `plugin.Service`, answered from the
resource the anchor names. `plugin.AssetSource` is the resource-side contract
(`MqlAsset() (*inventory.Asset, error)`), and the default implementation reads
the instance out of the connection's own resource cache, so a provider whose
resources implement it needs no other code, and one whose resources are not
assets answers nothing. The asset is built by the same function discovery uses
(`mcpConnectionConfig`, `mcp_discovery.go`), so ADR 030's forward/reverse parity
holds by construction rather than by discipline.

The cost is one RPC per distinct anchor - absorbed by the anchor cache, and
trivial next to the connect it immediately precedes. An earlier draft rejected
this call for costing "an RPC and a schema notion of 'this resource can mint an
asset'"; the schema already states that notion, because a field typed
`asset<root>` is exactly it. The callback channel was never an option -
`providerCallbacks.Collect` panics (`providers/runtime.go:857`).

**Never lookup-shop a foreign asset on the current runtime's recording.** The
`llx.Recording` API takes an `AssetRecordingLookup`, but only the local multi-asset
implementation honors it. `Upstream` is constructed per asset MRN
(`upstream_recording.go:26`) and answers every `GetResource` from its own asset,
ignoring the lookup — correct for what it is, and precisely why a foreign lookup
against it returns **the host's data under the target's name** rather than a miss.
Harmless while the two assets share no resource types; wrong data the moment they
do (host → container, both `os`, both with `packages`). Selecting a backing per
target asset makes that unrepresentable.

**This path is also the one imperative Go-side callers use**, exposed as
`Runtime.RuntimeForAsset(key, asset)` rather than as a parallel API. A second
connect path would bypass the recording-first ordering and make those assets
invisible to replay, as well as losing dedupe, parent ownership and the time
bound. The caller supplies the dedupe key because a freshly built asset has no
identity to key on: its mrn and platform ids are assigned by the connect the call
is about to make.

A **provider** wanting to expose a new asset (an `os` resource finding a
container image reference on disk) does not use that, and does not need a
callback to the host either: it declares a field typed `asset<root>` and
implements `plugin.AssetSource`, and the engine reaches the asset the same way.
That keeps the result queryable and chainable instead of a Go object only its
author can see, and it is why this needs no provider-side imperative API at all.
`docker.container.running` is the worked example.

This is *not* the same-asset cross-provider call that
[ADR 042](042-cross-provider-invocation.md) governs: no peer declaration is
involved, because creating a genuinely new asset is not calling another provider
for the asset you are already on.

### 5b. `asset` is a member of every root

`asset` is what a query asks for the platform, version and identity in front of
it. It is `@global`, which is right on the asset you connected to and silently
wrong one hop into another one: a bare mention resolves through the global
namespace to whichever runtime is executing, so `running { asset.platform }`
reported the *host* as `arch` for an Alpine container - the same shape of wrong
answer the `docker.container` embed produced.

So every root carries it, and the **schema builder attaches it** rather than each
provider declaring it. This is not a choice a provider makes: it is true of every
root and the shape is the one core defines, so restating it once per provider -
with a validator to catch whoever forgets - would be duplication guarding
duplication. A provider that declares a root gets `asset` without knowing this
exists.

The field names core's `asset` directly. An alias would have generated a
separate resource carrying only the part *that* provider extends onto it
(`os.base.asset` held the four fields os adds and none of the twenty core
declares), which then needs reconciling with the real one somewhere else;
naming the resource means there is only ever one of it. A provider that
deliberately declares its own `asset` member keeps it - the attachment fills a
gap, it does not overrule a schema.

Reached as a member, it resolves through the runtime the chain is bound to, so
on a cross-connected root it answers about that asset.

### 6. Top-level `_` is the connected asset's root

Inside a block, `_` already names the block's binding (`mqlc/mqlc.go:1492`). At the
top level there is no binding, so `_` used to fail with `cannot find resource for
identifier '_'`. It now resolves to the root the connection declares, so
`mql run local -c "_"` answers with the asset's root and `running { _ }` prints the
MCP root. One concept read from two ends: `asset<root>` is the root of *another*
asset, `_` is the root of *this* one.

The root reaches `mqlc` the way the downgrade catalog does: an optional interface on
the runtime (`llx.AssetRootSource`), type-asserted in `NewConfigFrom` — the same
shape as `llx.TranslationSource`. `_` compiles as the root resource itself, so
blocks, `where` and entrypoints work with no further wiring. It must not compile
by feeding the root's *name* back through identifier resolution: under a rooted
namespace that asks whether the root is a member of itself. Where the
provider declares no root, `_` keeps failing, with a message that says the
connection declares no root rather than pretending `_` is a resource name.

This is the shape the next point generalizes: `_` is an explicit way to say "the
root", and binding the root implicitly makes every bare identifier say it too, at
which point `_` needs no handling of its own.

### 7. Namespace evolution: every query is rooted

A query is really a block on the asset root — `assetRoot { …query… }` — and the
namespace it resolves against follows from that. This is what the flat namespace
has always been missing: `_.hostname` resolves and bare `hostname` does not
(`cannot find resource for identifier 'hostname'`), because `hostname` is a member
of the root and nothing binds the root. Binding it is the whole fix, and it needs
no new machinery: the compiler already tries the binding's members before the
global namespace inside a block (`compileIdentifier`), so this is setting
`c.Binding` at the top level. It also subsumes the special case for `_` in point
6 — with a binding present, `_` *is* the binding.

**v14 (default): global-first, root-fallback.** Resolve a bare identifier against
the global namespace exactly as today; only when it is not a global resource,
resolve it against the asset root. Three properties, all required:

- **Bit-identical bundles for content that compiles today.** Root-first would
  recompile `packages.list.length` as `os.linux` + field `packages` + …, a
  different chunk sequence and therefore a different checksum — and cnspec keys
  scoring continuity on that. Global-first changes nothing that already resolves.
- **Compile-once-run-many keeps working.** cnspec caches a resolved policy by
  `(policyMrn, assetFilterChecksum)` (`policy/datalake.go:85`), so one compiled
  bundle serves every matching asset. Root-first would bake one platform into a
  shared bundle.
- **`hostname` starts working.** It fails today, so nothing can depend on the old
  behavior.

**v14 with `RootedNamespace`: v15 semantics, early.** The feature flag (feature 23)
compiles rooted only: bare identifiers resolve against the asset root, the global
namespace is available only through resources marked `@global`, and a compile
without a root is an error rather than a silent fall back. It exists so the v15
model can be run and tested for the months before it becomes the default, rather
than arriving as a flag day. `MONDOO_FEATURES=RootedNamespace mql run local -c
"hostname"` answers, `registrykey` is rejected as not part of the tree, and
`time.now` still resolves because core marks it.

The mode also rejects a resource addressed by a global path that is not a root
member, `os.linux.packages` included: the root is the namespace, so a name is
reached through it or through `@global`, and finding what that breaks is what the
flag is for.

**v15: rooted by default.** The flag becomes the default and the fallback is
removed. A root is then required rather than optional, which is also when
supplying one becomes the caller's job (see below).

**Rooted bundles run on a v14 engine.** Code compiled under the flag (or by v15)
is ordinary resource-and-field chunks — `os.linux` then `packages` — and execution
resolves field types from the runtime's own schema, so a v14 engine runs it
unchanged. Verified: `os.linux.packages.list.length` and
`os.linux.file("/etc/hostname").exists` resolve today. The dependency is the
provider that ships the roots, not the engine: a v13 provider has `os.linux`
without the attached surface, which is precisely why v14's default stays
global-first.

**Where the root comes from**, in order:

1. The **connection** reports it (`ConnectRes.Root`) — the concrete platform root.
2. The **caller supplies** one. cnspec will, so a policy can state the root it
   targets; that replaces much of what platform filters express by hand today.
3. The provider's **declared union**, carried in the resources schema so a compile
   with no runtime can still reach it.
4. Nothing — and then v14 compiles against the global namespace as it always has.
   Under `RootedNamespace`, and in v15, this case is an error instead: rooted
   compilation without a root has nothing to resolve against.

**Marked globals.** A resource reachable without a root is marked `@global` in its
`.lr`. Core's resources carry the marking explicitly rather than being global by
provider, so the rule reads the same everywhere and nothing is global by accident
of where it lives: `asset`, `time`, `regex`, `parse`, `mondoo`, `uuid`, `cpe`,
`product`, `unicode` and `vulnerability.exchange`. Everything unmarked is expected
to be rooted.

**The declared root travels with the schema.** `option root` in the `.lr` is
recorded as `Schema.ProviderRoots` at generate time, so a compile holding only the
schema file — a policy bundle, a lint, an editor — can answer "does this hang off
the asset's tree" without a runtime. The coordinator stamps the same map from the
provider config for schemas that predate the option.

**A label is what the author wrote.** Reaching a member of the root costs chunks
nobody typed — the root, and one hop per embed — so none of them appear:
`hostname` is `hostname`, not `os.linux.unix.base.hostname`, exactly as `sshd` is
`sshd` whether or not `_` was spelled out. The root is labeled only when it is
itself the answer (`_`). The bundle records which root it was compiled against
(`asset_root`), which is what lets a reader tell an inserted chunk from an
authored one, and the global spellings label exactly as they did before.

**The non-rooted note.** Whenever v14 resolves a name globally that is not
reachable from the root and is not `@global`, the compiler records it on the
bundle as `unrooted_resources` — a list beside `MinProviderVersions`, so tooling
can show which parts of a bundle reach outside the asset's tree. The check runs on
the name that entered the namespace, not the leaf of a dotted path:
`sshd.config.params` enters as `sshd`, and a root carries `sshd`, never
`sshd.config`. A provider whose surface is fully attached produces an empty list,
which is what `os` does today. That is the same statement
[ADR 042](042-cross-provider-invocation.md) makes from the other side: the typed
field (`running asset<mcp>`) and the declared peer `import` declare a reach beyond
the asset tree at the schema level; this observes it at the query level. The note
is what makes the v15 cutover measurable instead of a guess.

**The flat `os` resource is deprecated on this line.** Its 13 fields (`name`,
`env`, `path`, `uptime`, `updates`, `lastUpdate`, `lastUpdateAge`,
`lastUpdateSource`, `rebootpending`, `hostname`, `hypervisor`, `machineid`, `date`)
are marked `@maturity("deprecated")` in v14 with `os.base.<field>` as the migration
target, and they **keep working**: v13 compatibility is mandatory, and the shipped
catalogs use six of them (`os.path` in 49 files, `os.machineid` in 18, `os.uptime`
in 14, `os.date` in 12, `os.hostname` in 10, `os.env` in 3, across cnspec content
and the policy repos). v15 migrates the policies, removes the fields, and leaves
`os` as the empty namespace node.

Each of them also carries `@replaced_by("os.base.<field>")`, which is the same
migration target as data rather than prose
([ADR 040](040-cross-version-type-migration.md#2-migrations-are-composable-directional-lenses--not-aliases)).
The compiler records every deprecated name a bundle reads on
`CodeBundle.deprecated_uses` and the CLI renders it against the root the query
compiled with, so someone running `os.hostname` on a connected asset is told
`os.hostname has migrated to hostname` - the spelling that works here - rather
than the schema path. That is the whole mechanism: no lens, no alias, nothing
that changes how `os.hostname` resolves. It resolves because the field is still
there, and in v15 it stops because the field is gone.

**Stays legal in both versions:** providers **extending** each other's resources
with new fields.

**Cross-provider call legality is not decided here.** Whether an undeclared
cross-provider call still resolves — and the v14-warn / v15-enforce timeline — is
owned by
[ADR 042](042-cross-provider-invocation.md#enforcement-timeline-v14--v15), because
it is enforced at the coordinator gate (`providers/runtime.go:1020`) and requires a
declaration form for *same-asset* calls (`CreateSharedResource`, 35 sites today)
that this ADR does not supply. The two declaration forms — typed field here, a
named peer `import` there — share one enforcement date.

## Resolution mechanics (the hook)

Where cross-asset resolution attaches, decided by reading the execution path rather
than from first principles.

**Only routing needs redirecting, not the schema.** `runResourceFunction`
(`llx/builtin.go:822`) reaches for the runtime exactly twice: `Schema().Lookup` and
`WatchAndUpdate`. The first is a non-problem, because `providers.Runtime.Schema()`
returns the coordinator's schema across all installed providers
(`providers/runtime.go:1295`) — `mcp` is already in it whenever `ai` is installed.
So the whole cross-asset question is *which runtime answers the field*.

**Two small additions to llx, neither of which can connect.**

```go
// A resource that names the runtime which answers its fields.
type RuntimeBoundResource interface {
    Resource
    MqlRuntime() Runtime
}

// Optional interface on the runtime, type-asserted at exec time — the same
// pattern as llx.TranslationSource and plugin.StaticProvider.
type AssetResolver interface {
    ResolveAssetRoot(v *AssetValue, root string) (Resource, error)
}
```

`runResourceFunction` picks `rt := e.ctx.runtime`, then `rt = b.MqlRuntime()` when
the bound resource is a `RuntimeBoundResource`. That is the entire routing change.
`providers.Runtime` implements `AssetResolver` and owns every part of the
federation, which is the constraint the wall above sets.

**The chain compiles to a deref chunk, not a field-on-asset chunk.**

```
running     → type asset<mcp>,  binding = mcpServer ref
$assetRoot  → type mcp,         binding = asset ref     ← builtin on types.AssetLike
tools       → type []mcp.tool,  binding = mcp ref       ← an ordinary field chunk
```

Converting the asset to a resource **once** is what makes the rest free. Blocks
(`running { tools, prompts }`) work because `blockExpressions` already branches on
`IsResource`; `where`, labels, entrypoints, recording and `_` all see an ordinary
resource. Per-item error isolation falls out too: a failed resolve is that ref's
error, so `mcpServers.map(running.tools)` degrades one item instead of the query.
And it recurses without new machinery — a field inside the target's tree that is
itself `asset<…>` resolves through the *target* runtime's own resolver.

**Lifecycle, dedupe and guards** (implementation constraints, not open questions):

- **Anchor-keyed backing cache on the parent runtime.** Coordinator dedupe keys on
  Mrn/PlatformIds (`coordinator.go:191`), and a discovered MCP asset has *neither*
  until the `ai` provider's `Connect` assigns them — so without a cache,
  `mcpServers.map(running.tools)` opens one connection per anchor. Key it
  `resourceType + "\x00" + resourceId`, the same shape as the resource cache key.
- **Sub-runtimes are owned by the parent** and closed with it, rather than left for
  the coordinator to reap.
- **Depth guard of 5** on chained resolution, with the chain reported in the error.
  It bounds A → B → A cycles across runtimes, which a per-runtime cache cannot.
- **A time bound on each step of reaching another asset** - asking its provider
  how to get there, and connecting to it. A backstop, not the primary bound: a
  provider that talks to something remote is expected to bound its own connect
  and can say far more about what went wrong than a caller counting seconds.
  What this stops is a provider that bounds nothing taking the query down with
  it. A connect that overruns is abandoned rather than cancelled - the plugin
  interface carries no context - so ownership of the sub-runtime passes to a
  watcher that closes it once the connect finally returns, because bounding must
  not mean leaking a runtime and the provider process behind it.

## Phased plan

1. **Type system + typed `running`.** `types.Asset("mcp")` parameterization; `.lr`
   gains the `asset<root>` form; conversions and builtins carry the root; `running`
   typed `asset<mcp>`; the compiler type-checks members against a loaded root and
   degrades with a warning otherwise. Retypes a shipped field
   (`*.mcpServer.running`), so ADR 040 reports a breaking type change; the resources
   are `@maturity("preview")` and only `== null` can consume the value, so we take
   the warning rather than deprecate-and-add. **Landed.**
2. **Provider-declared root + `_`.** `Root` on `plugin.Provider`, surfaced through
   `llx.AssetRootSource`, top-level `_` resolving to it. Verifiable on its own:
   `mql run local -c "_"`. **Landed.**
3. **Root taxonomy for `os`.** `os.base` gains the universals; family roots
   (`os.unix`, `os.linux`, `os.windows`, `os.macos`) and the `os.any` union
   receiver; the surface attached per root by alias; flat `os` deprecated;
   build-time guard on member/type collisions across roots.
4. **Implicit root binding, v14 semantics.** Bind the asset root at the top level
   so bare members of the root resolve (`hostname`), with the global namespace
   tried first so every bundle that compiles today compiles identically. Carry the
   declared root in the resources schema so a compile with no runtime has one.
   Record the non-rooted note on the bundle. Add the shadowing and
   language-construct guards, and `@global`, starting with core. **Landed.**
5. **`RootedNamespace` feature flag.** The v15 semantics behind a flag: rooted
   only, `@global` for the exceptions, no fallback, a root required. Runnable
   against real content for the months before it becomes the default. **Landed.**
6. **Root narrowing.** Compile `_` against the union, record the narrowed set on
   the bundle, refuse assets that do not satisfy it. Needed for the
   **disconnected** compile; a connected one already gets the concrete root from
   `ConnectRes` and is bounded exactly. **Landed.**
7. **Recording-backed cross-asset resolution.** `providers.Runtime` implements
   `AssetResolver`; the target asset is found from the reverse edge and connected
   with a `mock` connection, including the `providers/mock.go:182` asset-selection
   fix. Testable in-repo from a recording fixture; no live connect. **Landed.**
8. **Live-connect backend.** The same `RuntimeFor` + `Connect` path with the
   target's real connection; reachability asked for through `ResolveAsset`
   rather than carried on the value; sub-runtime lifecycle and timeouts.

   Also fixes `docker.container`, which embedded `os.linux` and answered every
   member of it about the **host**: an Alpine container reported the Arch host's
   1359 packages and the host's hostname. The embed is replaced by
   `running() asset<os.any>`, so a container is reached as the separate asset it
   is. Removed rather than deprecated - an embed carries no `@maturity`, and
   every member of it was wrong in the same way.

   Verified against live containers, which is what makes this the first phase
   with an end-to-end target anyone can reach: the `docker` connector lives in
   the os provider, so a container needs no second provider to connect to.
   The imperative entry point for Go callers is `Runtime.RuntimeForAsset`, the
   same implementation the anchor path uses with the anchor step replaced by a
   caller-supplied asset. **Landed.**
9. **Namespace migration + other providers.** Roots for the remaining providers,
   `os`'s deprecated fields removed in v15, global names retired, `RootedNamespace`
   becomes the default.
10. **Secrets for live connect:** vault/credential provisioning keyed to the asset
   (no `--env` inside a traversal).

Guards (anchor-keyed cache, parent-owned sub-runtimes, depth limit) are not a phase;
they land with the resolution they guard, in phase 7.

## Consequences

- A foundational change: touches the type system, compiler, `providers.Runtime`
  resolution, the recording layer, and provider schemas. Must land evolutionarily.
- Recording becomes a first-class resolution backend for *other* assets, not just a
  replay of the current one — aligned with upstream serving data we can't fetch
  locally.
- The llx surface grows by two small interfaces and one builtin, and llx still
  cannot connect. Every runtime that is not `providers.Runtime` (testutils mocks,
  embedders) is unaffected, because `AssetResolver` is optional.
- The forward path becomes the first in-repo consumer of
  `inventory.Asset.Relationships`, which today is written by MCP discovery and read
  by nothing. That makes ADR 030's forward/reverse parity invariant load-bearing at
  runtime rather than only at correlation time.
- v14 changes no compiled bundle: global-first resolution means every query that
  compiles today compiles to the same chunks, so checksums, scoring continuity and
  cnspec's shared resolved-policy cache are untouched. The new behavior is
  additive - names that used to fail now resolve through the root.
- Autocomplete offers both the global and the rooted path for every attached
  resource during the migration window. Transitional by design; consumers can
  already tell an alias from a resource by comparing the schema key against `id`.
- Runtime dependency: live `.tools` needs the `ai` provider; recording-backed
  resolution does not.
- Reconciles with ADR 030: the anchor is the identity for both correlation and
  recording lookup; the type carries the root, so the value keeps the shape ADR 030
  chose and stays secret-free.

## Alternatives considered

- **Dynamic/untyped traversal (widen `llx.Runtime` with `RunOnAsset`).** Smaller
  first slice but entrenches an untyped escape hatch with no chaining or
  type-checking; rejected as the target in favor of the typed-root foundation.
- **Platform-side correlation only (no in-query traversal).** Already works via ADR
  030 (discover MCP assets, scan them, correlate by anchor). Remains the way to get
  the data without any of this; `running.tools` is the in-query ergonomic on top.
- **Per-resource platform annotation** (`@platforms("linux")`) instead of placement
  in a root tree. Rejected: it is a second, weaker encoding of what tree membership
  already states, and it can drift from the schema while placement cannot.
- **Flat `os` as the universal root.** Rejected once the taxonomy existed: `os`
  would have to be both the union receiver and the universal base, which is the
  ambiguity the taxonomy removes. `os.base` is the base, `os.any` the receiver, and
  bare `os` holds nothing.

## Resolved (from review)

- **Root declaration → statically on `plugin.Provider`, refined by
  `ConnectRes.Root`.** Moved off `Connector` during implementation: connection
  types do not map onto connectors (8 connectors, 14 types in `os`), so a
  per-connector field is not resolvable from what the runtime holds. The static
  declaration serves the disconnected compile; the connection's answer bounds an
  interactive query by the platform it reached.
- **A missing member of a platform root is diagnosed as a platform mismatch**,
  naming the root that carries it, rather than as version skew. The union root is
  never offered as that alternative: it holds every platform's members, so it
  answers nothing.
- **Compile-time absence → degrade + warn**, with member checking deferred to the
  executing runtime.
- **Static vs. dynamic root → static, with the connection as the authority.** The
  field statically declares the root *name*, so chaining always has a
  statically-known root; a connection-declared root that disagrees with a compiled
  one is a reported error, not a silent substitution.
- **Platform-specific roots → yes, via the taxonomy**, with `os.any` as the
  compile-time receiver so content stays portable and narrowing decides
  applicability.
- **Recording backend → local or upstream, over the same path as live.** The backing
  is which connection the *target asset* carries (`mock` vs. its real one), not a
  second resolution mechanism.
- **Foreign lookups on one recording object → forbidden.** Select a backing per
  target asset instead; that is why resolution goes through `RuntimeFor`.
- **Target stub on the value → yes**, populated from the same builder discovery
  uses; lands with phase 6.
- **Namespace precedence → global-first in v14, rooted under `RootedNamespace`,
  rooted by default in v15.** Root-first in v14 would change every bundle's
  checksum and bake a platform into a bundle that cnspec shares across assets.
  The shadowing guard makes the eventual flip semantically free.
- **Globals → explicitly marked `@global`**, in core as well, so nothing is global
  by accident of which provider defines it.
- **Secrets → explicit, never implicit** (consistent with the `--env` decision).

## Follow-ups

- **Explicit secret source for live-connect traversal.** There is no `--env` inside
  a traversal, so explicit secrets must come from somewhere the non-interactive path
  can read. Candidate: the existing vault/`conf.Credentials` mechanism, keyed to the
  target asset's identity, resolved at connect. Does **not** block the earlier
  phases: recording/upstream resolution needs no secrets, and no-secret live servers
  work without it. The stub on the value carries no secrets, by the same rule.
- **Upstream anchor → MRN.** Resolving a target registered upstream needs an
  upstream lookup from `(host asset, anchor)` to the target's MRN. Nothing provides
  that today; the local recording answers it from the reverse edge because it holds
  both assets. A platform-side dependency, and the reason the local leg lands first.
- **Derived applicability replaces explicit policy filters** in cnspec's resolved
  policy, from two directions: the root a policy states (point 7) and the
  requirement narrowing derives from what a query touches (point 4). Targeted
  within the v14 lifetime; explicit filters are the fallback until then.
- **Asset-kind roots.** The family axis lands first; the kind axis (host /
  container / image / filesystem) composes onto it with multi-embed when a container
  image's surface is worth bounding separately.
