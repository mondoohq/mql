# ADR 040: Cross-version MQL — schema resolution, migration lenses, and down-adaptation

## Status

Proposed

## Context

Compiled MQL — and, less obviously, MQL *source* — is silently bound to one
exact schema version. Compilation resolves names into concrete types against a
schema and freezes them into bytecode and checksums; execution assumes the
runtime schema is byte-for-byte identical. When it isn't, everything from a
single field to a whole policy shatters. Because the server routinely ships
content (raw or compiled) down to clients and is usually **newer** than they are,
version skew is the steady state, not the exception.

The problem is **general schema evolution across skewed nodes, in both
directions**, not the narrow case of renaming a resource. A rename of a
structurally-identical resource is the *easy* 10%; the real difficulty is
**structural change** (a scalar becoming a typed reference, a list becoming a
single value, a field changing meaning) and the **new→old direction** (content
produced on a newer schema meeting an older node that has never heard of the new
names, types, or language features). Any solution that only handles renames, or
only the old→new direction, does not address the problem.

We treat the schema as an ambient global constant. It is **data**, and it must
travel with — or be resolvable alongside — the content, with a reconciliation
step at load time. This is the same problem Avro (writer schema vs reader schema
+ a resolution algorithm), Kafka's schema registry, and Cambria (bidirectional
lenses for "distributed data without a shared schema") exist to solve. We have
none of that machinery today.

### Two version axes, and we track neither

Reconciliation needs to know two independent things about a piece of content, and
we currently record neither reliably:

- **Which schema it was compiled against** (the *writer schema*, per provider).
  Today the bundle records no schema identity at all — the schema is only ambient
  at compile time.
- **The minimum MQL engine version required to execute it** (the *language/VM*
  axis — new opcodes, builtins, type kinds like ADR 031's `asset<root>`). This is
  distinct from the schema axis: an old VM can fail on new bytecode regardless of
  schema.

What we have is close but wrong for the job:

- `CodeBundle.Version` is set to `mql.APIVersion()` (`mqlc/mqlc.go:2267`) — a
  *writer* stamp (which engine compiled it), **not a minimum** and **not a schema
  identity**.
- `CodeBundle.min_mondoo_version` (proto field 22) was **never set by the
  engine** before this ADR; it is now stamped, and still read by nothing in mql
  (see Implementation status).
- Per resource/field, `min_provider_version` is populated
  (`providers-sdk/v1/mqlr/lrcore/versions.go:78-115`) but **read by nothing at
  runtime**, and it only covers the *provider-schema* axis.
- The per-field `min_mondoo_version` — the old *engine-version* signal — is
  **deprecated** (`resources.proto:79,96`, "We now use min_provider_version"). So
  when we moved to provider versions we **lost the min-MQL-version axis
  entirely**.

## Mechanics (grounded in the current code)

**A type is its name, frozen into content.** `types.Type` is a string whose first
byte is a tag; a resource type is tag byte `byteResource` (27) followed by the
name verbatim (`types/types.go:182-193`). `Resource("claude.code.repo")` is the
bytes `"\x1bclaude.code.repo"`. Human name and type identity are the same bytes,
so a rename is simultaneously an identity and a type change — and both get baked
in: the compiler copies the schema's `Field.Type` verbatim into field chunks
(`mqlc/mqlc.go:1089`), stamps the resource name into `Chunk.Id` and the resource
chunk type (`mqlc/mqlc.go:1144,1156`), and **folds the type string into the
checksum** (`llx/chunk.go:113`), from which the bundle identity `CodeV2.Id`
derives. Changing a field's type changes the content identity of every query that
touches it, even if the source is unchanged — which forks cnspec scoring, since
scoring keys on those checksums.

**The compiler has no version awareness.** A missing resource/field is a hard
`ErrIdentifierNotFound` (`mqlc/mqlc.go:25-35`) — never "needs a newer provider,"
never a fallback. Resolution is "is this key in the merged aggregate schema right
now" (`providers/extensible_schema.go`; `resources.Schema.Add` at
`providers-sdk/v1/resources/schema.go:21-123`).

**Source already rides along with bytecode, and there are two execution paths.**
`CodeBundle` carries both the raw `source` (field 3) and the compiled `CodeV2`
(field 6). `exec.Exec`/`mqlx.Env.Compile` recompile source against the *local*
schema (`exec/exec.go:35-76`); `exec.ExecuteCode` runs a pre-compiled bundle
**as-is with no recompilation** (`exec/exec.go:78-106`). The server-ships-bytecode
path lands in `ExecuteCode`. The presence of `source` in every bundle is the
escape hatch this ADR relies on.

**Skew fails lazily and inconsistently at runtime.** No pre-flight check. A
missing field degrades to `types.Unset` + a warning (`llx/builtin.go:850-861` —
its comment already names this exact skew scenario), a missing resource errors
(`providers/runtime.go:1040-1046`, `llx/builtin.go:825-843`), and a typeless
primitive coerces to null (`llx/data_conversions.go:817-838`). Combined with
three-valued logic (`null && null == true`), a degraded bundle can make an
assertion **pass** while verifying nothing.

## Decision

Make schema a first-class, versioned input to execution, reconcile writer against
reader at load time, and put the burden of bridging versions on the side that
owns the newer definitions. Five parts: four at runtime, one at build time.

### 1. Content carries its provenance; execution resolves writer against reader

Every compiled bundle records **both** version axes:

- a **schema fingerprint/version per referenced provider** (the writer schema
  identity), and
- a **minimum MQL engine version** required to execute it (revive the dead axis;
  populate the currently-inert `CodeBundle.min_mondoo_version`, or a dedicated
  field, and compute it from the language features actually used).

Providers keep a **schema registry / version history** (or a bounded
compatibility window) so any node can obtain a *writer* schema it did not compile.
Execution becomes `reconcile(writerSchema, readerSchema) → adapted plan` instead
of assuming `writer == reader`. When a node holds `source` and detects an epoch
mismatch it may recompile locally rather than run stale chunks — treating shipped
bytecode as a cache, not a contract. Bundle identity is defined as a **canonical
key resolved through the migration chain** (part 2), not the raw baked type
strings, so the same logical query keeps one identity across a migration and
scoring survives.

### 2. Migrations are composable, directional lenses — not aliases

For each version step that changes shape, the provider ships a directional
transform between adjacent schema versions, written as **arbitrary Go code**, not
a restricted mapping DSL. Two reasons: a lens is minute next to the provider it
lives in, so the cost of full generality is negligible; and authors need the
freedom to do whatever a real structural change demands (call an API, resolve an
id to a resource, restructure a value) rather than being boxed in by a mapping
language. We start with a thin lens interface and **grow a shared utility
library** (id→resource resolvers, common field hoists, list/scalar adapters) as
recurring patterns emerge. Renames are the degenerate identity lens; the
load-bearing ones are structural:

- `repos: []string → []git.repo` via `git.repo(url: $)` — a real constructor
  adapter, not a name swap.
- `vpcId string → vpc() aws.vpc` — resolve the id to a typed resource.
- hoist/flatten (`linuxParameters.maxSwap → linuxMaxSwap`), split, merge.

**The degenerate case gets a declarative shortcut.** A pure move — a field that
now lives somewhere else, unchanged — is declared in the schema as
`@replaced_by("os.base.hostname")` rather than written as a no-op Go lens. 444
deprecations in the tree carry that information as prose today, 431 of them
naming a target; as data it drives the notice a user sees while the old name
still works.

Note what moment that is. `@maturity("deprecated")` changes no behavior — it
decorates suggestions and nothing else — so through the whole deprecation window
both spellings resolve, in one schema, on one engine. There is no version skew to
bridge, which is why this case needs no lens: the old field is its own
compatibility. `@replaced_by` only makes the deprecation directed instead of
silent. When the field is finally deleted, the annotation is deleted with it;
nothing revives the old name and nothing narrates it, because a full major of
warnings was the migration. It also does not pre-authorize that deletion — the
removal still surfaces in the part-5 schema diff as breaking and still gets an
explicit decision.

**It does not replace or shadow the Go lens path, and must not grow toward it.**
The annotation carries no code, so it can express exactly one thing: this name is
now that name. Every migration that has to *act* — resolve an id to a resource,
restructure a value, split, merge, call an API, coerce at the data boundary — is
a lens in Go, and that is the general path. Giving the annotation a mapping
expression would rebuild the restricted DSL this ADR rejected on purpose; when
the shortcut doesn't suffice, you write the lens.

**It records the schema path and renders the spelling.** The stored value is
where the field lives (`os.base.hostname`); what a user is told is what they can
type (`hostname`), computed against whatever root the compile has — from the
connection in `shell`/`run`, or supplied by a caller compiling against a stated
root. The two differ once queries are rooted (ADR 031), and storing the typable
form would leave the annotation useless to any lens, which works
schema-to-schema.

Lenses **compose along the chain** (`v3→v4→…→v7`) so an arbitrary A→B is bridged
by traversing intermediate steps, and where a lens is invertible it also runs
backward (needed for part 3). A lens adapts the *plan/AST* (rewrite chunks into
the reader's vocabulary) and/or the *data* (coerce values at the boundary),
whichever the change requires.

### 3. The newer side adapts *down* for the older side

The direction that felt unsolvable — new content on an old node (cases where the
server is newer) — is solvable because the burden belongs to the **producer**,
which is newer and owns the lenses. Before shipping to a client on an older
version, the server **down-migrates content into that client's schema + engine
vocabulary**: the client receives content expressed entirely in names, types, and
language features it already knows, and compiles/runs it natively — it never has
to learn the new world. This is the real fix for the common skew; it lives in the
resolver (upstream cnspec), but the engine must *produce* the version metadata
(part 1) and *own* the lenses (part 2) that make it possible.

### 4. Partial execution is the floor — never silent, never falsely green

When a change is genuinely unbridgeable in a given direction (a new capability
with no backward projection), the producer **omits that datapoint for that
client** and reports `requires provider ≥ V` / `requires mql ≥ V`. Anything that
still slips through resolves to a typed null **carrying that reason**, and
assertions over an unavailable field **fail, not pass** (set explicit error/false
state on the stub to defuse the `null && null` footgun). Skew degrades per-field —
loud, localized, attributable — instead of shattering the whole query or, worse,
passing while verifying nothing.

### 5. Breaking changes are detected at build time and force a migration

None of the above helps if an author changes a type and simply forgets to ship a
lens. So detection is not advisory — it is a **build-time gate**, the enforcement
counterpart to the runtime machinery. Codegen already holds both schemas: the
previously-committed `*.resources.json` and the one freshly generated from the
edited `.lr`. It **diffs them** and classifies every delta:

- **Additive** (new resource, new field, a widened optional) — allowed; bump the
  schema fingerprint; no lens required.
- **Breaking** (a field's `Field.Type` changed, a resource/field removed or
  renamed, a semantics marker flipped) — **hard-fail the build** unless a
  migration lens (part 2) covering that exact transition exists, or the author
  explicitly annotates the change as intentionally unbridgeable (so part 4 can
  degrade it cleanly rather than guess).

This is the discipline `buf` enforces for protobuf: you cannot merge a breaking
schema change without acknowledging it. It supersedes today's purely prohibitive
rule ("never change a shipped field's type") — the type *can* change now, but the
build will not let you change it **without a lens**. The gate also drives part 1's
provenance: a detected breaking change forces the schema fingerprint (and, when
language features are involved, the min-MQL-version) to advance, so provenance can
never silently drift out of sync with the schema it describes.

## Phased plan

1. **Provenance, no wire break yet.** Stamp bundles with the per-provider schema
   fingerprint and a computed min-MQL-engine version (part 1, producer side).
   Wire `min_provider_version` into compile-time diagnostics so opaque
   `ErrIdentifierNotFound` becomes "field X requires provider ≥ V." Add the
   codegen schema-diff (part 5) as a **warning** so drift becomes visible
   immediately. Pure metadata + tooling; ships independently.
2. **Resolution + lens runtime.** Schema registry / version history; the
   `reconcile(writer, reader)` step; the lens interface and composition engine.
   Redefine bundle identity as the migration-chain-canonical key (part 1/2).
   **Escalate the schema-diff gate to hard-fail** now that lenses exist to satisfy
   it. Land one structural migration end-to-end as the proof (e.g. `repos:
   []string → []git.repo`, exercised in both directions).
3. **Down-adaptation in the resolver (upstream).** Server consumes client
   `ProviderVersions` + bundle provenance and down-migrates or withholds
   content per target (part 3).
4. **Degradation policy hardening.** Consistent typed-null-with-reason;
   assertion-safe stubs; per-field partial results (part 4).

## Implementation status

Phase 1 has landed. What exists now:

- **Provenance** — `Schema.provider_versions` records the version of every
  provider contributing to a schema, stamped at load time from the provider's
  own config (`providers/providers.go`, `providers/coordinator.go`). Bundles
  carry `CodeBundle.provider_schemas` (writer identity) and
  `CodeBundle.min_provider_versions` (the derived requirement), computed by a
  post-compile walk of the finished bytecode (`mqlc/provenance.go`). Both maps
  key on the **stable provider name**, not the module-path id -- see the note on
  id drift below.
- **Reconciliation primitive** — `mqlc.UnmetRequirements(bundle, reader)` answers
  "can this reader run this bundle", which is what parts 3 and 4 both need. A
  bundle with no recorded requirements is reported satisfiable, since absence of
  a requirement is absence of information.
- **Diagnostics** — a failed name resolution now names the provider whose
  namespace it fell under and the version installed, on all three failure paths
  (the ADR above cites only the root one). It deliberately does *not* claim which
  version would be new enough; that needs the phase-2 registry.
- **Build-time detection** — `lrcore.DiffSchemas` classifies every schema delta
  as additive or breaking, wired into `mqlr generate` as a warning, with
  `--fail-on-breaking` ready for phase 2. Documented in `CLAUDE.md` §2 Step 2.
- **Min-MQL-engine axis** — revived as a static feature → introducing-version
  table (`mqlc/engine_version.go`). This resolves the "how is min-MQL-version
  computed" open question as *static table*, not a build stamp: the version that
  matters is where the feature landed, which no amount of compile-time
  introspection can tell you. Its first entry is ADR 043 strict mode at
  **14.0.0** — an engine predating the nullability marker reads it as
  `UNSPECIFIED` and runs the bundle *non-strict*, so it does not fail, it
  verifies less.

  The floor is **declared, not enforced here**. mql stamps it and nothing in mql
  branches on it: `UnmetRequirements` answers for the provider axis only. The
  consumer is cnspec, which attaches a minimum version requirement to a policy
  that declares strict mode. A version number is a poor proxy for what is really
  being asked — whether a reader understands a language feature — and
  [the language-versioning draft](draft-mql-language-versioning.md) carries that
  question, which v15 has to answer.

### Part 4: what the code actually did

Part 4 above is written on the premise that version skew degrades to silent
nulls which three-valued logic then turns into a pass. Measuring the paths
before changing them showed the premise is half wrong, and the half that is
right has a different cause.

**Skew does not degrade silently.** Compiling against a schema carrying a field
the runtime lacks, then executing against that runtime, produces a clean error
that `&&` propagates:

```
sshd.config.futureField                            -> cannot find field 'futureField' in resource 'sshd.config'
sshd.config.futureField && sshd.config.futureField -> cannot find field 'futureField' in resource 'sshd.config'
```

The `llx/builtin.go` Unset fallback this ADR cites is not what fires. What is
missing there is *attribution*, not failure: the bundle's
`min_provider_versions` already says `os: 99.0.0`, so the message could name the
version gap instead of the symptom.

**The falsely-green bug was real but unrelated to skew.** It came from genuine
runtime nulls, in the `bind.Value == nil` shortcut shared by the logical
operators, and it was two defects rather than one:

- `null && null` returned **true** - an assertion reporting success over two
  values it never read. Nine providers (`azure`, `databricks`, `mongodbatlas`,
  `ms365`, `neon`, `oci`, `os`, `vllm`, `zoom`) had grown regression tests across
  16 sites whose only purpose was keeping their resources from tripping it.
- `null || true` returned **false**, because `boolOrOpV2` carried the AND rule
  verbatim. Wrong under three-valued logic, under null-as-false, and under
  null-as-true alike.

Both are fixed by making a null operand **falsy**: `null && x` is false, and
`null || x` is whatever `x` says. Implemented by routing a nil binding down the
path `false` already takes, which deletes both special cases rather than adding a
third. Comparison is untouched - `null == null` stays true, because whether two
absent values are equal is a different question from whether an absent value
satisfies a check.

This lands in **v14**: it turns checks that were passing into checks that fail,
which is the point, and it cannot ship in a minor. It also retires the
per-provider workaround tax, and it stands on its own correctness argument rather
than on the skew premise.

**The recompile-from-source path deliberately does not degrade.** A reader
holding `source` and compiling it locally against an older schema fails at
`ErrIdentifierNotFound`, and that is the intended outcome: content that needs a
newer provider should say so, and the compile error now names the provider and
the version installed rather than reading as a typo. Degradation is for executing
bytecode that was already compiled elsewhere, not for papering over content this
node cannot express.

**Graceful degradation now works off the provenance.** When a bundle declares it
needs a newer provider than this build has, a field the reader does not define is
dropped rather than failing the query: the field resolves to an *unavailable*
value carrying `requires the os provider >= 99.0.0 (13.0.0 is installed)`, and
everything else in the query still runs.

Three properties make this safe rather than a way to hide bugs:

- **Evidence is required.** Degradation happens only when the reader can name a
  version for that provider and it is genuinely older. A reader that knows no
  version is *absent information*, not proof of skew, and a missing field there
  stays a hard failure - which is what a typo and a compiler defect look like.
- **The value keeps its type.** The reader has no field definition to take a type
  from, but the compiler baked the writer's type into the chunk, so the stand-in
  is a typed null rather than the untyped one that produces "a primitive with no
  type information" downstream. This is the typed-null-with-reason of part 4, and
  it falls out of the bytecode for free.
- **It cannot read as a pass.** An unavailable field is an error value, and a
  null operand is falsy, so an assertion over one fails. Under ADR 043 strict
  mode the skew reason survives rather than being replaced by the generic
  null-binding message, because `resolveNullBinding` declines a binding that
  already carries an error.

The pieces: `llx.ErrFieldNotFound` (typed so the executor can classify it),
`llx.SkewPolicy` (which providers the reader is behind on, and why),
`degradeUnavailableField` in the executor, `skewPolicyFor` in `exec/internal`
(the one place holding both the bundle and the runtime), and a dimmed
not-measured rendering in `cli/printer`.

### Part 6: degradation compiled into the bundle

Parts 1-4 handle a gap the reader can *recognise*: a name it does not have. That
inference only works for additive change. When a field's **type** changes, the
name exists on both sides and nothing fires - measured on a field flipped from
`[]string` to `string`:

```
sshd.config.ciphers                  -> []string, no error        # silently the wrong type
sshd.config.ciphers == "aes256-ctr"  -> cannot find function '==' for type '[]string'
sshd.config.ciphers.length           -> 6, no error               # confidently wrong
```

Two of the three are silent, and the third blames the query rather than the
version. Detection is cheap and local, because the reader already holds both
types: `chunk.Function.Type` is the writer's, baked into the bytecode by the
compiler, and `resource.Fields[id].Type` is its own. Nobody compares them.

Repair splits in two, and only one half needs new machinery.

**Case 1: no translation exists.** A list collapsed to a scalar, when nothing
says which element to take. There is no answer to invent, so this is the part-4
floor: mark the value unavailable and let it propagate to everything built on
it. Identical treatment to a field that simply does not exist yet, which is what
it is from the reader's side.

**Case 2: a translation exists, and the producer knows it.** Some changes carry
their own backward projection:

- `terraform.resources(query)` is shorthand for
  `terraform.where(<is a resource>).where(query)`.
- a field promoted from `string` to `time` is the old string, parsed.
- `process.executable` promoted from `string` to `file` is the old string as a
  path, with `basename` the operation that recovers the name.

For these the fallback should be **compiled into the bundle**: the producer emits
a form that works on both vocabularies, rather than the reader guessing or the
producer compiling per client.

Three properties make this the cheap option:

- **No wire change and no bootstrapping.** The fallback is ordinary bytecode in
  the older vocabulary, so an old executor runs it without knowing the mechanism
  exists. An alternatives table in the bundle would need the *reader* to
  understand it first, which means shipping the mechanism a release before
  anything could use it.
- **One artifact.** The producer still compiles once for everyone, preserving the
  property that makes parts 1-4 work offline and peer-to-peer: the server never
  needs to know who it is compiling for.
- **The compiler already knows when.** A field's `min_provider_version` says
  which release changed it. Emitting the defensive form only for changes newer
  than a configured oldest-supported-provider keeps this from being a permanent
  tax on every query, and the knob is a single policy setting rather than
  per-client knowledge.

The constraint that decides whether a change qualifies: **the fallback must be
expressible using only constructs that predate the change.** A projection that
needs a resource or an operator the old reader lacks is not a fallback, it is
case 1 wearing a disguise. That is checkable at build time against the same
schema history the part-5 gate already reads, which is what keeps "we know how to
degrade it" from becoming a claim nobody verifies.

**Implemented** as a sidecar plus an in-place patch, not as branches in the
primary code. `CodeBundle.translations` carries `(ref, provider, below_version,
block_ref)` entries; the translation blocks ship inside `code_v2` as ordinary
blocks that nothing points at until a patch does. `llx.Patch` selects the entries
this reader needs and returns a **copy** with those chunks redirected at a
`$translate` chunk, which runs the block against the original binding.

Why the copy: one bundle is executed against many assets and queries run in
goroutines, so rewriting in place races a goroutine reading the chunk - and a
lock around the patch does nothing about that. Only the blocks actually
containing a patched chunk are cloned; a current reader copies nothing.

Three properties fall out, all pinned by tests:

- **A current reader pays nothing.** It walks the sidecar, matches nothing, and
  runs pristine bytecode - no branch it can never take.
- **Identity survives.** The executor reads `code.Checksums[ref]` rather than
  recomputing, so a patched reader reports under the checksums the producer
  shipped and scoring does not fork across versions.
- **Nothing renumbers.** Blocks are addressed by index and the patched chunk is
  replaced at its own index.

The catalog reaches the compiler through the **runtime**, not through a caller
assembling it. `providers.Runtime` implements `llx.TranslationSource`, and
`mqlc.NewConfigFrom(runtime, features)` picks it up - so anything that compiles,
here or built on this, gets the mechanism by using mql normally. There is no
second compiler to wire separately.

The lookup is a function rather than a prepared map, because which providers a
query touches is only known while compiling it: a map would force the caller to
guess, or to start every installed provider just in case, and reading a catalog
means *running* the provider. Asked lazily, a compile with no floor set starts no
providers at all, and one with a floor consults only the providers its query
reaches. Misses are cached, so an unreachable provider is asked once rather than
once per field.

**The support window is a default, not a setting to remember.** The floor is the
provider's current major minus two, clamped at 14 and always the `.0.0` of that
major, computed per provider by `mqlc.DefaultDowngradeFloor` and applied by
`NewConfigFrom`:

```
provider 15.1.2  ->  14.0.0   (15-2 is 13, clamped)
provider 17.1.2  ->  15.0.0
provider 16.4.0  ->  14.0.0
```

The clamp is not arbitrary: the machinery that *consumes* translations ships in
v14, so a v13 reader ignores the sidecar field and runs the primary code no
matter what is emitted for it. A provider still on a pre-14 major therefore gets
no floor at all rather than a floor above its own version - which also means the
compiler never asks it for a catalog, and asking means starting it. Every
provider is on major 13 today, so the default currently emits nothing and costs
nothing; it starts working on its own as providers reach 14, which they do
together with mql.

Because the default activates for every provider at that point, the catalog is
read only from a provider the runtime **already has connected** - never through
the coordinator, which would start one that is not running. Compiling is not
always followed by executing: shell autocomplete compiles on every keystroke, and
launching a provider process per keystroke to read a catalog is not a trade worth
making. The case that matters is unaffected, since a query cannot run against a
provider without that provider being connected. The cost is that a fallback may
be missed for a provider that had not started yet, which degrades to the part-4
unavailable value rather than to a wrong one.

Providers author steps between adjacent releases in Go
(`plugin.Translate` + `TranslationBuilder`), which keeps their maintenance linear
and lets a shipped step stay frozen. The compiler relocates each into the bundle,
rebasing block-relative bindings and recomputing checksums at the destination,
and emits one entry per era so the reader selects exactly one and never composes
anything at runtime. A field read in several places gets one entry per read but
shares a single block, keyed on the binding's checksum: two reads of the same
field off the same binding are the same computation, and two reads off different
bindings are not.

Two things it refuses to emit: a translation whose result type disagrees with the
field's declared type (downstream is compiled against that type), and one that
rebuilds a field out of something introduced *after* the era it serves - checked
against `min_provider_version`, since a translation that is itself unrunnable is
worse than none.

`plugin.Service` answers the new RPC with an empty catalog, so adding it changed
no provider. A provider binary that cannot be reached yields no fallbacks, one
aggregate warning, and compilation continues.

**The reverse direction is detection only.** An old bundle carries no translation
for a change it predates, so the reader compares the writer's baked-in
`Function.Type` against its own schema (`llx.FindTypeDrift`) and warns. This is
the skew with no symptom of its own - the name resolves on both sides, so nothing
errors, and the query either fails somewhere unrelated or returns a plausible
wrong answer. Repairing it needs the inverse of the provider's own step; until
that exists, saying so beats the alternative.

### A note on provider-id drift

Provenance keys on the stable provider **name** rather than the module-path id
because the ids in the tree have not converged. 45 of 81 providers ship a
committed `*.resources.json` whose `provider` string predates the current one,
across three generations of the format (27 on `mql/v13/...`, 17 on
`cnquery/v9/...`, 1 on `cnquery/...`).

The `.lr` sources are all current, and codegen writes the `.lr`'s
`option provider` verbatim into every resource — so this is purely artifact lag.
A schema is only rewritten when its provider is rebuilt, and CI regenerates only
the providers a PR touches
(`.github/workflows/pr-test-generated-files.yaml`), so its
`git diff --exit-code providers/**/*.resources.json` never sees an untouched
provider. Regenerating all 45 is a mechanical follow-up; normalizing the key
means provenance does not depend on it happening.

Two fixes were prerequisites the ADR did not anticipate, both in
`Schema.Add` — the aggregate the compiler actually resolves against:

- It **dropped `MinProviderVersion`** when copying a `ResourceInfo`, so the
  version data codegen writes never reached the compiler at all.
- It **aliased the per-provider schemas' `Field` pointers** into the aggregate,
  so merging appended to the coordinator's cached schema and every rebuild
  appended again, growing `Others` without bound.

## Consequences

- Structural type change and the new→old direction — the actual problem — become
  tractable, not just renames and not just old→new.
- `min_provider_version` (already shipped, currently dead) and a revived
  min-MQL-version axis become the backbone of diagnostics and content selection,
  for near-zero new wire data.
- Bundle identity decouples from baked type strings, so migrations stop forking
  cnspec scoring.
- Real new cost and surface: a schema registry / version history per provider,
  an authored-and-maintained lens per structural change, and down-adaptation
  logic in the resolver. Lenses are code that must be tested in both directions;
  an unbridgeable change must be *declared* so part 4 can degrade cleanly rather
  than guess.
- Lenses accumulate; they need a deprecation horizon (warn in vN, drop in vN+2,
  mirroring ADR 031's namespace evolution) or the chain grows without bound.
- Breakage can no longer ship silently: the codegen gate (part 5) turns an
  un-migrated type change into a build failure in the author's PR, not a runtime
  surprise on a customer's older client.

## Alternatives considered

- **Server compiles per-client-version content (negotiation, no lenses).** Solves
  compatibility but requires the server to retain and compile against every
  historical schema and helps neither offline nor peer-to-peer. Subsumed as the
  narrow "withhold/down-level" fallback within part 3, not a general strategy.
- **Always recompile from source, never execute foreign bytecode.** Collapses the
  bytecode axis, but without migration-chain-canonical identity (part 1) different
  clients compile the same source to different identities under drift, forking
  scoring; and it still can't compile *source* that names resources the local
  schema lacks. Retained as the recompile-on-mismatch option inside part 1, not
  the whole answer.
- **Runtime graceful degradation alone.** The missing-field→null path already
  exists (`llx/builtin.go:850`). Insufficient as a solution — silent nulls plus
  three-valued logic pass assertions that verified nothing — so it is demoted to
  the part 4 floor, hardened to fail attributably.
- **Rename-only aliasing (the previous draft of this ADR).** Handles a
  structurally-identical resource in the old→new direction only. It is exactly the
  degenerate identity lens in part 2 and does not touch structural change or the
  new→old direction; rejected as a headline, absorbed as a special case.

## Relationship to late binding ([ADR 041](041-late-binding-resource-types.md))

This ADR reconciles versions while still *baking* concrete types into content.
The root cause — that a type is its name, frozen in at compile time — can be
attacked directly by **late binding**: reference fields by a stable contract and
resolve concrete types against the local schema at load time. That would make the
common evolutions (rename, reorg, additive) non-breaking *by construction*,
shrinking how often a part-2 lens is even needed.

Late binding is **additive to this ADR, not a replacement**: structural/semantic
changes and new→old capability gaps still need lenses (part 2), down-adaptation
(part 3), and the degradation floor (part 4) regardless. Because 1-4 stands on its
own and does not require the invasive v14 wire/VM change late binding entails, and
because this ADR's identity model (migration-chain-canonical, part 1) is
deliberately written to be satisfied by a late-bound world, late binding is
proposed as a **separate decision (ADR 041)** on its own timeline rather than
folded here. Folding it in would hold this shippable compatibility layer hostage
to the hardest, most invasive change. (If we decide the lens burden is only
tolerable *after* late binding shrinks it, the two collapse into one — but 1-4's
content is unchanged either way.)

## Open questions

- **Fingerprint granularity:** per-provider version, a hash of the merged schema,
  or per-resource? Per-provider is cheapest and matches `min_provider_version`.
- **How the min-MQL-version is computed** from a bundle — a static table of
  language features → introducing engine version, or a coarser high-water mark?
- **Where lenses are authored** when a migration crosses provider boundaries
  (`claude.code.repo` in os → a shared `git.repo`): old owner, new owner, or core?
  Ties into ADR 031's cross-provider schema availability and the `others`
  duplication field slated for removal.
- **Invertibility:** invertible-by-construction lenses, or manually paired
  up/down lenses with a build-enforced round-trip test? (Expressiveness itself is
  settled — lenses are arbitrary Go code, with a shared utility library grown over
  time.)
- **Diff classification edge cases:** is widening a field optional/nullable
  additive or breaking? Does reordering an enum's documented values count? The
  part-5 gate needs a precise, conservative rulebook.

## Follow-ups

- Prototype `claude.code.repo → git.repo` (structurally identical) and a genuinely
  structural change (e.g. an id→typed-ref) as the two reference migrations once
  phase 2 lands; capture both in `CLAUDE.md`.
- Compiler test: identity stability across a migration (same source + lens ⇒
  identical migration-chain-canonical id).
- Coordinate rollout with [ADR 041](041-late-binding-resource-types.md) (late
  binding depends on this ADR's version axis); cross-link ADR 031 (typed roots /
  cross-provider schema) and ADR 030.
