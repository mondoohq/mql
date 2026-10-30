# ADR 041: Late binding of resource types (stable type identity)

## Status

Proposed

## Context

[ADR 040](040-cross-version-type-migration.md) reconciles version-skewed content
by carrying schema provenance, bridging shape changes with migration lenses, and
adapting content down for older nodes. But it does all of that while still
*baking* concrete resource types into content at compile time. This ADR attacks
the **root cause** that makes every schema change breaking in the first place:
**a type is its name, frozen into the bytecode.**

Late binding is **additive to ADR 040, not a replacement.** ADR 040 handles
structural and semantic change; those still need lenses, down-adaptation, and the
degradation floor no matter what. What late binding removes is the *large,
avoidable* class of breakage that isn't a real shape change at all — renames,
reorganizations, and moving a resource between providers. Today those are as
breaking as a genuine type change, purely because identity is spelled with the
name. Fix that and the vast majority of ADR 040's lenses become unnecessary: they
collapse from "authored transforms" to "nothing to do."

This ADR **depends on ADR 040 shipping first.** Introducing stable identity is a
wire change, and the only safe way to roll it out across a skewed fleet is behind
ADR 040's min-MQL-version axis and down-adaptation. So 040 is the foundation;
041 is the follow-on that shrinks 040's ongoing cost.

## Mechanics (grounded in the current code)

**Identity is the name, and the name is baked in.** `types.Type` is a string
whose first byte tags the kind; a resource type is `byteResource` (27) followed by
the name verbatim (`types/types.go:182-193`), so `Resource("claude.code.repo")`
is `"\x1bclaude.code.repo"`. That exact string is what the compiler writes into
`Function.Type`, into the resource `Chunk.Id` (`mqlc/mqlc.go:1144,1156`), and into
the checksum that forms the bundle's identity (`llx/chunk.go:113`). At runtime the
VM resolves resources and fields **by that name string** — resource dispatch
looks up `rr.MqlName()` in the schema (`llx/builtin.go:825-843`;
`providers/runtime.go:1040-1046`), field access indexes `resource.Fields[chunk.Id]`
(`llx/builtin.go:850-861`). Rename the resource and every one of those name-keyed
lookups misses. There is no indirection between "the name a user typed" and "the
identity the runtime resolves."

**We already have two weak, partial forms of indirection** — worth building on
rather than inventing from scratch:

- **Aliases**: the schema stores one `*ResourceInfo` under several map keys
  (`resources.proto:11-28`; materialized at `lrcore/schema.go:50-68`), so N names
  can point at one resource. This is name→name indirection, resolved only at
  compile time, and it does nothing for baked bytecode or type identity.
- **`.lr.versions`**: a committed, per-resource-and-field metadata file
  (`providers-sdk/v1/mqlr/lrcore/versions.go`) that already tracks stable
  per-field data across releases. It is the natural home for a stable *id*
  allocated once per resource/field.

## Decision

Decouple a resource's (and field's) **identity** from its **name**, and bind
concrete types **late** — at load, against the local schema — instead of freezing
them at compile time.

1. **Stable ids, allocated once, never reused.** Each resource and field gets a
   stable identifier assigned when it is first introduced and recorded alongside
   `.lr.versions` (the mechanism that already tracks per-field release metadata).
   This is the protobuf-field-number discipline: the id is the identity, the name
   is a mutable display label, and a retired id is never recycled.

2. **Content references ids, not names.** Compiled bytecode carries the stable id
   for each resource/field reference; the human name is retained only as a label
   for diagnostics and decompilation. ADR 040's migration-chain-canonical bundle
   identity becomes simply "the ids," so a **rename requires no lens at all** —
   the id is unchanged, old content resolves, and the checksum is stable.

3. **Late type binding.** The compiler records the referenced ids and the
   *expected kind* (scalar / resource / list-of, enough for static checking) but
   does **not** freeze the fully-resolved concrete type. At load, the executor
   binds each reference to the local schema's current definition for that id. A
   reorganization that preserves ids and kinds (moving a field, restructuring a
   parent) stops being breaking by construction.

4. **Roll out behind ADR 040's version axis.** New (v14+) engines emit and consume
   id-based content; older engines receive name-based content via ADR 040
   down-adaptation. During the transition, content dual-encodes (id + name) and
   readers prefer the id and fall back to the name, so no flag day and no fleet
   coordination. ADR 040's min-MQL-version axis is exactly what gates this.

5. **Cross-provider unification stays explicit, not inferred.** Merging
   `claude.code.repo` into a shared `git.repo` is a *declared* equivalence (an ADR
   040 lens/alias, shape-checked by the part-5 build gate), **not** something the
   runtime infers from matching shapes. Stable ids make rename/continuity free;
   unification of two independently-allocated ids remains an author's deliberate,
   verified act.

## Phased plan

1. **Allocate and record ids** for every existing resource/field (backfill,
   analogous to the `.lr.versions` backfill), and thread them through codegen into
   the schema. No wire change yet; ids are metadata.
2. **Dual-encode content** (id + name) in the compiler; make the runtime resolve
   by id with name fallback. Redefine ADR 040's canonical identity as the id set.
3. **Late-bind types at load** for id+kind references; drop the requirement that
   the fully-resolved concrete type be baked.
4. **Retire name-based resolution** once the fleet's min-MQL-version floor clears
   the transition window (ADR 040 governs the floor).

## Consequences

- Renames, field moves, and reorganizations become **non-breaking by
  construction**, eliminating the largest and most avoidable class of ADR 040
  lenses. The `claude.code.repo → git.repo` rename needs zero migration code once
  ids exist (the cross-provider *unification* still needs a declared equivalence).
- Bundle identity becomes genuinely stable across cosmetic schema evolution, so
  cnspec scoring/aggregation stops fragmenting on renames.
- New, permanent obligations: an **id allocation authority** and the
  never-reuse discipline (a leaked or reused id is a silent correctness bug, the
  same failure mode as a reused protobuf field number). Ids must be reviewed like
  wire contracts.
- It is a wire/format change touching every serialized bundle, DB blob, and
  `resources.json`. Bounded and safe only because ADR 040's provenance +
  down-adaptation carry the transition — which is why 040 lands first.
- Static type-checking is preserved (kinds are still recorded); only the *fully
  concretized* type is deferred to load. Error quality must stay good — a
  late-binding miss has to name the id *and* its last-known label.

## Alternatives considered

- **Structural / shape typing** (identity = the set of field name→types, not a
  name or id). Uniquely attractive here because it would make **cross-provider
  unification automatic** — `claude.code.repo` and `git.repo` with the same shape
  would simply *be* the same type, directly serving the motivating goal. Rejected
  as the baseline because: accidental shape collisions become silent
  type-equivalence bugs; error messages degrade ("expected {…12 fields…}"); shape
  *changes* still break (so ADR 040 is still needed); and it is a far larger VM
  semantic shift than stable ids. Kept on the table as a possible *opt-in, declared*
  equivalence for the specific unification case — but declared, per decision 5, not
  inferred.
- **Name + late type resolution, no ids** (keep names in bytecode, just stop
  baking the resolved field types). Fixes *field-type drift under an unchanged
  name*, but a rename still breaks because the name is still the key. Solves the
  smaller half of the problem; rejected as insufficient.
- **Keep baking, rely on ADR 040 lenses alone** (do nothing here). Every rename
  and reorg remains a hand-written lens forever, and bundle identity keeps
  fragmenting on cosmetic changes. This is the status quo ADR 040 leaves behind;
  rejected because the recurring lens cost is exactly what this ADR removes.
- **Global type-registry service** (identity assigned by a central service at
  registration). Overkill and introduces a runtime dependency; the committed
  `.lr.versions`-adjacent file already gives us a distributed, reviewable id
  ledger without a service.

## Open questions

- **Id namespace and authority:** per-provider id spaces (with the provider id as
  a qualifier) or a single global space? Per-provider avoids cross-provider
  coordination but complicates unification (decision 5).
- **Fields too, or resources only?** Field renames are common; if only resources
  get ids, field renames still need lenses. Leaning toward ids for both, at the
  cost of a larger ledger.
- **Split / merge of resources** (one resource becoming two, or the `git.repo`
  merge) — how ids behave when identity genuinely forks or joins. This is the
  boundary where stable ids hand off to ADR 040's lenses.
- **Interaction with ADR 031 typed roots** — `asset<root>` parameterizes types by
  a root resource type; that parameter should reference the root's stable id, not
  its name, for the same reasons.

## Follow-ups

- Prototype id allocation for one provider (os, home of `claude.code.repo`) and
  prove a rename with zero lens code end-to-end.
- Specify the id ledger format and the never-reuse review gate (CI check that no
  committed id changes meaning).
- Revisit structural equivalence once real unification cases accrue; decide
  whether declared shape-equivalence earns its keep beyond decision 5.
