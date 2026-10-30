# ADR draft: MQL language versioning

## Status

Draft, proposed for **v15**. Deliberately unnumbered: it records a problem and
the shape of a solution, and it should take a number when someone commits to
building it. (Numbers are cheap here and gaps are normal: 017, 019, 024, 026,
034-036 and 038 are all unclaimed.)

## Context

We track two version axes and only one of them has a home.

The **provider schema axis** is real, load-bearing, and now implemented
([ADR 040](040-cross-version-type-migration.md) phase 1). It answers *"does this
name resolve"*: `CodeBundle.min_provider_versions` records what a bundle needs,
`mqlc.UnmetRequirements` answers whether a given reader can supply it. Every
failure in that axis is **detectable by the reader** — the field is missing, so
something errors or reads null, and part 4 exists to keep that from degrading
into a false pass.

The **MQL language axis** has never had a home. It answers a different question:
*"does this engine understand what this bytecode means"*. Its failures are not
detectable by the reader, because the reader does not know it misread anything.

[ADR 043](043-mql-strict-mode.md) produced the first true instance.
`Function.Nullability` is a new proto3 field on an existing message. An engine
that predates it ignores unknown field 5 entirely, reads the absence as
`NULLABILITY_UNSPECIFIED`, and runs the bundle **non-strict**. It does not fail.
It completes, and reports a pass, having verified less than the policy claims.
No provider version is wrong, no name failed to resolve, and nothing in the
schema axis can see it.

The consequences are bounded, which is why strict content ships now rather than
waiting on this ADR. `?` has parsed and compiled since v13, and support is retired
every two majors, so every engine that can receive content accepts the syntax. A
v13 node runs a strict bundle leniently: same values, less verification. The gap
is not correctness, it is **knowing which nodes actually verified**, and that is
answered where the policy is authored — cnspec attaches a minimum version
requirement to a strict policy — not by an engine refusing a bundle it can run.

### What we reached for, and why it is the wrong shape

`CodeBundle.min_mondoo_version` was the nearest available field. It was the
per-field minimum, deprecated when we moved to provider versions
(`providers-sdk/v1/resources/resources.proto:64,96` reserve it), and ADR 040
phase 1 revived it at bundle level as a static feature-to-version table
(`mqlc/engine_version.go`), stamped in `mqlc/provenance.go:49`. One entry: strict
mode at `14.0.0`.

A version floor is the wrong shape for this question, for three reasons.

1. **It disguises a capability question as a version question.** What we need to
   know is "does this engine understand nullability markers". We infer it from a
   number through a hand-maintained table. The table's own contract is that a
   feature whose introducing version is unfilled contributes *no* requirement,
   so it degrades silently to no-gate exactly when someone forgets to update it,
   which is the same silent under-enforcement it exists to prevent.

2. **The version is not the thing that changed.** Provider versions carry
   tangible meaning: which resources and fields exist. An MQL engine version
   carries no comparable payload, and we already retire MQL support every two
   majors, which bounds the skew independently.

3. **It compensates for an encoding choice.** ADR 043 records that `[]?` was
   *retired as an encoding* in favor of `[]` plus the marker. The old form was a
   distinct function that an old engine rejects loudly ("cannot find function");
   the new form is invisible to it. The floor exists because we moved from
   fail-loud to fail-silent.

## Decision (sketch)

1. **The compiler owns language-feature provenance.** Each MQL language feature
   declares the engine version that introduced it, next to the compiler code that
   emits it. **This mechanism already exists** — `mqlc/engine_version.go` is
   exactly that table. What this ADR changes is its status: it becomes the
   language's own metadata, owned by the compiler, rather than an input to a
   version gate. Nobody needs to build it; somebody needs to decide what it is
   for.

2. **`min_mondoo_version` stays populated and stays advisory *inside mql*.** We
   have carried it this far and dropping it now costs more than keeping it. In
   v14, within this repository, it is **informational only**:
   - nothing branches on it, and `mqlc.UnmetRequirements` must not start;
   - it may be absent on any bundle, including one that needs a feature;
   - **absence is not evidence of compatibility.**

   That guarantee belongs in the proto comment as well as here. The field is not
   inert — it is written on every strict compile — and live data with no consumer
   and no validation will be trusted by the first consumer that arrives.

   Advisory here does not mean unused everywhere. cnspec is the one system that
   acts on it: a policy declaring strict mode declares a matching minimum version
   requirement, so the platform does not route it to a node that would run it
   non-strict. That is a deliberate split — the engine executes whatever it can
   execute, and the content decides where it is allowed to run.

3. **Enforcement is a v15 decision**, and it is gated on the open question below
   rather than on this annotation.

## What is true in v14, for the record

- `min_mondoo_version` is stamped by `mqlc/provenance.go:49` from
  `mqlc/engine_version.go`. One feature: strict-mode nullability markers, 14.0.0.
- `mqlc.UnmetRequirements` reads `min_provider_versions` only and never consults
  the engine floor. It also has **no production callers** — nothing in mql
  refuses a bundle on version grounds.
- Real failures fail at execution, where they can be attributed. A field the
  runtime lacks produces `cannot find field 'x' in resource 'y'`, not a silent
  null (ADR 040, part 4 as measured). Enforcement lives there, on what actually
  did not work, rather than up front on what a version number predicts.

**The rule underneath all three: never act on absent evidence.** It is already
stated in part 4's degradation properties — "a reader that knows no version is
*absent information*, not proof of skew" — and it is why `UnmetRequirements`
early-returns when a bundle records no requirements (`mqlc/requirements.go:49`):
a pre-provenance bundle is unknown, not incompatible, and refusing every one of
them would break every client holding one.

The engine floor is exactly such a signal. One feature is in the table, and an
unfilled introducing version contributes no requirement by design, so a bundle
that declares nothing is indistinguishable from one that needs nothing. Gating
execution on that would refuse working content on the strength of a number we
cannot currently compute reliably. **That is why the floor is declared and not
enforced, and it stays that way** — a v15 mechanism has to earn the right to
refuse by being reliable first.
- The provider axis is unchanged and is the one carrying weight.

## The open question v15 has to answer

An annotation on the bundle — whether spelled as a version or as a capability
set — can only ever help a **server-mediated** path, where the resolver holds the
client's identity and decides what to send. An old engine cannot read a new field
that tells it that it is too old.

| approach | protects server-mediated | protects direct-to-client | ongoing cost |
|---|---|---|---|
| version floor (today) | yes | no | table maintained forever, silent when unfilled |
| capability set on the bundle | yes | no | no table, exact rather than inferred |
| fail-loud encoding | yes | **yes** | wire/namespace cost per feature |

If content always passes through the resolver, the first two are interchangeable
and the second is tidier. If content can reach an engine without resolver
mediation, only the third works, and the annotation is documentation rather than
a control.

Whichever is chosen, it annotates until it is reliable. A signal that is absent
whenever someone forgot to fill it in cannot be the grounds for refusing to run
content — that is the rule in "what is true in v14" above, and v15 does not get
to skip it.

The deprecation window is what makes that survivable today rather than urgent.
Retiring support every two majors bounds the unmediated population to engines one
major back, and for strict mode that population parses the content correctly and
merely under-verifies it. A future feature with a worse failure mode — one where
an old engine produces a *different value* rather than a less-checked one — would
not have that cushion, and is the case that forces the decision.

**This ADR does not answer that.** It records that strict mode shipped with a
fail-silent encoding, that the floor is what we put in its place, and that the
next feature on this axis may not be so forgiving.

## Consequences

- One less thing pretending to be enforcement. The v14 story becomes honest: the
  provider axis gates, the language axis annotates.
- The table stops needing to be complete to be correct, because nothing depends
  on it being complete.
- If v15 chooses fail-loud encoding, the annotation retires rather than growing;
  if v15 chooses resolver mediation, it is already populated and needs a consumer
  and a validation story, not a rebuild.

## Relationship to other ADRs

- [ADR 040](040-cross-version-type-migration.md) introduced the axis as part of
  Decision part 1 and resolved its open question as "static table". This draft
  reopens *whether it should gate*, not how it is computed.
- [ADR 043](043-mql-strict-mode.md) is the only feature in the table and the
  reason the axis was revived. Its §5 and implementation-status item 9 carry the
  same split this draft describes: mql stamps the floor and does not act on it,
  cnspec attaches the requirement to a strict policy. Strict content ships
  without waiting on anything here.
