# ADR 043: MQL strict mode — explicit optionality in access chains

## Status

Proposed

## Context

MQL absorbs nulls. `sshd.config.params.DOES_NOT_EXIST.lines.map(downcase)`
evaluates to null: the missing key produces null, and every subsequent link
faithfully passes that null along to the end. The value is not wrong, but the
result carries no indication that `DOES_NOT_EXIST` was the link that broke, and a
chain that resolved cleanly to null looks identical to one that never resolved at
all.

That is convenient in an exploratory shell and dangerous in a policy. A security
check is a claim about a system; "I could not read the thing I was claiming about"
and "the thing is configured correctly" must not produce the same result, and
today they frequently do.

### What happens today: nulls propagate, silently

Null propagates all the way down a chain, and so does an error. That is the part
worth being precise about, because the two are not symmetric in the way that
matters.

Take `sshd.config.params.DOES_NOT_EXIST.lines.map(downcase)`. The missing key
reads as null (`llx/builtin_map.go:32-35`), `.lines` on a null string yields null,
`.map(downcase)` on a null array yields null, and the query returns null. Nothing
along the way objects, and nothing in the result identifies `DOES_NOT_EXIST` as
the link that broke. The same holds for resource fields
(`llx/builtin.go:825-830`, which stores `NilData` and returns no error), dict
access (`llx/builtin_map.go:374-379`), and array index (`llx/builtin_array.go:61-64`).

An error propagates too, but it propagates *as itself*: `runFunction` re-types the
error to the chunk's output type, caches it, and returns it
(`llx/llx.go:792-810`), and `triggerChainError` walks the rest of the chain firing
callbacks (`llx/llx.go:974-1009`). The user sees which step failed.

So the asymmetry is not propagation. It is **attribution**: a propagated error
names its origin, a propagated null does not. And providers convert the first
into the second at scale. The AWS provider calls `Is400AccessDeniedError` in 771
places, each turning a permission failure into a null field, and there are ~3,500
explicit `StateIsNull` sites across all providers. A scan run without the
permissions to read something produces the same null as a scan run against a
system where the thing is genuinely absent, and a policy cannot tell them apart.

The second problem is that the treatment of a null receiver is decided per
builtin. There are 104 `bind.Value == nil` branches across `llx/`, each written
for its own call site, and they do not agree: `dataOpV2` propagates null
(`llx/builtin_simple.go:162-167`), `nonNilDataOpV2` returns `false` on the
reasoning that "a missing config param is not <= 4"
(`llx/builtin_simple.go:172-180`), and `arrayAllV2` returns a null bool
(`llx/builtin_array.go:341-350`). Each choice is defensible where it sits. There
is no rule above them that an author can rely on.

### `?` already means this, and we already shipped it once

This is not a new idea being introduced from scratch. [#6633][pr6633] (Feb 2026,
"optional chaining: a.b.c vs a?.b?.c") built it: `?` marks a link optional, an
unmarked link is required, and dereferencing null without the mark is an error.
That PR shipped the whole front half and it is all still in the tree:

- **Syntax and AST.** `parseOperand` tracks `isConditional` across the `?`/`.`
  loop and stamps it onto the following call (`mqlc/parser/parser.go:526-563`);
  `Call.IsConditional` is part of the AST (`mqlc/parser/parser.go:137`). `a?.b`,
  `a['b']?.c`, and `a.b ?. c` all parse today.
- **Bytecode.** The compiler emits a distinct function id, `[]?` instead of `[]`,
  for a marked access (`mqlc/mqlc.go:1298-1302`, `mqlc/mqlc.go:1578-1585`), so the
  author's intent survives compilation and lands in the chunk checksum.
- **Runtime, and even the diagnostics.** `_dictGetIndex` / `_mapGetIndex` took an
  `isConditional` argument and raised `cannot access field <k>, parent element is
  null` when it was false.

What [#6633][pr6633] did **not** cover is resource field access. It only ever
touched `llx/builtin_map.go`; `runResourceFunction` was never part of it, so
`?` has always been a dict/map-only feature.

Then [#7079][pr7079] (Mar 2026, "propagate null through dict and map bracket
access") took the runtime half back out. It made `[]` behave like `[]?`, deleted
the `isConditional` parameter as dead, and collapsed both ids onto one handler
(`llx/builtin.go:547-548,732-733`). The null-propagation comments now sitting in
`dictGetIndex` and `mapGetIndex` are that revert's rationale. Its stated reason:
`dict["domain"]["key"]` was erroring with `cannot access field key, parent element
is null` whenever `domain` was absent, and that broke real queries.

**[#7079][pr7079] deferred the behavior; it did not abandon it.** The semantics
were never the problem. The problem was ordering: strictness was live before `?`
was established in the field, so content had no backwards-compatible way to say
"this link is legitimately optional" that older clients would also accept.
Deferring the runtime half let the operator settle first, on the reasoning that
once `?` is understood everywhere, content can adopt it freely and strict mode
can be turned on without stranding anyone.

That is the position we are now in. `?` has parsed and compiled to a distinct
chunk id since Feb 2026, so the operator is established and the deferred half is
what this ADR resumes. The remaining pieces are narrow: a mode to switch on,
resource field access wired to it, and an opt-in that lets each piece of content
choose.

[pr6633]: https://github.com/mondoohq/cnquery/pull/6633
[pr7079]: https://github.com/mondoohq/cnquery/pull/7079
## Decision

Introduce **strict mode**: a compile-time mode in which *producing* null is legal
and *dereferencing* null is an error, and in which `?` is how an author declares a
dereference optional.

### 1. The rule

> **Every link in a chain must resolve. `?` after a link waives that link.**

A link **fails to resolve** when:

- its receiver is null — whatever made it null, and
- for a map or dict, the key it names is absent.

A link **resolves to null** when the lookup succeeded but the value is null. That
is a legal outcome, and it is the whole of the field/map distinction:

- **A field always resolves.** A field is declared, so asking for it is never a
  claim that might be false; the type says what comes back, and if that is null
  the field resolved to null. Reading it is fine, reading *through* it is not.
- **A map key lookup may fail to resolve.** Naming a key is a claim that the key
  exists, and only the author knows whether they meant it. In strict mode an
  absent key is an error **at the lookup**; in non-strict mode it is null.

That asymmetry is the point, and it is what makes `params.PermitRootLogn == "no"`
behave correctly: the typo is a claim about a key that is not there, so the lookup
errors and the comparison never runs. A genuinely null field compared the same way
still yields `false`, because a null field is a value the provider actually
reported, not a mistake in the query.

**`?` sits after the link it guards, and pulls double duty.** It waives both
failure modes of that link *and* short-circuits the chain if the link yields null,
so the author never has to know which of the two they are guarding against:

| Situation | Non-strict | Strict | Guard |
|---|---|---|---|
| `m.k`, key absent (terminal) | null | error at `.k` | `m.k?` |
| `m.k == "no"`, key absent | false | error at `.k` | `m.k? == "no"` |
| `m.k.c`, key absent | null | error at `.k` | `m.k?.c` |
| `m.k.c`, key present, value null | null | error at `.c` | `m.k?.c` |
| `a.f`, field null (terminal) | null | null | — |
| `a.f == "no"`, field null | false | false | — |
| `a.f.c`, field null | null | error at `.c` | `a.f?.c` |
| `a.f.c`, `a` null | null | error at `.f` | `a?.f.c` |

Rows three and four are the double duty: one guard, two causes, same position. The
mark always attaches to the link on its left — `a?.f` guards `a`, `m.k?` guards the
`k` lookup — which is also how `a?.b` already reads in JavaScript. Guarding two
links takes two marks (`a?.f?.c`), and when a guard fires it abandons the rest of
the chain, so `a?.f.c` yields null rather than continuing on to fail at `.c`.

Note `m.k? == "no"` in row two: a trailing `?` with no following link is a valid
and necessary spelling, and it is the escape hatch for a key the author knows may
be absent. The parser does not support it today — `parseOperand` consumes the `?`
and then drops it when the next token is not `.` (`mqlc/parser/parser.go:528-536`),
and `parseOperation` swallows a `?` in operator position outright (`:730-732`).

**Relationship to [#6633][pr6633].** That PR treated an absent key as producing
null and raised the error one link later, at the dereference
(`cannot access field "b", parent element is null`). This ADR moves the error to
the lookup, which is what catches the terminal typo — [#6633][pr6633]'s placement
cannot, because a terminal lookup has no following link to raise it. Guard
placement is unchanged from [#6633][pr6633]: `params.d?.b` still works, and now
`params.d?` does too.

### 2. What counts as a dereference

The rule applies to every operation that reads through a receiver, not just field
and key access:

- **Resource field access** — `x.field`, compiled at `mqlc/mqlc.go:1084-1095`, run
  by `runResourceFunction`.
- **Block binding** — `x { … }`. A null `x` yields null without running the block
  today (`llx/llx.go:594-596`); in strict mode it errors, and `x? { … }` is the
  guard. Nothing about blocks is special here — the block-open is the dereference,
  the same way `.field` is.
- **Implicit array mapping** — `xs.field` over a null `xs`. A *non-null* list whose
  elements produce nulls is unaffected: those are produced values, not receivers.
- **Builtin methods on a null receiver** — `x.length`, `x.all(…)`, `x.contains(…)`.
  These are the 104 `bind.Value == nil` sites, and strict mode answers them with
  the rule above instead of per-site judgment.

**Operators that take null as a meaningful operand are exempt.** `== null`,
`!= null`, `== empty`, `!= empty`, `notEmpty`, and the three-valued boolean core
(`&&`, `||`, `!`) receive a null receiver as *input*, not as a failed dereference,
so the rule does not apply to them. Without the exemption `a["key"] == null` would
error in strict mode and there would be no way to test for null at all.

This preserves behavior rather than adding a special case: `null == null` already
evaluates **true** today, via `chunkEqTrueV2` → `boolOpV2` (`llx/builtin.go:35`,
`llx/builtin_simple.go:48-64`), and the `== null` / `== empty` handlers exist for
every type (`llx/builtin.go:64-65,116-117,189-190,262-263,418-419,466-467,
656-657,745-746,771-772`). The exemption is structural rather than a list: an
operator is not part of an access chain, so the compiler never marks it, and an
unmarked chunk keeps the behavior it has always had.

Note what the exemption does *not* cover. `a.b == null` with `a` null still errors,
because the failing link is `.b`, not the comparison — the guard is `a?.b == null`.
The exemption only means the comparison itself tolerates a null it is handed.

**Arrays are left inconsistent, deliberately.** An out-of-range `xs[9]` errors at
the lookup already, in both modes (`llx/builtin_array.go:87-95`). Under §1 an
absent map key now does the same — but only in strict mode. So the two converge
under strict and stay split under non-strict, where a missing key is null and a
missing index is an error. Arrays are effectively always strict on this point, and
`?` has no defined effect on an index. Whether they should soften to match maps is
genuinely unclear (the current behavior may well be the more useful one) and is
**not being settled in this iteration**. Recorded so the inconsistency is a known
position rather than an oversight.

### 3. Out of scope for this ADR

Strict mode governs **access chains only**. It does not touch:

- **Three-valued boolean logic.** `null && null` still evaluates truthy, which is
  a genuine false-green source (already flagged in `CLAUDE.md §5`). It is a
  separate change with a much larger blast radius on existing content, and strict
  chains remove a large share of the nulls that feed it. Tracked as a follow-up.
- **Comparison against a null *field*.** `nonNilDataOpV2` returning `false` stays.
  `a.f == "no"` with a null `f` is still silently false, and under §1 that is
  correct rather than a gap: the field resolved, the provider reported null, and
  nothing in the query was wrong. The mistyped-*key* version of this,
  `params.PermitRootLogn == "no"`, is caught — see §1. Whether a null field should
  also make a comparison loud is the deferred question, and it belongs with the
  boolean-logic work above, not here.
- **Provider-side null production.** Whether `Is400AccessDeniedError` *should*
  yield null instead of an error is a provider question. Strict mode changes what
  happens downstream of that null, not the decision to emit it — and by making the
  downstream consequence loud, it puts real pressure on the 771 AWS call sites to
  be revisited. That is intended, and it is the largest piece of follow-on work.
  [ADR 046](046-structured-provider-errors.md) is that work, and it settles the
  question in the direction this section anticipated: a refusal is reported as an
  error carrying a kind, not as a null, so the nulls strict mode would otherwise
  have to reason about are not produced in the first place.

### 4. Strictness is baked into the bytecode, per dereference

Strictness must travel with the compiled code, not with the executing client. A
`CodeBundle` is compiled once, checksummed, cached, shipped upstream, and replayed
against recordings; a mode that lived only in the runtime's feature set would let
the same bundle mean two different things on two nodes.

Add a tri-state to the `Function` message (`llx/llx.proto:36-42`), which is
already the node that names its receiver via `binding`:

```proto
message Function {
  string type = 1;
  repeated Primitive args = 3;
  uint64 binding = 4;
  // How this call treats a null binding.
  //   NULLABILITY_UNSET    - legacy/non-strict: null binding yields null
  //   NULLABILITY_REQUIRED - strict: null binding is an error
  //   NULLABILITY_OPTIONAL - author wrote `?`: null binding short-circuits
  Nullability nullability = 5;
}
```

Three consequences follow, and each is load-bearing:

- **`Function.checksumV2` must include it** (`llx/chunk.go:111-127`). It currently
  hashes only type, binding, and args — so without this, `a.b.c` and `a.b?.c`
  compile to byte-different, checksum-identical bytecode, and the two collide in
  the code cache and in any upstream store keyed on chunk checksums. This is the
  single easiest way to get this feature wrong.
- **The bytecode becomes self-describing.** There is no ambient "am I strict"
  question at runtime; each chunk states its own contract. Strictness is uniform
  within a policy (§6), so a bundle-level bit would be semantically sufficient
  today — but `?` is inherently per-chunk and has to enter the checksum regardless,
  and chunk checksums are what results are keyed on, so the mode has to reach that
  level anyway. Given that, carrying `REQUIRED` beside `OPTIONAL` is a small delta
  that removes an ambient-state class of bug and leaves the per-query door (§6)
  costless if it is ever opened.
- **`REQUIRED` must be explicit, not inferred from absence.** Because both modes
  persist (§6), "no marker" genuinely means non-strict rather than
  not-yet-migrated, so a single `optional` bit could not distinguish a strict
  dereference from a lenient one. This is what forces a tri-state; if strict-only
  were the near-term end state, one bit would do.
- **`[]?` stops being the encoding and becomes an alias.** New compilations emit
  `[]` with `nullability = OPTIONAL`. The `[]?` id stays registered
  (`llx/builtin.go:548,733`) permanently, because bundles carrying it already
  exist in the wild.

`CodeBundle` may carry an informational `strict` bit for reporters and
decompilation, excluded from all checksums. The semantic truth is per-chunk.

### 5. Old executors are the permissive direction

An executor built before this field ignores it and runs everything leniently. A
strict bundle then returns null exactly where it was supposed to error — a
downgrade **in the permissive direction**, which can turn a strict check green on
an old node.

Two things bound that risk, and together they are why strict content can ship
without an engine-side gate.

**The syntax is already understood across the supported window.** `?` has parsed
and compiled since [#6633][pr6633] in v13, and MQL support is retired every two
majors, so the oldest engine that can receive content is v13. Optional-marked
content is accepted everywhere in that window — it compiles, it runs, and it
returns the same values. Only the *enforcement* is new, and enforcement is what
v14 adds.

**What an old executor loses is verification, not correctness.** A v13 node runs a
strict bundle non-strict: every result it produces is a result it would have
produced anyway. Nothing breaks, nothing is misreported as a value; the check
simply verifies less than the policy claims. That is a reason to know which nodes
ran it, not a reason for the engine to refuse the bundle.

So the minimum version is **declared, not enforced by the engine**. A bundle
containing `NULLABILITY_REQUIRED` chunks records a v14 floor in
`CodeBundle.min_mondoo_version` (`llx/llx.proto:138`), stamped from the language
feature table in [ADR 040](040-cross-version-type-migration.md)'s min-MQL-version
axis. mql itself does not branch on it — see
[the language-versioning draft](draft-mql-language-versioning.md) for why a
version floor is the wrong instrument for a capability question.

**The consumer is cnspec.** A policy that declares strict mode has to carry a
corresponding minimum version requirement, so the platform does not hand it to a
node that would run it non-strict. That is a policy-authoring concern, where the
declaration already lives (§6), not an executor concern.

### 6. The switch: per-content opt-in, config default underneath

Strict mode is **opted into by the content**, not by the client. A policy declares
whether it is strict, because a policy's outcome has to be predictable regardless
of which operator runs it and with what config. That declaration lives in the
cnspec bundle schema; mql's job is the compile-time knob it drives
(`mqlc.CompilerConfig`) and the precedence rule.

**The policy is the unit, and the only unit.** A declaration applies to the entire
policy, uniformly. Nothing below it — a query, a check, a variant — can override
it; inside a strict policy the only escape is `?` on the individual link, which is
the whole reason the operator exists. Per-query granularity is a door left open,
not a plan: it would be reached for only under real pressure, because it trades
away the property the declaration is there to provide. A reader should be able to
answer "is this policy strict?" without reading its queries.

**Query packs need no separate rule.** They live in cnspec and run on the policy
framework, so they inherit the declaration, the precedence, and the lint without a
second mechanism.

Resolution is a two-level fallback:

1. **The content's own declaration** — a policy that says strict, or explicitly
   says non-strict, gets what it asked for.
2. **The config default** — a tri-state `strict` key in `CommonOpts`
   (`cli/config/config.go:262-303`), used whenever the content carries no setting.
   It must be `*bool`, not `bool`, so "unset" stays distinguishable from "false";
   `Features []string` sitting two fields above is the wrong shape here precisely
   because a feature flag cannot express "explicitly off".

Deliberately **not** a `features.yaml` flag. That mechanism is global and
client-side: flipping it reinterprets every query the client holds, including
third-party policy content the operator did not author and cannot fix. That is the
shape of the thing [#7079][pr7079] deferred, and reaching for it again would
reintroduce the same problem under a new name. The compiler already takes its
configuration from `CompilerConfig` (`mqlc/mqlc.go:89-111`), which is per-compile,
so per-content strictness needs no new plumbing — only a field that is not
`Features`.

**v14 requires every policy to state its mode.** Not "defaults to non-strict" —
*stated*, one way or the other, enforced by a linter. An unstated policy is one
whose result depends on the operator's config file, which is exactly the
unpredictability this design exists to remove. The config default covers ad-hoc
surfaces (shell, `mql run`, `mqlx` embeddings) where there is no content to carry
a declaration; it is not a fallback that policies are allowed to rely on.

**Both modes persist for now.** Strict-only is the intended end state but is some
way off and needs considerably more verification first. Two consequences follow
directly: non-strict compilation stays a first-class path rather than a
deprecation, and the bytecode must carry `REQUIRED` explicitly rather than
inferring it from absence — see §4, where this is what forces the tri-state over
a single `optional` bit.

## Implementation status

Landed in mql (parser through to the config knob). Strict mode is off by default;
with it off nothing is marked and every checksum is byte-identical to before.

1. **Parser — `?` in every position.** The mark attaches to the link on its
   **left**: the last call, or the operand's root value when there is no call yet
   (`Operand.ValueIsConditional`). One rule covers `a?.b`, `a.b?.c`, `a?["k"]`,
   `a? { … }`, and a trailing `a.b?` / `a.b? == "no"`, all of which previously
   parsed and silently dropped the mark. The old stickiness is gone: `?` no longer
   carries across a dotted run, which is what makes the semantics non-sticky.
2. **Wire format.** `Function.Nullability` (`llx/llx.proto`), folded into
   `Function.checksumV2` **only when set**, so pre-existing checksums do not move
   — `TestCompiler_DeterministicChecksum` still passes with its hardcoded id.
3. **Compiler.** `CompilerConfig.Strict`; each link is marked as it is emitted.
   `[]?` is retired as an encoding in favor of `[]` plus the marker, with the
   `[]?` handler kept registered for bundles already compiled.
4. **Runtime.** One decision point ahead of builtin dispatch
   (`llx/builtin.go`, `runBoundFunction`), plus the absent-key rule inside
   `mapGetIndex` / `dictGetIndex` — the branch [#7079][pr7079] removed.

Two things went differently from the plan, both simplifications:

- **The 104 nil branches were not unified.** The decision point sits *ahead* of
  dispatch and only intercepts marked chunks, so under non-strict every branch
  still runs exactly as before. Unifying them is no longer a prerequisite; it is
  optional cleanup.
- **The short circuit needed no executor surgery.** A null produced by an optional
  link is tagged (`RawData.ShortCircuited`) and a required link passes a tagged
  null straight through. That is what makes `a?.f.c` yield null when `a` is null
  while still erroring when `a` is set and `f` is null. The alternative - having
  the executor skip downstream chunks - would have collided with block completion
  counting expected codepoints (`llx/llx.go:497-546`), which hangs rather than
  errors when a callback point never reports.

Landed in cnspec (the policy declaration, §6):

5. **`Policy.strict` and `QueryPack.strict`**, tri-state, carried across
   `ConvertQuerypacks`. Resolved by `Policy.EffectiveStrict(default)` and stamped
   onto the per-policy compile in `CompileExt`. It also enters the policy's
   execution checksum, so a policy compiled both ways cannot resolve to one
   cached plan.
6. **The operator's default** rides `LocalServices.Strict` /
   `scan.WithStrict()`, fed from the `strict` config key and `--strict`. It only
   decides what an *undeclared* policy inherits.
7. **A conflict guard.** Queries live at bundle level and are shared by MRN, so
   one query is compiled once per referencing policy, each time overwriting its
   checksum and code id. Two policies disagreeing about the mode used to mean the
   last one compiled decided the semantics for both; that now fails the bundle
   instead.
8. **The lint rule**, opt-in behind `LintOptions.RequireStrictDeclaration` and
   `cnspec policy lint --require-strict-declaration`. It fires on every policy
   written before the field existed, so enabling it by default would bury real
   findings under migration noise. It becomes the default in v14.

One trap worth recording, because nothing about it is visible from the mql side.
A query is recompiled well after the bundle is built - the resolver rebuilds
executable code (`mquery2executionQuery`), and the datalake refreshes checksums -
each time from a compiler config that knows nothing about the owning policy. The
first cut compiled the bundle strict and the execution job lenient, so the
reporting job waited on checksums the execution job never produced and the check
came back **unscored**: not passing, not failing, simply absent from the report.
The fix is that a query records the mode it was compiled under
(`Mquery.strict`, derived rather than authored) and `Mquery.Compile` honors it,
which makes every later recompile agree by construction. Any future code path
that recompiles a query has to keep going through `Mquery.Compile`.

Not yet done:

9. **cnspec declares the minimum version for a strict policy** (§5). mql stamps
   the v14 floor into `CodeBundle.min_mondoo_version` (`mqlc/provenance.go`, from
   the feature table in `mqlc/engine_version.go`) and deliberately does not act
   on it. What is missing is the other end: a policy that declares strict mode
   has to carry a matching minimum version requirement, so the platform does not
   hand it to a v13 node that would run it non-strict. This does not block
   shipping strict content — a v13 node runs it, and runs it leniently — it
   decides whether we can tell that apart from a node that verified it.
10. **Asset filters follow the bundle default, not the policy.** Filters are
    deduplicated across policies by code id, so compiling one two ways would
    split matching rather than just change the mode. They are predicates over
    asset metadata rather than assertions, so they gain little from strictness -
    but it is a documented seam, not a uniform rule.
11. **Later, and separately: streamline.** Reducing the ceremony and eventually
    retiring non-strict is future work, gated on evidence from real v14 policy
    runs rather than on a release date.

## Caveat: replaying non-strict recordings

A recording stores **resource fields**, keyed by resource, id, and field name,
holding the whole `RawData` value (`providers-sdk/v1/recording/recording.go:405-443`
and `:514-529`). That shape decides how faithfully strict mode can replay, and it
treats the two causes of a null receiver (§1) differently:

- **Map keys replay correctly.** A key is not a recorded unit; the map or dict is
  recorded whole, as one field value. An absent key is therefore genuinely absent
  from the recording, and a strict replay errors at the lookup exactly as a live
  strict run would. The concern that a recording would have "invented" a null for a
  missing key does not apply — there was never a per-key entry to invent one in.
- **Field nulls lose their provenance, and this is the caveat.** A field recorded
  as null could have been legitimately null, or a provider call that failed and
  degraded to null (`Is400AccessDeniedError` and the ~3,500 `StateIsNull` sites).
  The recording keeps the value and drops the reason, so a strict replay cannot
  tell the two apart and treats both as a null receiver. Note that live execution
  cannot tell them apart either — the collapse happens in the provider, not in the
  recording — so replay is no worse than the original run. It is documented here
  because it looks like a recording defect and is not one.

The practical consequence is narrower than it first appears: a recording captured
non-strict and replayed strict will **error where the capture succeeded**. The
underlying data is identical; only the interpretation changed. Anyone diffing a
strict replay against its non-strict capture should expect that, and it is not a
regression.

One genuine gap remains, and it is not strict-specific: a recording only contains
fields that were actually *requested* during capture, and a non-strict run
short-circuits. `a.f.c` with `f` null never requests `c`, so `c` is absent from the
recording, and a later query that needs it finds nothing. That is ordinary
recording incompleteness, which strict mode neither causes nor fixes.

## Consequences

**Good:**

- A broken chain names the link that broke, instead of producing a null that
  looks like a finding.
- Under-permissioned scans stop resembling clean ones. This is the single largest
  behavioral win and the single largest migration cost — the same 771 AWS
  access-denied sites are responsible for both.
- The 104 per-builtin nil branches answer to one rule, in one place, instead of
  each site deciding for itself.
- `?` becomes documentation: a marked chain says "this is legitimately absent
  sometimes," which is information the schema does not carry today.

**Costs and risks:**

- **A mistyped key becomes an error instead of a silent `false`.** This is the
  case strict mode most needs to catch, and it is only catchable because the
  lookup errors rather than the dereference (§1).
- **A policy that opts in breaks loudly**, including the dict chains
  [#7079][pr7079] deferred. That is what opting in means, and it is why the
  diagnostic pass in step 6 exists: an author should see every unguarded
  dereference in their policy before they flip it, not after.
- **The v14 lint is itself a migration cost.** Every existing policy has to be
  touched to state a mode, including the large majority that will state
  non-strict and change in no other way. Unavoidable if outcomes are to be
  predictable, but it is churn across the whole content estate.
- **Two live modes is a permanent tax until it is not.** Every nil-handling
  decision, test, and diagnostic now has two correct answers, and the VM carries
  both paths. Accepted deliberately, with strict-only as the eventual exit.
- **The checksum change is a compatibility event.** Bundles recompile and
  re-checksum. It rides the same machinery ADR 040 exists to manage, but it is not
  free.
- **`?` noise on genuinely-sparse schemas.** Some resources return null for most
  fields most of the time, and their queries will grow a lot of question marks.
  The alternative is those queries silently reporting nothing, so this is the
  right trade — but it will be the loudest complaint.
- **Nullability is not in the schema.** The compiler cannot tell "this field is
  never null" from "this field is usually null", so it cannot warn about a
  redundant `?` or a definitely-missing one. See open questions.

## Open questions

- **Should `.lr` declare field nullability?** §1 rests on "a field should hold a
  valid value of its declared type, and null is not one unless the type says so" —
  but no type in the schema says so today, so the rule is a convention the compiler
  cannot check. If `.lr` carried it, the compiler could reject a pointless `?` and
  demand a missing one, turning strict mode from a runtime rule into a static
  check. Large schema project (~3,500 `StateIsNull` sites to audit); should not
  gate this ADR, but strict mode is what would make it pay off.
- **Do arrays ever converge with maps?** An out-of-range index errors in both
  modes today, so arrays are already strict on a point where maps are about to
  become strict only on opt-in (§2). Softening arrays to match would need a guard
  spelling for the index itself, and it is not obvious the current behavior is even
  wrong. Left open, explicitly not addressed in this iteration.

## Alternatives considered

- **Insert an explicit `$notNull` guard chunk between links.** Needs no proto
  change, participates in checksums automatically, and fails *loudly* on old
  executors ("unknown function") instead of silently downgrading — a genuinely
  better failure mode. Rejected on size: it roughly doubles the chunk count for
  access chains, and every chunk is a ref, a cache entry, and a checksum.
- **Encode strictness in the chunk id, as `[]?` already does.** Works for
  accessors and breaks for fields, because `chunk.Id` *is* the field name — it
  indexes `resource.Fields[chunk.Id]` (`llx/builtin.go:856`) and is passed to
  `WatchAndUpdate` (`llx/builtin.go:850`). Suffixing it would require stripping at
  every consumer. Rejected.
- **A single bundle-level `strict` bit, with no per-chunk marks.** Smaller, but it
  makes chunk checksums identical across modes for every unmarked dereference, so
  two semantics share one key. Rejected for the same reason the checksum has to
  include nullability at all.
- **A pure runtime flag, no wire change.** Cheapest to build and wrong: the same
  compiled, cached, upstream-shipped bundle would mean different things on
  different nodes, and recordings would replay under whatever mode the replayer
  happened to have. Rejected.
- **A `features.yaml` flag (`MQLStrictMode`), the ladder MassQueries and PiperCode
  took.** The obvious move, and the wrong one here: a feature flag is global,
  client-side, and two-state, so it cannot express "this policy is explicitly
  non-strict" and it reinterprets third-party content the operator cannot fix.
  Rejected in favor of a content declaration with a tri-state config default; see
  §6.
- **Extend [#6633][pr6633] to resource fields with no opt-in.** The same ordering
  mistake [#7079][pr7079] deferred, over a far larger surface: dict chains are a
  fraction of what resource fields are. Rejected.
- **Declare strictness per query or per check instead of per policy.** Finer
  grained, and it would let a large policy adopt strictness a check at a time.
  Rejected for now: it makes "is this policy strict?" a question you answer by
  reading every query in it, which is the predictability the declaration exists to
  provide. The door stays open, but it needs a forcing case, not a convenience
  argument. `?` already covers the in-policy escape.
- **Skip non-strict entirely and go strict-only in v14.** Tempting, since
  strict-only is the intended end state. Rejected as premature: the behavior needs
  far more verification against real policy runs first, and there is no way back
  from it if the verification turns up something. Both modes ship; strict-only is a
  later decision made with evidence.
- **Settle the 104 nil branches one at a time instead.** This is the current
  approach, and it produced the current state. Each site can only reason about its
  own call, so the branches cannot converge on a rule an author could rely on, and
  a change to any one of them is indistinguishable from a change to the language.
  Rejected.
