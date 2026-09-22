# Adding fields and resources from a new SDK version

Read during Phase 5 (enum comments) and Phase 7 (implementing the user's selection). This
covers only what an SDK upgrade specifically makes tricky; AGENTS.md remains the authority
on `.lr` style, doc-comment shape, and the typed-reference gate.

## Contents

- [Before you add anything: is it real data?](#before-you-add-anything-is-it-real-data)
- [Version entries](#version-entries)
- [Typed references](#typed-references)
- [When a value earns a sub-resource](#when-a-value-earns-a-sub-resource)
- [Null versus zero](#null-versus-zero)
- [Discriminated unions](#discriminated-unions)
- [Enum comment drift](#enum-comment-drift)
- [Codegen mechanics](#codegen-mechanics)

## Before you add anything: is it real data?

A field existing on an SDK struct does not mean it arrives populated. Three traps, each of
which produces a field that confidently reports a wrong value on every asset:

**Request-flag-gated fields.** The value only populates when the request sets a flag we
don't set. Alibaba's `DescribeDBInstances` fills `AutoRenewal` only when sent with
`QueryAutoRenewal`; Databricks fills `TriggerDetails` only with `include_trigger_state`.
Exposed as-is, these read `false`/empty everywhere. Either set the flag deliberately — a
behavior change to the lister worth its own consideration — or leave the field out.

**Detail-only fields.** Present on the detail response, absent from the list response. If
the resource is built from a list, the field needs a lazy accessor backed by the detail
call, not a plain field. Look for an existing cached-fetch helper on the resource before
adding a second one.

**Deprecated fields.** Often return empty on modern resources because the data moved.
Check for `// Deprecated:` on the SDK field before modelling it.

The general test: can you name the API response that populates this, and is that the
response the provider actually fetches? If not, don't ship the field.

## Version entries

Every new resource and field needs a line in `<provider>.lr.versions`, at the provider's
**current version plus a patch** — read `Version` from `providers/<name>/config/config.go`,
not the highest number already in the versions file, which may be stale from before a
major bump.

`mqlr generate` writes these for you and gets it right; verify rather than hand-edit.

Do **not** bump `config.go`'s `Version` — that belongs to the release flow.

## Typed references

AGENTS.md's gate applies to every new field: a value that identifies another modeled
resource should be a typed accessor, not a raw ID string. Two SDK-upgrade-specific
cautions:

**Check the target has an `init`.** `NewResource` runs the target's `init`; without one you
get a husk with unset fields, which surfaces client-side as `llx: encountered a primitive
with no type information`. If the target resource is only ever built from a list, resolve
by scanning that cached list instead — several providers already have a `resolve*` helper
doing exactly this.

**Count the API calls.** Resolving a parent per child turns one list into N calls. Prefer a
cached list scan. Where the reference genuinely needs a per-item call, a lazy computed
accessor is acceptable — it costs nothing unless queried — but say so in the PR, especially
for providers with tight rate limits.

If neither is workable, ship the raw value and note the typed accessor as follow-up rather
than shipping something that returns empty.

## When a value earns a sub-resource

AGENTS.md's bar: a clear natural ID, or nested typed references. Otherwise flatten scalars
onto the parent with a disambiguating prefix, or use `map[string]string` / `[]dict`.

The upgrade-specific hazard is **`__id` collisions on shared values**. A struct that is
shared between parents cannot key a sub-resource on its own ID: GitHub's pull-request
`Stack` has a stack ID, but every PR in the stack shares it while `position` differs per
PR. Keying on the stack ID would cache one instance and report one member's position for
all of them. Flattening onto the parent avoids it entirely.

When a synthetic key is unavoidable (an ordered list with no natural key), pass it via the
magic `"__id"` argument as `<parentId>/<thing>/<index>` and do **not** declare an `id`
field — a synthetic key isn't something a user would ever query by.

## Null versus zero

The distinction carries real meaning, and getting it wrong produces confident wrong
answers rather than errors.

Report **null** when the value is absent, inapplicable, or unreadable. Report a **zero
value** only when zero is the actual answer.

The test that makes it concrete: can the zero value also be a legitimate reading? GitHub's
stack `position` counts from 1, so 0 could only mean "not in a stack" — but `size: 0` at
`position: 0` reads as a real stack to a policy comparing numbers, so all the stack fields
stay null when the PR isn't stacked. Likewise an empty list asserts "there are none",
which a permission-denied read has not established; degrade those to null.

Use `llx.NilData` for the absent case and set `StateIsSet | StateIsNull` when returning
`nil, nil` from a singular resource accessor or a list accessor.

## Discriminated unions

SDKs model "exactly one of these is set" as a struct of optional pointers. Model it as one
resource with a `<thing>Type` discriminator plus the union of the members' fields, only the
relevant ones populated — that's how existing providers handle it.

Give the flattener a `default` branch that reports `unknown` rather than empty, so a member
this SDK version models but the provider doesn't classify still appears.

Then **add a reflection test** that walks the union's members and fails when one isn't
classified. Without it, the next SDK upgrade adds a member, the flattener keeps compiling,
and those entries quietly report an empty type. Several providers already have this test;
copy the local one rather than inventing a shape.

## Enum comment drift

`enumdrift.py` reports `.lr` comments enumerating values the SDK has grown past. Fixing
them is cheap and worth doing in the same PR, with two judgment calls:

- **Confirm the pairing.** Unrelated enums share vocabulary; the tool guesses by overlap.
- **Confirm the omission is accidental.** A comment may deliberately list the subset we
  map, or the subset that is meaningful for the field. If so, leave it and consider saying
  why in the comment.

When adding values, keep the existing prose shape (`One of A, B, or C.`) and remember the
doc-comment rules: a one-line comment, or a title plus a blank `//` plus the description —
never two contiguous comment lines, which fails the parse.

## Codegen mechanics

```bash
make providers/mqlr
./mqlr generate providers/<name>/resources/<name>.lr --dist providers/<name>/resources
```

Two gotchas that cost real time:

- **Internal structs need a second pass.** Adding a `mql<Resource>Internal` struct after
  the first generation means running `generate` again for the generator to embed it. The
  same applies on removal — the stale embed lingers and the build fails with
  `undefined: mql<Name>Internal`.
- **Generated files are not sacred but are not editable.** If a bulk rename touches
  `*.lr.go`, restore it from HEAD and regenerate rather than hand-fixing.

Only `aws`, `azure` and `gcp` carry a `*.permissions.json`. If the upgrade adds an API call
in one of those, rebuild the provider so the manifest regenerates, and commit it.
