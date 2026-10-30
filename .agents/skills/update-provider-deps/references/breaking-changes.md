# Breaking changes and backwards compatibility

Read during Phase 4, after the build is green. A clean build says the code compiles against
the new SDK; it says nothing about whether the data reaching MQL still means what it did.

## Contents

- [The three kinds of break](#the-three-kinds-of-break)
- [Silent-break taxonomy](#silent-break-taxonomy)
- [Decision table: what to do about a shipped field](#decision-table-what-to-do-about-a-shipped-field)
- [Deprecations](#deprecations)
- [What "backwards compatible" means here](#what-backwards-compatible-means-here)

## The three kinds of break

Sort every finding into one of these, because the response differs completely.

**1. Compiler-caught.** A removed method, a changed parameter list, a struct field that no
longer exists. The build fails, you fix the call site, done. These are the cheap ones and
they need no ceremony.

**2. Compiles, behaves differently.** A method renamed to something that still exists with
a different meaning, a value that changed units or nullability, a field that moved to a
different struct. Nothing fails. These are found by reading the release notes and the
struct diff, which is why Phases 2 and 4 exist.

**3. Compiles, and changes what a customer's query returns.** Any of the above where the
affected value feeds a field already declared in `.lr`. These are the ones with a blast
radius beyond the repo, and they are the reason the decision table below exists.

The test for kind 3 is mechanical: take the changed SDK field, find the `CreateResource`
argument or accessor it feeds, and check whether that key appears in the provider's `.lr`.
If it does, a customer may have a policy reading it.

## Silent-break taxonomy

Patterns seen repeatedly across Azure, Atlas, Okta, Databricks and Nutanix upgrades.

| Pattern | How it shows up | What to do |
|---|---|---|
| **Scope split** — `ListThings` becomes `ListOrgThings` + `ListGroupThings` | Both take `(ctx, string)`. Wrong choice compiles and silently reads the wrong scope. | Check each call against the identifier it passes (`orgID` vs `projectID`), not against the build. |
| **Mass accessor rename** — `XxxApi` → `XxxAPI` | Dozens of call sites, all compiler-caught, so it looks trivial | Usually is trivial, but check whether any accessor was *deleted* rather than renamed. Deleted ones are functionality loss, not a rename. |
| **Value type change** — `*string` → `*time.Time`, `*string` → `*int64`, enum → typed enum | Compiler-caught at the mapping, but the *field's meaning* may change | If it feeds a shipped `.lr` field, go to the decision table. A `time` field fed by an epoch `int64` needs conversion, not a cast. |
| **Struct-to-string** — a nested struct becomes a serialized string | Compiler-caught, but a `dict` field's shape changes | Kind 3. A query traversing into the dict starts returning null. Deprecate and add. |
| **Pointer-ization** — a value field becomes a pointer | Compiler-caught | Guard nil and decide what nil *means*. Dropping the item from a list under-reports; prefer keeping it with an empty inner value. |
| **Sync → long-running** — `Update` becomes `BeginUpdate` | Compiler-caught | Use the `Begin*` form plus `.PollUntilDone(ctx, nil)`. Rare in a read-only provider. |
| **Subpackage extraction** — a service moves to its own module | Compiler-caught, "package not found" | Add the new module to `go.mod` and import it. |
| **Enum member removed** | Not caught at all if we store the raw string | Feeds Phase 5. If a `.lr` comment enumerates it, fix the comment. |
| **Write-API churn** | Not caught, because we never call it | No action. mql is read-only: an SDK major whose entire breaking-change list is create/update/delete methods costs us nothing. Check before spending time on it. |

## Decision table: what to do about a shipped field

Once a change is kind 3, the rule from AGENTS.md governs: **never change a shipped field's
type or meaning in place.** Customers have policies compiled against it.

| Situation | Response |
|---|---|
| SDK renamed the source but the value is identical | Nothing user-visible. Fix the mapping, move on. |
| SDK retyped the source, same meaning (`*string` → typed enum with the same strings) | Convert at the mapping so the MQL field keeps its type and values. This is the common case and it is genuinely backwards compatible. |
| SDK retyped the source, different meaning (`*time.Time` → epoch `*int64`) | Convert so the MQL field keeps its declared meaning. A `time` field must stay a real timestamp. |
| SDK changed the shape of a `dict` field's payload | Not convertible. Keep the old field, mark it `@maturity("deprecated")` with a description leading `Deprecated in favor of ...`, add the new shape under a new name. |
| SDK **removed** the source entirely | The field can no longer be populated. Mark it `@maturity("deprecated")` and explain in the description. Do not silently null it and do not delete it — deleting is a breaking schema change. |
| SDK added a value to an enum we map into a bool | Re-check the bool's derivation. A two-state assumption that just gained a third state is now wrong for the new value. |

Two things that are *not* acceptable responses, both of which look like fixes:

- **Silently nulling a field** whose source disappeared. A null reads as "we looked and
  there was nothing", which is a different claim from "we can no longer see this".
- **Changing the field's type in place** because the SDK did. That breaks every policy
  using it, in exchange for saving one deprecation.

## Deprecations

A method that still exists but is marked `// Deprecated:` is a judgment call, not a fix.

Take the replacement when it is shaped the same. Leave the deprecated call when adopting
the replacement would change the MQL schema — for example when a singleton getter is
replaced by a list-plus-get pair, turning one resource into a collection. That is a schema
change nobody chose in this run, so it belongs in a PR of its own rather than being absorbed
into the migration. (This is not in tension with bundling the Phase 6 additions into the
provider's PR: those were picked deliberately and reviewed as part of the upgrade. This one
would arrive unannounced, as a side effect of a call-site edit.)

Either way, leave a comment at the call site saying which it is and why, so the next
upgrade doesn't have to re-derive the reasoning.

The same applies to *fields*: AGENTS.md says to skip deprecated SDK fields when adding new
schema. A deprecated field often returns empty on modern resources because the data moved,
so modelling it adds dead schema.

## What "backwards compatible" means here

Concretely: a policy written against the provider before the upgrade returns the same
answers after it, or fails loudly. What must not happen is the same query returning a
different answer with no signal.

That standard is why deprecation beats mutation, why null and zero are not
interchangeable, and why a changed `dict` shape is treated as a break even though nothing
in the type system noticed.
