# Provider bug taxonomy

The catalogue of bug classes that recur in mql providers, ordered roughly by how
badly they hurt users. Each entry: **what it is**, **fingerprint** (how to spot
it), **why it matters**, and the **correct pattern**. This is the checklist the
analysis agents work from and the reference you verify against.

A theme runs through the worst of these: the bug produces *wrong data with no
error*. A panic at least announces itself. A pagination loop that returns one
page, a field that resolves differently through two code paths, or a **stub that
invents an authoritative-looking absence** hands the user a confident wrong
answer. Weight those highest.

---

## 0. Stub / placeholder / fabricated data (silent data loss — RANK AT THE TOP)

**What:** an accessor or field that returns fabricated, hardcoded, or empty data
instead of the real value — code that never actually fetches or parses what it
claims to expose. **All data a resource surfaces must be real.** This is the
single worst class: other bugs mangle data that's at least present, but a stub
invents an authoritative-looking *absence* ("this account has zero Pages
projects"), so a security audit over it passes *vacuously* — nothing to fail on.

**Fingerprints:**
- An accessor whose whole body is `return nil, nil` / `return []any{}, nil` /
  `return "", nil` with **no API call or parse** — a not-yet-implemented stub
  shipping empty. Real Cloudflare example: `workers.pages()` was `return nil, nil`,
  so every account looked like it had no Pages projects.
- A field hardcoded to a literal `""`, `false`, `0`, or `{}` in `CreateResource`
  where the SDK/API actually returns a value (distinct from a value the API
  genuinely omits — see the caveat).
- `// TODO`, `// not implemented`, `// placeholder`, `// stub`, `// for now`
  comments near a resource method or field.
- A `.lr`-declared field or accessor with no corresponding real population in Go.

**Why it matters:** it compiles, returns no error, and looks valid. A user or
policy concludes "there's nothing here" when there is — the most dangerous
possible answer in a security-inventory tool.

**Correct pattern:** every declared field/accessor is populated from real
fetched/parsed data. If it can't be implemented yet, **remove the field** rather
than ship a stub that returns empty. When you find one, rank it with
silent-data-loss/panic at the top of the report; when fixing, implement it
against the real endpoint (or delete it), never leave the empty stub.

**Verify by:** reading the accessor body — does it actually call the client /
parse the source, or just return a zero value? Cross-check every `.lr` field has
a real Go population path. Route to `provider-verification` to confirm the real
endpoint returns data if you can't tell statically.

**Caveat:** a genuinely absent value the API doesn't return (a deprecated SDK
field, a field the list endpoint omits) is *not* a stub — that's correct
null/empty handling. The stub bug is claiming to expose data and then not
fetching it.

---

## 1. Pagination truncation (silent data loss)

**What:** a list endpoint returns only the first page of results, silently
dropping the rest.

**Fingerprints:**
- A `List...` call whose SDK response supports paging but the code never loops.
  For the header-cursor SDKs (okta): initial `.Execute()` returns `(slice, resp, err)`
  but there's no `for resp.HasNextPage() { resp, err = resp.Next(&slice); ... }`.
  For token SDKs (aws/gcp/azure): a response with `NextToken`/`nextPageToken`/
  `marker`/a pager `.More()` that's read once, not looped.
- A **hand-rolled HTTP client** (in `resources/sdk/`) that does one `GET` and
  never follows the `Link: rel="next"` header. These are the highest-risk spot —
  the SDK's automatic paging is bypassed, so the loop must be written by hand and
  is easy to forget.
- A **hardcoded small limit** like `?limit=50` on a raw fetch, especially with no
  next-page follow — a double bug (small page *and* truncated).
- Missing `.Limit(queryLimit)` / max page size. This one is usually **perf-only,
  not data loss** — if the `HasNextPage` loop is present, results are complete,
  just fetched in more round-trips. Flag it, but rank it low.

**Why it matters:** an audit that counts or inspects a collection (policy rules,
role bindings, users in a group) is silently wrong past the first page. No error
surfaces. Real Okta example: `fetchAccessPolicyRules` did `GET .../rules?limit=50`
with no `Link` follow while the sibling path paginated correctly — any policy
with >50 rules lost the rest.

**Correct pattern:** every paginated list loops until the SDK says there are no
more pages; hand-rolled fetches follow the `Link: rel="next"` header (or the
token) in a loop, ideally bounded by a `maxPages` guard so a malformed/cycling
cursor can't hang the whole scan.

**Verify by:** confirming the SDK response type actually exposes a next-page
signal (read the SDK source), and that the loop consumes it.

---

## 2. Nil dereference / panic on real-world data

**What:** dereferencing an SDK pointer or asserting a type without a guard, on a
value that is legitimately null/absent in some accounts.

**Fingerprints:**
- `*entry.Field` or `entry.Field.Sub` where `Field` is a `*string`/`*bool`/
  `*time.Time` or a nested pointer, without going through the nil-safe helper
  (`<provider>Str()`, `oktaBool()`, `llx.*DataPtr()`) or a `== nil` check.
- **Bare type assertions on runtime/JSON data**: `x := v.(T)` instead of
  `x, ok := v.(T)`. A panic here is not local — the executor runs blocks in
  goroutines, so a panic **crashes the entire scan**, not just one query. Guard
  every assertion on `arg.Value` / `map[string]any` values / `AdditionalProperties`
  with comma-ok or a `== nil` check.
- A response object dereferenced right after the error check on the assumption
  it's non-nil (`resp, _, err := Get(...); if err != nil {...}; x := resp.Field`)
  — if the API can return `(nil, nil)`, that's a panic. Sibling inits usually
  guard `if resp == nil`; a missing guard where siblings have one is a tell.

**Why it matters:** panics crash scans; and OpenAPI-generated SDKs model almost
every scalar as a pointer precisely because "absent" is common.

**Correct pattern:** pointers go through nil-safe helpers; assertions use
comma-ok; response bodies are nil-checked before use.

---

## 3. Singular resource accessor returns nil without StateIsNull

**What:** a computed accessor returning a single resource pointer (`(*mqlXxx, error)`)
does `return nil, nil` for the legit-null case without first marking the field
set-and-null.

**Fingerprint:**
```go
func (a *mqlFoo) bar() (*mqlBar, error) {
    if id == "" {
        return nil, nil   // BUG: runtime doesn't know the field resolved
    }
```
Correct:
```go
    if id == "" {
        a.Bar.State = plugin.StateIsSet | plugin.StateIsNull
        return nil, nil
    }
```

**Why it matters:** without the state flag the runtime doesn't know the field was
resolved to null and may panic or re-fetch indefinitely. Applies to **every**
`return nil, nil` path in such an accessor: empty id, access-denied fallback, nil
API response, unset optional. Does **not** apply to functions returning slices,
maps, or scalars — only singular resource pointers.

---

## 4. Init fall-through husk

**What:** a singular resource's `init` returns `args, nil, nil` after a lookup
that found nothing, instead of a not-found error.

**Fingerprint:** an init loop that searches for a match and ends with
`return args, nil, nil` when no match was found (as opposed to the legitimate
early "args already complete" fast-path like `if len(args) > 2 { return args, nil, nil }`).

**Why it matters:** returning no resource *and* no error tells the runtime to
build the resource from whatever partial `args` exist (often just an id/arn),
leaving every other field **unset** (not null — unset). Any query touching those
fields surfaces client-side as `llx: encountered a primitive with no type
information, coercing to null`, with no attribution. Return a not-found error
instead. Same for intermediate failures inside the init (an ARN that won't parse).

**Note the nuance:** a *bare resource with no id* is a valid empty state and
should return `args, nil, nil`. The bug is specifically the *lookup-miss*
fall-through.

---

## 5. Caching / `__id` bugs

**What:** wrong or colliding cache keys, so resources overwrite each other or
never cache.

**Fingerprints:**
- **`CreateResource` where `NewResource` is required.** Only `NewResource` runs a
  resource's `init`. If a resource's identity (`__id`) is computed *in* its init,
  or it's a parameterized resource (an access-review / who-can lookup keyed on
  args), `CreateResource` skips init → the `__id` stays empty and every instance
  collides in the cache → every query returns the first one's result.
- **Empty or duplicated `__id`.** A new resource created without a stable unique
  `__id` (and without an `id()` method) collides. Review caught exactly this: a
  sub-resource missing `__id` used an empty cache key and every row aliased.
- **Non-unique `id()`.** An `id()` that returns a value shared across instances.
- **Typo'd `__id` prefix.** Cosmetic if still unique (e.g. `okta.trustedOriogin/`),
  but a real defect — flag it low.

**Correct pattern:** every resource has a stable, unique `__id` — an ARN, a
GCP resource name, a composite `<parent>/<leaf>`. Hide synthetic composite ids
(pass `"__id"` directly, no public `id` field); expose `id` only when it carries
user-meaningful, queryable information.

**How the `__id` is actually set (read this before judging any `__id` finding).**
The generated `createXxx` does `SetAllData(res, args)` then, *only when the
result is still empty*, falls back to the `id()` method:
```go
SetAllData(res, args)          // sets res.__id from an explicit "__id" arg, if passed
if res.__id == "" {            // otherwise, and ONLY otherwise:
    res.__id, err = res.id()   // ...call the id() method
}
```
Consequences to reason from:
- An explicit `"__id"` arg **wins** over `id()`. So an `id()` that depends on an
  Internal-struct field set *after* `NewResource` returns (e.g. `zoneID` assigned
  post-construction) is silently bypassed if you also pass `"__id"` — and is
  *wrong* (empty field) if you rely on it. Fix by passing `"__id"` explicitly.
- A resource with **neither** an `id()` method **nor** an `"__id"` arg gets the
  empty key and every instance collides (the classic silent aliasing bug).
- To confirm any `__id` finding, open the generated `createXxx` in `*.lr.go` and
  check which of these paths the resource takes.

---

## 6. `null && null == true` — unset booleans pass assertions

**What:** an init-miss stub or degraded resource leaves boolean fields as
`StateIsNull` instead of explicit `false`.

**Fingerprint:** a not-found / access-denied path that creates a resource but
doesn't set its bool fields; or a stub returning without explicit `false` values.

**Why it matters:** MQL uses three-valued logic where `null && null` evaluates to
`true`. A `{ a && b }` assertion over such a stub passes even though nothing was
actually verified — a false sense of security in a security scan. Misses and typos
must **fail**, so degraded/stub resources need explicit `false`, not null.

---

## 7. Typed-reference gate misses (data-model bug, expensive to fix later)

**What:** a field that identifies or points at another modeled resource is shipped
as a raw `*Id` / `*Arn` / `*Url` string instead of a typed accessor.

**Fingerprints:** `projectId string`, `vpcId string`, `roleArn string`,
`networkUrl string` (GCP self-links), `subnetIds []string`, etc. — where the value
names something the provider models as a resource.

**Why it matters:** it blocks MQL traversal (`aws.rds.proxy.vpc.cidrBlock`), and
replacing a shipped `projectId string` with `project() <provider>.project` later
is a **breaking change** (version bump + consumer migration). So it's worth
catching in review of *unreleased* resources especially. The fix: store the raw
id in a `cache*` field on the Internal struct and resolve via `NewResource` in a
typed accessor named for the domain (`project()`, `vpc()`), not `<thing>Typed`.
Deprecate the raw `*Id` when a typed ref carries the same value.

**Caveat:** a raw string is correct when it's the resource's own `id`, or a
genuinely opaque/scalar value (a hash, a free-form name, a discriminator). Don't
flag those.

---

## 8. Cross-path data inconsistency

**What:** the same field resolves to different values depending on whether you
reach the resource through the collection or through a single-object lookup.

**Fingerprint:** the collection creator (`newMqlXxx` / list loop) populates a
field from the *list* API response, while the init/single-fetch path populates
the same field from a *separate detail* call. If the list API doesn't actually
return that field, the collection path yields empty/zero while the single path
yields the real value.

**Why it matters:** `provider.things { field }` disagrees with
`provider.thing(id: "...") { field }`, and the empty answer looks valid. Real
Okta example: `okta.customRole.permissions` decoded inline from the list roles
endpoint (which doesn't include permissions) but the single-role init made a
separate `ListRolePermissions` call — so the collection returned `[]` for every
role. Fix: make the field a lazy computed method backed by the detail call, so
both paths resolve identically (and queries not selecting it skip the call).

**Verify by:** checking whether the list API response actually carries the field
(SDK model + docs), or route to live verification.

---

## 8b. `.lr` type vs `llx.*Data` constructor mismatch

**What:** a field's declared `.lr` type doesn't match the `llx.*Data` helper used to
populate it, so the runtime stamps the value with the wrong type.

**Fingerprint:** the classic one is a **`[]dict` field populated with
`llx.DictData(x)`** (scalar dict) instead of `llx.ArrayData(x, types.Dict)` —
`convert.JsonToDictSlice` returns a `[]interface{}`, and `DictData` stamps it as
a single `types.Dict` rather than an array of dicts. Look for any `llx.DictData(`,
`llx.StringData(`, `llx.IntData(` whose target `.lr` field is a list or a
different scalar type. Cross-check each `CreateResource` arg's helper against the
field's declared type in the `.lr`, and against how sibling `[]dict` fields in the
same provider do it (they're the reference — e.g. `scopes []dict` using
`ArrayData(scopes, types.Dict)`).

**Why it matters:** `provider.things { listDictField }` hits a type/coercion
error, or silently returns a mistyped value that downstream MQL can't iterate. It
compiles and the field "exists," so tests and codegen don't catch it — only a
query that touches the field reveals it. Real Okta example: `okta.domain.dnsRecords`
(declared `[]dict`) was set with `llx.DictData` while the sibling
`okta.trustedOrigin.scopes` used `llx.ArrayData(..., types.Dict)` correctly.

**Correct pattern:** the `llx.*Data` constructor matches the `.lr` type exactly —
`[]dict` → `ArrayData(x, types.Dict)`, `[]string` → `ArrayData(x, types.String)`,
`dict` → `DictData(x)`, and so on. A quick grep of every `Data(` call against the
resource's `.lr` field list catches these fast.

---

## 9. Error propagation / access-denied handling

**What:** a single permission gap or expected-empty condition fails a whole query
instead of degrading.

**Fingerprints:**
- A sub-accessor that returns the raw error on a 403/permission denial, where the
  provider's convention is to degrade (`Is400AccessDeniedError(err)` → nil result;
  region-not-available guards; resource-policy "operation not recognized" →
  null). New region-looping accessors especially need the not-available guard or
  they hard-fail whole accounts.
- A "not configured" 404 (e.g. no billing contact) propagated as an error instead
  of a clean null via `StateIsSet | StateIsNull`.

**Why it matters:** one inaccessible resource shouldn't sink an entire scan; and a
legitimately-absent optional should read as null, not an error. **But judgment
applies:** surfacing a real permission error so the user learns their token is
under-scoped is sometimes correct. Flag the pattern; let the reviewer decide.

---

## 10. Range-variable pointer capture

**What:** taking the address of a `for _, v := range xs` loop variable and storing
it, so every stored pointer aliases the same final element (pre-Go-1.22 semantics;
still a real bug in mapping code that appends `&v`).

**Fingerprint:** `for _, v := range xs { ...&v... }` or passing `&v` into a
`CreateResource` arg. The correct provider idiom is index-addressed:
`for i := range xs { ...&xs[i]... }`.

**Why it matters:** every created resource ends up with the last element's data.
Fast to sweep for with grep; the whole provider usually uses `&slice[i]` — an
`&v` stands out.

---

## 11. Schema-naming husks (build/compile-time fingerprints)

**What:** `.lr` resource/field naming that produces an empty or mistyped resource.

**Fingerprints:**
- A resource named `<parent>.<field>` queried by that same dotted path becomes an
  empty husk: `cannot convert primitive with NO type information`. Don't give a
  resource the same name as the path used to reach it.
- A list field whose path equals its element resource type compiles as a single
  resource, not a list: `is not a list type`. Use a plural field name with a
  singular element resource (field `policies` → resource `...policy`).

**Why it matters:** these surface as broken queries, not build failures, so they
slip through. Mostly relevant when reviewing new `.lr` schema.

---

## 12. Shared-runtime mutation (mostly llx/core, occasionally providers)

**What:** mutating a slice/map obtained from `arg.Value` / `bind.Value` in place.

**Fingerprint:** `append(x[:j], x[j+1:]...)` or index assignment on a slice/map
taken directly from runtime data without copying first.

**Why it matters:** the runtime caches resolved values and hands the same pointer
to multiple callers; mutating it corrupts the value for every subsequent use.
Copy before modifying. Primarily a concern in `llx/` builtins, but worth a glance
if a provider does clever in-place list surgery.

---

## 13. convert.SliceStrPtr* panic on nil elements

**What:** `convert.SliceStrPtrToStr` / `convert.SliceStrPtrToInterface` deref each
pointer with no nil guard — they **panic** on a slice containing nil elements.

**Fingerprint:** either helper called on an SDK `[]*string` that may hold nils.

**Correct pattern:** write a nil-safe loop when the SDK slice can contain nil
pointers. They are not drop-in "safe" replacements.

---

## Things that are usually NOT bugs (avoid false positives)

- `runtime.Connection.(*connection.XxxConnection)` — a bare assertion, but a
  codebase-wide invariant; always the right connection type. Not a panic risk.
- `if len(slice) == 0 { return nil, nil }` before a pagination loop — an empty
  first page implies no next page, so no data is dropped; it's a null-vs-empty
  style choice, not a truncation.
- Missing `.Limit()` on a list call whose SDK request type has **no** `.Limit`
  builder — verify in the SDK before flagging; some endpoints genuinely don't
  offer it.
- Deprecated SDK fields left unmodeled — often correct (the data moved), not an
  omission.
- A type switch (`switch v := x.(type)`) — safe, not a bare assertion.
