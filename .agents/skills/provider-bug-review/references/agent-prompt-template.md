# Analysis-agent prompt template

Dispatch one agent per file-group, **all in a single message** so they run
concurrently. Use `general-purpose` (or `Explore` if read-only). Fill in the
`<...>` slots. Paste the full bug-class list from `bug-taxonomy.md` into each
prompt (agents don't share your context) — or, if the skill files are on the
agent's filesystem, tell it to read `bug-taxonomy.md` first.

Keep groups to ~5-7 files and put the newest/riskiest files together so their
findings come back from one focused agent.

---

```
You are auditing Go source files in the <PROVIDER> provider of the `mql`
codebase (a cloud-inventory tool) for USER-IMPACTING BUGS. Working dir: <REPO>

Audit ONLY these files (read each fully):
- <file 1>
- <file 2>
- ...

Read <REPO>/.agents/skills/provider-bug-review/references/bug-taxonomy.md first
— it is the exact catalogue of bug classes to look for. [OR: paste the taxonomy
inline if the agent can't read it.]

Focus on these classes (see the taxonomy for fingerprints and correct patterns):
0. STUB / FABRICATED DATA (top severity) — an accessor or field that returns
   empty/hardcoded/zero data with no real API call or parse: a body that is just
   `return nil, nil` / `return []any{}, nil` / `return "", nil`, a field pinned
   to a literal ""/false/0/{} the API actually populates, or a `.lr`-declared
   field with no real Go population. Confirm every declared field/accessor
   actually fetches or parses real data. All data must be real.
1. Pagination truncation — a List over a paginated endpoint that doesn't loop
   the next-page signal (silent data loss); hand-rolled HTTP fetches that skip
   the Link:next header; hardcoded small limits.
2. Nil deref / panic — SDK pointer derefs without the nil-safe helper; BARE
   type assertions on runtime/JSON data (v.(T) not x,ok:=v.(T)); response bodies
   used without a nil check.
3. Singular resource accessor returning nil,nil without setting
   `a.Field.State = plugin.StateIsSet | plugin.StateIsNull` first.
4. Init fall-through husk — `return args, nil, nil` after a lookup found NOTHING
   (should be a not-found error); NOT the legit "args complete"/"no id" fast-path.
5. Caching/__id — CreateResource where NewResource/init-built identity is needed
   (cache collision); empty/duplicate __id; non-unique id().
6. null && null — degraded/stub resources that leave booleans as StateIsNull
   instead of explicit false (they spuriously pass `{a && b}` assertions).
7. Typed-reference misses — raw *Id/*Arn/*Url strings that should be typed
   accessors (breaking to fix after ship).
8. Cross-path inconsistency — a field populated from the list API on the
   collection path but from a separate detail call on the single-object path,
   where the list API doesn't return it (collection yields empty).
8b. `.lr` type vs llx.*Data mismatch — a `[]dict` field populated with
   `llx.DictData(x)` instead of `llx.ArrayData(x, types.Dict)` (or any helper
   that doesn't match the field's declared .lr type). Cross-check every
   CreateResource arg's llx.*Data helper against the field type in the .lr.
9. Error propagation — a 403/permission gap or "not configured" that fails the
   whole query instead of degrading to null/empty.
10. Range-variable pointer capture — `&v` inside `for _, v := range` (should be
    `&slice[i]`).

For EACH finding report:
- file path + line number
- the bug class
- a CONCRETE failure scenario: what input/state triggers it and what the user
  sees (wrong data? panic? empty list?)
- a suggested fix
- the quoted code

Rank findings by severity (silent data loss / panic > wrong-or-inconsistent
data > error-propagation > perf > cosmetic). CROSS-CHECK sibling files and the
SDK's actual return types / model structs before reporting, to avoid false
positives — verify the pointer-ness and JSON tags of SDK fields, and confirm
paginated response types really expose a next-page signal. Also list what you
checked that came back CLEAN, so coverage is visible.

This structured list is your final output (it is not shown directly to a human,
so include full detail).
```

---

## After the agents return

Do **not** relay agent output verbatim. For every candidate finding, open the
file and confirm it against source and the SDK model (see SKILL.md step 4).
Only verified findings go in the report; route anything that needs live runtime
data to `provider-verification`.
