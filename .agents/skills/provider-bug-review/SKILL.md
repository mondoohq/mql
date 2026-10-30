---
name: provider-bug-review
description: >-
  Deep static code review of an mql provider for logic errors, nil-handling
  bugs, pagination truncation, caching/__id collisions, and other defects that
  silently give users wrong data. Use this whenever someone wants to audit,
  review, deep-dive, bug-hunt, or "find problems in" a provider (aws, gcp,
  azure, okta, k8s, or any provider under providers/) — whether the ask is a
  whole provider, a recently-shipped set of resources, or a PR/commit range.
  Trigger it for "review the okta provider for bugs", "audit gcp for nil
  issues", "any pagination problems in the azure provider?", "deep dive the
  new resources for logic errors", or a general "check this provider for
  issues". This is the STATIC/logic counterpart to provider-verification
  (which proves resources against live cloud infra) — reach for this when the
  goal is finding bugs by reading code, not spinning up infrastructure.
---

# Provider bug review

Find the bugs in an mql provider that a compiler and a passing test suite will
not catch: pagination loops that silently return one page, pointer derefs that
panic on a real-world null, a field that resolves differently through the
collection path than through the single-object path, an `__id` collision that
makes every query return the first resource's data. These are the defects that
reach users as *wrong data with no error* — the worst kind, because the wrong
answer looks valid.

This skill is a **static** review: you find bugs by reading the Go and the SDK,
reasoning about what the cloud API actually returns, and cross-checking against
the codebase's own conventions. It complements two other skills:

- **provider-verification** — proves resources against *live* cloud infra. When
  a finding here needs an over-50-rules policy or a real null contact to
  confirm, hand it off there rather than guessing.
- **code-review** (generic PR review) — this skill is mql-provider-specific and
  goes deeper on the provider bug classes below.

## When this is the right tool

Use it when the goal is *finding defects by reasoning about code* across a
provider or a meaningful slice of one. If the user instead wants to prove a
specific PR works against real infrastructure, that's `provider-verification`.
If they want a quick generic review of a small diff, that's `code-review`.

## The core loop

The method that works is **fan out, then verify**: parallel analysis agents
generate candidate findings against a precise bug taxonomy, then *you*
personally confirm every candidate against the actual source before reporting
it. Agents are good at surfacing suspects across a lot of files fast; they also
hallucinate plausible-but-wrong bugs, so nothing reaches the report unverified.

Work through these steps. Create a todo per step so none are skipped.

### 1. Scope and prioritize

- Identify the provider and enumerate its Go files: `providers/<name>/resources/*.go`,
  `connection/`, `provider/`, and any hand-rolled `resources/sdk/` subpackage
  (custom HTTP clients live here and are the single richest source of bugs —
  they reimplement pagination and error handling by hand).
- Pull the provider version from `providers/<name>/config/config.go` and recent
  history: `git log --oneline -15 -- providers/<name>/` and the file mtimes.
  **Recently-added/changed files carry the most risk** and deserve the most
  scrutiny; long-shipped code that users rely on daily is where a found bug
  matters most. Note both.
- If the ask is a PR or commit range, scope to those files but still read the
  shared infrastructure (next step) for context.

### 2. Learn the house patterns FIRST (do not skip)

Before judging any resource, read the shared infrastructure so you know what
"correct" looks like here and can tell a real bug from a convention you don't
recognize yet:

- `connection/connection.go` — how the client and auth are built; what
  `conn.Client()` returns.
- `resources/helpers.go` (or equivalent) — the nil-safe pointer helpers
  (`oktaStr`, `<provider>Str`, `convert.To*`), link/ID parsers, shared resolvers.
- **The SDK's pagination mechanics.** Find how the SDK signals "more pages"
  (`resp.HasNextPage()` reading a `Link: rel="next"` header, a `NextToken`, a
  `marker`, a `nextPageToken`). *This is what lets you judge every pagination
  finding* — if you don't know how the SDK paginates, you can't tell whether a
  missing loop truncates. Read the SDK source in the module cache when unsure
  (`$GOPATH/pkg/mod/.../<sdk>@<ver>/...`).
- One representative resource file end-to-end, to internalize the collection →
  `CreateResource` / init → `NewResource` pattern the provider uses.

### 3. Fan out analysis agents by file-group

**First decide whether to fan out at all — match the machinery to the size.**
The parallel fan-out earns its cost (each agent is ~100k+ tokens and minutes of
wall time) only when the provider is too large to hold and reason about in one
context. Gate it on the hand-written surface:

- **Small (≲6–8 hand-written resource files / ≲2k LOC):** skip the fan-out. Read
  every file yourself, run the mechanical greps below, and use **at most one**
  verification agent (or none). A single focused agent on a 2-file provider
  mostly re-confirms your own read — spend the tokens on the SDK verification in
  step 4 instead. (Most non-cloud/IaC providers land here: cloudformation was 2
  files, ansible/bicep a handful.)
- **Large (many files, or a hand-rolled `resources/sdk/` client — aws/gcp/azure/
  cloudflare-scale):** fan out. This is where parallel agents pay off; cloudflare
  (28 files) is where the fan-out surfaced a HIGH `__id` bug a single pass would
  likely have missed.

When you do fan out: split the resource files into groups of ~5-7 (put the
newest/riskiest together) and dispatch one analysis agent per group **in
parallel, in a single message**.
Give each agent the bug taxonomy and the exact reporting contract. A proven
prompt template is in `references/agent-prompt-template.md` — read it and adapt
the file list per group. Key requirements to put in every agent prompt:

- The full bug-class checklist (from `references/bug-taxonomy.md`), so agents
  look for the same things and label findings by class.
- "For each finding: file:line, bug class, a **concrete failure scenario**
  (what input/state triggers it and what the user sees), a suggested fix, and
  the quoted code."
- "Cross-check sibling files and the SDK's actual return types before
  reporting, to avoid false positives" — this dramatically cuts hallucinated
  findings.
- "Rank by severity; report what you verified as clean too."

Also run a fast mechanical sweep yourself while agents work — these grep
patterns catch whole classes cheaply:

```bash
# range-variable pointer capture (bug): &v inside `for _, v := range`
grep -rn "for.*:= range" providers/<name>/resources/*.go | grep -v _test
# then check whether the body takes &loopvar rather than &slice[i]

# bare single-result type assertions on runtime data (panic risk): x := v.(T)
grep -rnE "[a-zA-Z0-9_]+ := [a-zA-Z0-9_.]+\.\([a-zA-Z]" providers/<name>/resources/*.go \
  | grep -v ", ok" | grep -v _test

# STUB DATA (taxonomy class 0, top severity): accessors that return empty/zero
# with no real fetch, and "not implemented" markers. Open each hit and confirm
# the body actually calls the client / parses source — a `.lr`-declared field
# that returns a stubbed zero value is silent data loss.
grep -rnE "return nil, nil|return \[\]any\{\}, nil|return \"\", nil" providers/<name>/resources/*.go | grep -v _test
grep -rniE "TODO|not implemented|placeholder|stub|for now" providers/<name>/resources/*.go | grep -v _test
```

### 4. Verify every candidate against source

This is the step that makes the review trustworthy. For each finding an agent
reports, open the actual file and confirm the bug is real: the line still says
what the agent quoted, the SDK type is what the agent assumed, the failure
scenario actually holds. Agent reports are leads, not verdicts.

**Reading the SDK / generated source is the spine of this step, not an
"if unsure" fallback.** In practice nearly every confirm-vs-refute decision
turns on a fact you can only get from source: a field's pointer-ness and JSON
tags, whether a `List` returns a real paginator or a single-page type, how the
generated `createXxx` computes `__id` (see the caching class in the taxonomy),
what `IntDataPtr(nil)`/`ToDataRes` do with a null. So: **a finding whose severity
depends on a type, pointer-ness, pagination shape, or generated-code behavior is
NOT confirmed until you have read and can cite that source.** This is cheap (SDK
reads are small) and it is what kills both hallucinated findings *and*
false-clean dismissals — e.g. the same reads refuted a nullable-int "bug" and
confirmed a real `__id` collision in the same review.

**Re-rank severity, don't just confirm existence.** An agent's severity is a
lead too. On verification, upgrade findings whose trigger is more common than the
agent thought and downgrade ones that "could" happen but realistically won't. Two
real examples from this skill's own use: an agent flagged a scalar-value parse
bug as a rare malformed-input case, but verifying the caller showed it fires on a
*valid, common* input (metadata with a scalar member) → upgraded; and an agent
called a Stream list "truncating past one page" MEDIUM, but the SDK modeled it as
a single-page type → downgraded to a live-verification item, not asserted.

When a finding hinges on runtime data you can't see statically ("does the list
endpoint really omit this field?"), say so explicitly and route it to
`provider-verification` for live confirmation rather than asserting it. Before
offering or running live verification, check the target account/infra actually
contains instances of the resources under review — proving a fix against an empty
account verifies nothing.

### 5. Report

Produce a single severity-ranked report. Order: **silent data loss / panic >
correctness (wrong or inconsistent data) > robustness (error propagation) >
performance > cosmetic.** For each finding give `file:line`, the bug class, the
concrete failure scenario, and the fix. State plainly what you checked that was
clean — a review that only lists problems hides its own coverage.

**Always include a test-coverage section.** A review isn't complete until it
calls out gaps in unit-test coverage of the provider's **pure-Go logic** — the
pagination loops, parsers, splitters, id/cache-key builders, null/zero
converters, and degrade/error-classification helpers where wrong-data bugs
actually live and where a compiler + passing integration suite won't catch a
regression. Name that logic, say which parts have direct unit tests and which
don't, and treat a missing test on non-trivial pure-Go logic as a reportable
gap (roughly robustness-tier). When you go on to fix findings, add unit tests
for the pure-Go logic you touch.

Then stop and let the user decide what to fix. **Do not open a fix PR
unprompted** — a review's job is to report; fixing is a separate, explicit
step. When they ask you to fix, follow the normal worktree → change →
`make providers/build/<name>` → gofmt → PR flow, and add regression tests for
any pure-Go logic you touch (pagination loops, parsers, splitters — exactly the
places bugs hide).

## The bug taxonomy

The heart of this skill is `references/bug-taxonomy.md` — the catalogue of
provider bug classes, each with how to spot it, why it hurts the user, the
correct pattern, and the fix. Read it before writing the agent prompts (the
agents need it) and keep it open while verifying. It is the accumulated result
of many provider audits; treat it as the checklist, not a suggestion.
