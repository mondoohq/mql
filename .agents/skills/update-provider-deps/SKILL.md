---
name: update-provider-deps
description: Upgrade an mql provider's vendored SDKs (all providers or a named subset), audit the new versions for breaking changes and fix call sites while keeping shipped MQL fields backwards-compatible, check whether .lr enum comments drifted, and propose a numbered list of new resources and fields the upgrade unlocks for the user to choose from. Use this whenever the user mentions updating, bumping, upgrading, or refreshing SDK or provider dependencies for any provider (azure, aws, gcp, github, cloudflare, okta, alicloud, mongodbatlas, databricks, and the rest), asks what a newer SDK would give us, asks whether a dep bump is safe or breaking, or asks what new fields or resources an SDK version makes available. Also use it for "check for new SDK majors", "are our SDKs current", and "what did we miss in the new SDK". Runs one provider at a time by default; a sweep across several providers is an explicit opt-in.
argument-hint: "[provider name] (one provider is the default; comma-separated for a sweep)"
---

# Update provider SDK dependencies

An mql provider is a thin layer over a vendor SDK, so an SDK upgrade is two jobs at once:
not breaking what we already ship, and harvesting what the new version exposes. Doing only
the first leaves the schema stale for months; doing only the second breaks customers.

`go get path@latest` cannot do the first job at all — it only searches within the current
major and never discovers that the dep now lives at `path/v3`. The bundled `probe.py`
handles that; the rest of this skill is about the parts that need judgment.

All paths below assume you are at the mql root:

```bash
P=.agents/skills/update-provider-deps
```

## Phase 0 — Scope

Work in worktrees, and **target one provider per run unless the user asked for more**.
One provider is both the common ask ("update the azure SDKs", "is go-github current?")
and the cheaper one: probe time scales with the dep count, and review time scales with
the number of PRs. Widen to a sweep only on an explicit "check every provider" or a
named list — never because a single-provider run finished and the others were right
there.

**Single provider — the default shape.** One worktree, one branch, one PR, carrying the
bump together with whatever the migration forced: code edits, `.lr` enum-drift fixes, and
the Phase 6 additions the user picked. There is no split to decide, so none of the
combined-PR rules below apply — go straight to Phase 1.

**A sweep — only when asked.** Now the split matters, and it follows from **what each
provider's diff touches**, not from how many providers the run spans:

- **A provider whose diff touches anything beyond `go.mod`/`go.sum` gets its own worktree,
  branch, and PR.** That means the Phase 6 schema additions the user picked, the code edits
  a major-version migration forces, and `.lr` enum-drift fixes. **Bundle that provider's SDK
  bump into the same PR** — the bump is what unlocked the fields, and splitting them makes
  a reviewer reconstruct the connection from two places.
- **Everything else goes in one combined PR**, covering every provider whose entire diff is
  a dependency bump with no code change at all.

The test is what the review actually costs: reading logic and judging a schema decision, or
confirming a green build. The first needs a domain reviewer and a thread of its own; the
second needs a glance — and N of them need N glances plus N context switches for no added
safety. Review cost per PR is close to constant regardless of diff size, so a run that opens
eleven PRs where nine are a one-line `go.mod` bump saying the same thing has spent most of
its review budget on ceremony.

**A failing bump leaves the combined PR rather than sinking it.** If one provider in the
combined set won't build, pull it out and give it its own PR — by definition it now has a
code change. The combined PR should only ever hold changes that cannot fail in interesting
ways.

**Sequencing consequence: do not open the combined PR until the Phase 6 selections are in.**
A provider moves out of the combined PR the moment the user picks a field on it, and you
cannot know that before Phase 6. Apply and verify everything first, decide the split last.
Opening PRs as each provider goes green feels like progress and forces a rewrite.

Confirm the target with the user. `python3 $P/probe.py --list` shows every known provider
and the module prefixes it scans. For a provider that isn't in that table (a DB driver, a
network device client), pass its `go.mod` directly — that's the escape hatch:

```bash
python3 $P/probe.py providers/mssql/go.mod --provider=mongo   # any prefix set you like
```

**Some providers are pinned on purpose.** `probe.py` refuses to touch them and prints why.
Nutanix is the standing case: its SDK version is set by the Prism Central release the
customer runs, and a newer client requests API paths that GA Prism Central answers with
404. If a user asks for one of these, relay the reason rather than working around it —
the failure is invisible locally and only shows up against the customer's server.

The general form of that rule: **newest is not automatically correct.** An SDK is a client
for a server someone else operates. Where a provider talks to self-hosted or
version-negotiated software, the right target is the oldest version in the major that
still covers our feature set.

## Phase 1 — Probe, then get sign-off

```bash
python3 $P/probe.py --provider=azure                    # one provider — the default
python3 $P/probe.py --provider=github,cloudflare        # named subset
python3 $P/probe.py --provider=aws --json               # structured, for scripted follow-up
python3 $P/probe.py                                     # every provider — a sweep
```

Probing AWS or Azure takes minutes (120+ deps, two proxy round-trips each), so start it in
the background and do other prep while it runs. The bare form is every provider in the
`--list` table and costs that much again for each one — don't reach for it to answer a
question about a single provider.

Three outcomes: `UP` (stable upgrade available), `OK` (current), `BETA` (a higher major
exists but only as beta or pseudo-version). Never fold `BETA` into the upgrade set — a
major that has only shipped as beta churns for months, and adopting it means redoing the
migration at GA. List them separately so the user can decide.

Show the user the `UP` rows and confirm the set before applying anything.

## Phase 2 — Read the release notes before touching code

This is the step that pays for itself, and the easiest one to skip.

```bash
python3 $P/changelog.py github.com/cloudflare/cloudflare-go/v6 v6.10.0 v7.8.0
```

It resolves the module to its source repo (GitHub, and the vanity paths like
`go.mongodb.org/...`, `cloud.google.com/go/...`, `k8s.io/...`), pulls GitHub Releases and
`CHANGELOG.md` sections in range, and follows any migration-guide link it finds, inlining
the guide. Run it for **every module crossing a major**. Patch and minor bumps inside a
major are covered by SDK compatibility promises and rarely repay the time.

What you are reading for, in priority order:

1. **A migration guide.** Some vendors ship before/after code for each break. Cloudflare
   v7 does. Use it rather than rediscovering the same edits from compiler errors.
2. **Renames of things that still compile.** MongoDB Atlas announces "many renames of
   existing function names, due to operation ID renaming" — that one line predicts the
   entire migration. Without it you find the renames one compiler error at a time and
   miss the ones that don't error.
3. **Deprecations.** A method still present but marked deprecated is a decision, not a
   fix: see the backwards-compatibility rules in Phase 4.
4. **Enum additions and removals.** Azure's notes list these explicitly, and they feed
   Phase 5 directly.
5. **Fields that only populate under a request flag.** Rarer, but these are what make a
   new field read as `false` on every asset. See "stub data" in
   `references/schema-additions.md`.

## Phase 3 — Apply and get it compiling

```bash
python3 $P/probe.py --provider=cloudflare --apply
```

This rewrites `go.mod`, rewrites the import path in every `.go` file when the major moved,
then runs `go mod tidy` and `go build`.

**The Go toolchain fails inside the sandbox.** `go mod tidy`, `go build`, `go test` and
`gh` all hit the proxy's intercepted TLS and die with `x509: OSStatus -26276`. Re-run them
with `dangerouslyDisableSandbox: true`. Don't set `GOSUMDB=off` to route around it — that
disables checksum verification. `curl` and the bundled scripts are unaffected.

Then iterate on build errors. Use `go build -gcflags=-e ./...` to see every error at once
rather than the first ten.

Two things the import rewrite deliberately does **not** touch, both of which have shipped
as review findings:

- **Import aliases.** `cloudflarev6 "github.com/cloudflare/cloudflare-go/v7"` compiles
  perfectly and lies to every future reader. Grep for the old major as an identifier.
- **Comments naming the old version.** "cloudflare-go v6 models this as a union" is
  wrong the moment the path changes. Prefer dropping the version to advancing it: the
  behavior being described is usually a property of the SDK, not of one release, and a
  version number in a comment only guarantees it rots again at the next bump.

If you fix those with a bulk rename, **read the rendered diff, not just the build**. A
phrase that wraps across a line break defeats a single-line pattern: the first rule misses
and a later, narrower rule fires on the orphaned fragment, producing duplicated words and
mangled sentences that compile fine.

## Phase 4 — Audit for breaks the compiler won't catch

A clean build is not evidence of a clean upgrade. Three checks:

```bash
# What disappeared, intersected with what we call
$P/apidiff.sh github.com/okta/okta-sdk-golang/v5 v5.0.6 \
              github.com/okta/okta-sdk-golang/v6 v6.1.7 > /tmp/diff.txt

# What changed shape on types this provider actually uses
OLD=$($P/modfetch.sh github.com/okta/okta-sdk-golang/v5 v5.0.6)
NEW=$($P/modfetch.sh github.com/okta/okta-sdk-golang/v6 v6.1.7)
python3 $P/structdiff.py "$OLD" "$NEW" --types-from providers/okta
```

Two things about that output, both learned the hard way:

- **`modfetch.sh` prints the extraction root, not the module root.** The module lands under
  `<printed>/<module-path>@<version>/`, so `$NEW/CHANGELOG.md` does not exist. `structdiff.py`
  and `enumdrift.py` walk down and are fine; a `grep` or `sed` of your own needs the nested
  path. AWS service modules and the `cloud.google.com/go/*` sub-modules each ship a
  `CHANGELOG.md` worth reading, and this is what stops you finding it.
- **`structdiff.py` cannot see embedded structs.** A release that adds capability by
  embedding reports as no change at all: hcloud-go v2.48.0 embedded `DeprecatableResource`
  into `hcloud.Image`, giving it `Deprecation` and `UnavailableAfter`, and the tool reported
  nothing for the module. When release notes mention something the diff does not show, read
  the type's source before concluding the release was empty.

`structdiff.py`'s `RETYPED` and `REMOVED` lines are the dangerous output. For each one, ask
whether the affected value reaches a **shipped `.lr` field**. If it does, the upgrade has a
user-visible consequence and needs a deliberate decision rather than a mechanical fix.

The scope-ambiguous rename is the worst case and deserves its own habit: when an SDK splits
`ListThings` into `ListOrgThings` and `ListGroupThings`, both take `(ctx, string)`, so
picking the wrong one **compiles cleanly and reads the wrong scope**. Check each migrated
call against the identifier it passes, not against the build.

**Read `references/breaking-changes.md`** for the taxonomy of silent breaks and the
decision table for keeping shipped fields backwards-compatible. The short version: never
change a shipped field's type or meaning in place — deprecate and add alongside.

## Phase 5 — Check enum comments for drift

`.lr` comments routinely enumerate a field's values ("One of Primary, Readonly, Guard, or
Temp"). Policy authors write `where(state == "...")` against those lists, so a list that
silently loses a value costs them rows they should have matched.

```bash
python3 $P/enumdrift.py providers/databricks/resources/databricks.lr "$NEW"
```

It pairs each enumerating comment with the SDK const block whose values it quotes, and
reports what the SDK has that the comment omits. Only comments that claim completeness
("One of A, B, or C") are reported; ones phrased as examples ("such as A or B") are
allowed to be partial and are counted separately.

Treat every hit as a candidate, not a verdict — confirm the paired enum is the one the
field carries, and that the omission isn't deliberate. Fix the genuine ones in the same
PR; they are cheap, and they are documentation a policy author relies on when deciding
which `where()` clauses to write.

**A clean run is not always a clean bill of health.** The check needs the SDK to declare
typed string constants. Azure, Databricks, GCP and Nutanix do; several OpenAPI-generated
SDKs — go-github, okta, the Atlas SDK — type every enum field as a plain string, and the
tool will tell you it has nothing to compare against. For those, enumerated values have to
be checked against the vendor's API docs by hand, or left alone.

## Phase 6 — Propose additions, then stop

This is the half of the upgrade that gets skipped, and the reason to bother upgrading at
all. Produce a **numbered, ranked list** and let the user choose. Don't implement anything
in this phase.

```bash
# Tier A — new fields on types the provider already uses
python3 $P/structdiff.py "$OLD" "$NEW" --types-from providers/cloudflare

# Tier B — whole services the SDK gained (drop the filter, read the NEW TYPES list,
# and diff the client's service accessors)
python3 $P/structdiff.py "$OLD" "$NEW" | head -60
```

Rank by audit value per unit of effort, and separate the tiers, because their costs differ
by an order of magnitude: Tier A is fields on resources we already ship and often needs no
new API call, while Tier B needs a lister, an `__id` scheme, and a schema review.

Before listing anything, check it isn't already exposed (`grep` the `.lr`) and that it
isn't stub data. **`references/proposal-format.md`** has the format and the ranking
criteria.

Present the list, ask which numbers they want, and wait. The user picks — that's the point
of the phase.

On a sweep, their answer also settles the PR split from Phase 0: every provider they pick
a field on leaves the combined PR and gets its own, and a provider they pick nothing on
stays in the combined PR unless its bump already needed a code edit. On a single-provider
run there is nothing to settle — the picks land in the one PR alongside the bump.

## Phase 7 — Implement the selection, verify, PR

For each chosen item, follow `references/schema-additions.md`: `.lr` entry, `.lr.versions`
at the provider's current version plus a patch, regenerate, map the field, and handle the
null-versus-zero question honestly.

Verify before claiming anything, and verify **per provider** — including every provider
riding in the combined PR, which is a set of independent modules rather than one build:

```bash
cd providers/<name> && go build ./... && go test ./... && gofmt -l .
```

Then open PRs in the shape Phase 0 set out.

**The single-provider PR.** One PR titled for the provider, carrying the bump and any
schema work together. The body requirements in the next paragraph apply to it unchanged.

**Sweep, per-provider PRs.** One for each provider whose diff has a code change. The body
carries the SDK bump and the schema work together, and should state which breaking changes
in the new version did *not* reach a shipped field, and why. That is the reasoning a
reviewer would otherwise have to redo from the changelog.

**Sweep, the combined PR.** One PR for all the pure bumps, titled for the sweep rather
than for any one provider (`🧹 providers: refresh SDK dependencies`). Its body needs:

- a table of every provider and module bumped, with from/to versions, so the change is
  readable without expanding `go.sum`;
- confirmation that each provider was built and tested **separately**;
- an explicit note on any `go mod tidy` side effect that rode along. An unrelated indirect
  dependency dropped because `main` was untidy is not a consequence of the bump, and it
  reads as one unless you say so.

Say plainly in every PR what was **not** verified — none of this can be checked against live
infrastructure without credentials, and a reviewer needs to know which claims rest on the
compiler and which on an actual API response.

Provider versions in `config/config.go` are **not** bumped here; that's the release flow.

## Reference files

- `references/breaking-changes.md` — silent-break taxonomy, and how to keep shipped MQL
  fields working when the SDK moves under them. Read during Phase 4.
- `references/schema-additions.md` — `.lr` rules for adding fields and resources: version
  entries, typed references, when something earns a sub-resource, null versus zero, and
  the stub-data traps. Read during Phases 5 and 7.
- `references/proposal-format.md` — the numbered proposal format and ranking criteria.
  Read during Phase 6.

## Bundled scripts

| Script | Does |
|---|---|
| `probe.py` | Find and optionally apply upgrades, including new-major path rewrites |
| `changelog.py` | Fetch release notes, CHANGELOGs, and migration guides between two versions |
| `modfetch.sh` | Extract any module version from the proxy, no module context needed |
| `apidiff.sh` | Exported symbols added and removed between two versions |
| `structdiff.py` | Struct fields gained, lost, and retyped, filtered to types we use |
| `enumdrift.py` | `.lr` enum comments that no longer match the SDK's constants |
