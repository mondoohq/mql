# Proposing what to add

Read during Phase 6. The output of this phase is a numbered list the user picks from, not
an implementation.

## Why numbered and ranked

An SDK major typically exposes far more than anyone wants to build. Handing over an
unranked pile moves the sorting work onto the user; implementing your own favourites
without asking spends their review budget on your priorities. A ranked list with honest
effort estimates lets them say "1, 2, and 6" in one line.

## Gather

Two passes, because their costs differ by an order of magnitude.

**Tier A — new fields on types the provider already uses.** Cheapest possible schema
growth: the resource exists, the API call already happens, and often the value is already
in a response being parsed.

```bash
python3 $P/structdiff.py "$OLD" "$NEW" --types-from providers/<name>
```

Read the `+` lines. Ignore parser noise (a field whose type reads like an English word is a
misparsed comment).

**Tier B — services the SDK gained.** Needs a lister, an `__id` scheme, error handling, and
schema review.

```bash
python3 $P/structdiff.py "$OLD" "$NEW" | head -80     # NEW TYPES section
```

The client struct's own diff is the most reliable signal here: a new service accessor on
the top-level client is a whole API area. Cross-check against the release notes, which
usually name new services explicitly.

## Filter before listing

Every candidate must survive three checks. Doing this before presenting keeps the list
trustworthy:

1. **Not already exposed.** `grep -i '<fieldname>' providers/<name>/resources/*.lr`. Check
   the *resource* too — a name may exist on a different resource than the one you mean.
2. **Real data.** See "Before you add anything" in `schema-additions.md`. A field gated
   behind a request flag we don't set is not a candidate.
3. **Actually readable.** A service with only create/update/delete methods cannot back a
   read-only resource. GitLab's security-attributes service is exactly this: attractive in
   the diff, unbuildable without dropping to GraphQL.

Say so when something interesting fails these checks — "considered and rejected because"
is useful information, and it stops the same candidate being re-proposed next time.

## Rank

Order by **audit value per unit of effort**, not by size.

Audit value is highest for things that answer a question a policy would ask and currently
cannot: an unset webhook secret, a trigger that starts code from an external location, an
agent with standing access to data, a backup that dies with its cluster. Capability and
cost flags rank lower. "Would a security policy read this?" is the discriminator.

Effort is roughly: **S** = fields on an existing resource, no new call. **M** = a new
resource over one list endpoint, or fields needing a new call. **L** = a service with
sub-resources, pagination, and its own error semantics.

Keep the tiers visually separate so the user can take all of Tier A cheaply without
implicitly signing up for Tier B.

## Format

```markdown
### Tier A — new fields on existing resources

1. **<provider> · <short title>** [S]
   <One or two sentences: what it reports and which question it answers.>
   Fields: `fieldOne`, `fieldTwo`, `fieldThree`

2. ...

### Tier B — new resources

7. **<provider> · <short title>** [M]
   <What the service is and why it is worth modelling.>
   API: `ListThings` / `GetThing`

### Considered and rejected

- **<thing>** — <why: already exposed / stub data / no read method>
```

Then ask which numbers they want, and wait. Don't start implementing the obvious ones while
waiting — the point of the phase is that the choice is theirs.

## After they choose

Confirm the selection back in one line, then implement per `schema-additions.md`. If a
chosen item turns out to be unbuildable once you're in the code, say so and stop rather
than substituting something else.

The selection also decides the PR split (Phase 0). Each provider the user picks a field on
gets its own PR carrying both the schema work and that provider's SDK bump; the providers
nobody picked stay in the single combined dependency PR. This is why the combined PR cannot
be opened before the user answers.
