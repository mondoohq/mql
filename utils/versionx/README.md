# versionx

One parser and one comparator for version strings, shared by MQL's `version` type, the
provider/engine version checks, and anything else that has to order the versions a fleet
actually reports.

```go
versionx.Compare("1.2.3-r4", "1.2.3-r10")  // -1
versionx.Parse("1:2.4.52-1ubuntu4.6").Epoch()  // 1
versionx.SortStrings(versions)             // oldest first, parsing each string once
versionx.Max(a, b)                          // the newer one; "" loses
versionx.Satisfies(v, ">= 1.0.0", "< 2.0.0")
```

## The order

1. **Epoch** (`1:2.4.52`, `1!2.0`) — a higher epoch wins outright. That is what an epoch is for.
2. **Release** — everything before the first `-`, compared component-wise on `.`, each component
   as alternating digit / non-digit runs. Missing trailing components are zeros, so `1.2` and
   `1.2.0` are the same version. No cap on component count.
3. **Suffix** — everything after the first `-`. A recognized prerelease word (`alpha`, `beta`,
   `rc`, `pre`, `prerelease`, `preview`, `dev`, `devel`, `snapshot`, `nightly`, `canary`,
   `milestone`) sorts **before** the bare release; anything else — a distro revision, a dist tag,
   a build id — sorts **after** it. The word has to be the whole word: `1.2.3-devuan1` is a
   Devuan revision, not a `dev` build, and sorts after `1.2.3`.

Plus: a `~` run sorts before everything (Debian's pre-release marker), and `+build` metadata is
ignored (semver says it carries no precedence). The `+` is dropped for every kind, not only
semver — the classifier cannot tell the cases apart anyway, since a deb like `1.0+dfsg1-1` matches
the semver shape — so two versions differing only after the `+` compare equal.

Rule 3 is the one that matters. Under semver `1.0.0-alpha` precedes `1.0.0`; under packaging
`1.2.3-1ubuntu1` follows `1.2.3`. Both are "X-suffix vs X", nothing in the string says which
convention is in force, so the suffix itself has to decide.

## How the three implementations compare

Every string below is real — from package inventories, upstream release tags, or vendor
firmware. **Masterminds** is `github.com/Masterminds/semver` v1.5.0 used directly; **mql v13** is
the comparator llx shipped through v13.38.1 (Masterminds, with a lexical string compare whenever
Masterminds refused to parse); **versionx** is this package. `n/a` means Masterminds could not
parse one of the two strings and had no answer to give.

| A | B | correct | Masterminds | mql v13 | versionx | why |
|---|---|:---:|:---:|:---:|:---:|---|
| `1.2.3` | `1.2.4` | `<` | `<` ✅ | `<` ✅ | `<` ✅ | plain semver |
| `1.2` | `1.10.2` | `<` | `<` ✅ | `<` ✅ | `<` ✅ | minor is a number, not text |
| `2.0` | `10.0` | `<` | `<` ✅ | `<` ✅ | `<` ✅ | major is a number, not text |
| `1.2` | `1.2.0` | `=` | `=` ✅ | `=` ✅ | `=` ✅ | missing components are zeros |
| `v1.2.3` | `1.2.4` | `<` | `<` ✅ | `<` ✅ | `<` ✅ | a leading v is decoration |
| `1.2.3` | `1.2.3+build.5` | `=` | `=` ✅ | `=` ✅ | `=` ✅ | build metadata carries no precedence |
| `1.0.0-alpha` | `1.0.0` | `<` | `<` ✅ | `<` ✅ | `<` ✅ | a prerelease leads its release |
| `1.0.0-alpha.2` | `1.0.0-alpha.10` | `<` | `<` ✅ | `<` ✅ | `<` ✅ | numeric prerelease identifiers |
| `1.2.3` | `1.2.3-1ubuntu1` | `<` | `>` ❌ | `>` ❌ | `<` ✅ | a distro revision is a LATER build |
| `2.1.0` | `2.1.0-1` | `<` | `>` ❌ | `>` ❌ | `<` ✅ | bare numeric revision |
| `1.2.3-r4` | `1.2.3-r10` | `<` | `>` ❌ | `>` ❌ | `<` ✅ | apk revisions count |
| `1.2.3-r4` | `1.2.3` | `>` | `<` ❌ | `<` ❌ | `>` ✅ | apk revision beats the bare release |
| `1.2.3-devuan1` | `1.2.3` | `>` | `<` ❌ | `<` ❌ | `>` ✅ | a revision that merely starts with a prerelease word |
| `1:2.4.52-1ubuntu4.6` | `1:2.4.52-1ubuntu4.10` | `<` | n/a ❌ | `<` ✅ | `<` ✅ | deb epoch + revision |
| `4.18.0-425.3.1.el8_7` | `4.18.0-425.13.1.el8_7` | `<` | n/a ❌ | `>` ❌ | `<` ✅ | rpm dist tag with an underscore |
| `1.1.1f-1ubuntu2.20` | `1.1.1k-12.el8` | `<` | n/a ❌ | `<` ✅ | `<` ✅ | openssl letter release |
| `1.1.1` | `1.1.1k` | `<` | n/a ❌ | `<` ✅ | `<` ✅ | letter release follows the bare one |
| `16.1.2.2` | `9.1.0.0` | `>` | n/a ❌ | `<` ❌ | `>` ✅ | four components (BIG-IP) |
| `4.40.0.0` | `10.1.0.0` | `<` | n/a ❌ | `>` ❌ | `<` ✅ | four components (Windows driver) |
| `126.0.6478.126` | `99.0.4844.51` | `>` | n/a ❌ | `<` ❌ | `>` ✅ | four components (Chrome) |
| `1.2.3.4.5` | `1.2.3.4.6` | `<` | n/a ❌ | `<` ✅ | `<` ✅ | five components |
| `2:1.0.0` | `10.0.0` | `>` | n/a ❌ | `>` ✅ | `>` ✅ | epoch beats a larger major |
| `1!2.0` | `1.9.0` | `>` | n/a ❌ | `>` ✅ | `>` ✅ | PEP 440 epoch |
| `1.0~rc1` | `1.0` | `<` | n/a ❌ | `>` ❌ | `<` ✅ | Debian tilde |

**Masterminds 8/24** (5 wrong, 11 unanswerable) · **mql v13 14/24** · **versionx 24/24**

Every row is a test case in `versionx_test.go`, so the table is reproducible rather than
asserted.

### The three ways the old comparator went wrong

**It refused, then guessed.** Masterminds v1 takes at most three numeric components and a
restricted prerelease charset, so it rejects a four-component build, an `_` in an rpm dist tag,
and a letter patch like `1.1.1k`. That is 11 of the 24 pairs above — most of a real package
inventory. llx's answer to a rejection was a lexical compare on the raw string, which is right by
accident when the strings happen to align (`1.1.1f` vs `1.1.1k`) and badly wrong the moment digit
counts differ: `16.1.2.2` below `9.1.0.0`, `126.0.6478.126` below `99.0.4844.51`,
`425.13` below `425.3`. Nothing errored, nothing logged.

**It parsed, and was still wrong.** The five `-suffix` rows are cases Masterminds accepts and gets
backwards for packaged software, because it applies semver's prerelease rule to what is actually a
distro revision. A version whose suffix parses is not a version whose suffix *means* what semver
thinks it means. Reading the suffix instead of assuming it only moves the problem to where the
word ends: `devuan1` opens with `dev` and means the opposite of it.

**It had no notion of `~`.** `1.0~rc1` is Debian's way of saying "before 1.0", and both older
implementations sort it after.

## Beyond ordering

The same parse backs `version(…)`'s other MQL behavior, so a few things that used to be errors now
have answers:

| expression | mql v13 | versionx | why it changed |
|---|---|---|---|
| `version('1:1.2.3').inRange('>= 1.0.0', '< 2.0.0')` | error: *epoch doesn't work yet* | `false` | epochs compare now, and epoch 1 is above the `2.0.0` ceiling |
| `version('1.2.3.4.5').inRange('>= 1.0.0', '< 2.0.0')` | error: *semver or similar* | `true` | a four-component version is an ordinary version |
| `version('1.1.1k-12.el8', type: 'debian')` | error: *not a debian version* | accepted | the debian format does not require a semantic upstream part |
| `version('1.9.0').inRange('^1.2.3', '< 3.0.0')` | error: *improper constraint: >= ^1.2.3* | `true` | a bound that already carries an operator is passed through, not prefixed |
| `version('latest').inRange(…)` | error | error | unchanged — a version with nothing numeric in it still refuses |

`Satisfies` accepts `>= > <= < = == !=`, the `^` / `~` / `~>` shorthands, and `1.2.x` wildcards,
all comparing through `Compare` — so a range check works on epoch'd and multi-component versions,
not only on semver.

Callers that default a bare bound to `>=` or `<=` (MQL's `inRange` does) must ask
`NeedsOperator` first. Prefixing an operator onto `^1.2.3` produces `>= ^1.2.3`, which
Masterminds rejected outright and a naive parser would happily evaluate against the nonsense
version `^1.2.3`; `ParseConstraint` rejects stacked operators for that reason.

## Scope

`Parse` never fails, and ordering is total, transitive and stable for every pair of strings —
including pairs from different packaging schemes, where no comparator has a meaningful answer and
the only thing on offer is a deterministic one. Within a single scheme it is correct.

**Do not use this to decide whether a host is vulnerable.** That question needs the per-format
parsers the advisory data was written against — `providers/core/resources/versions/{deb,rpm,apk}`
here, and the equivalents in the server's `mvd/versions`. Those implement their formats exactly;
this package is the one that has to order everything, including strings no single format claims.
