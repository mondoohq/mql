---
name: provider-release
description: Release mql providers and cut mql/cnspec releases, stable or pre-release. Use when the user wants to release providers, bump provider versions, check which providers have changes, publish a provider to the preview channel, cut a release candidate (rc), or understand why a published provider or release did not reach clients. Triggers on requests like "release providers", "bump provider versions", "release the os provider", "do an rc release", "cut v14.0.0-rc.N", "why is the old provider still installed".
---

# Provider and release process

Two things are released from this repo, on different mechanisms:

- **Providers** (everything under `providers/` except the builtins) publish
  themselves when their version changes on `main` or `v13`.
- **mql itself** (the `mql` binary and module) releases on a git tag, and a
  tag is what starts the matching cnspec release.

The failure this skill exists to prevent is a release that looks done but did
not reach clients: a provider that is published but not in the index clients
read, or an rc tagged before the provider it depends on is resolvable.

## Release lines and channels

| Branch | Versions | Provider channel | Pointer document |
|---|---|---|---|
| `v13` | `13.x.y` | stable | `providers/latest.json` |
| `main` | `14.0.0-rc.N` until 14 goes GA | preview | `providers/preview.json` |

Providers from both branches share one namespace,
`releases.mondoo.com/providers/<name>/<version>/`. The channel is decided by
the version string alone: a semver pre-release segment (`-rc.N`) publishes to
`preview.json`, a plain version to `latest.json`.

A client picks its channel from `update_channel` in its config, and falls
back to the channel of its own build: a pre-release binary reads
`preview.json`, a stable one `latest.json` (`cli/config` `GetUpdateChannel`,
`providers/registry.go` `pointerDocument`). **An rc client therefore only
gets a provider fix if a pre-release version of that provider carrying the fix
is in `preview.json`.** A fix merged on `main` does nothing for rc clients
until the provider's version is bumped and published.

The guard in `.github/workflows/providers.yaml` refuses a plain version whose
major is ahead of what stable serves (e.g. `14.0.0` while `latest.json` is on
13), because every stable client would install it. Keep the `-rc.N` segment on
`main`; promoting a major is a deliberate `allow_major_promotion` dispatch.

## Publishing a provider

`.github/workflows/providers.yaml` ("Build & Release Providers") runs on every
push to `main` or `v13` that touches `providers/**`. Its scoping step compares
each provider's `Version:` in `config/config.go` against the pointer for that
version's channel, and builds and publishes every provider whose version
differs. **The version bump is the release.** Merging a fix without a bump
publishes nothing.

### Stable bump (`v13`)

```bash
go run providers-sdk/v1/util/version/version.go check providers/*/
go run providers-sdk/v1/util/version/version.go update providers/aws/ --increment=patch --commit
```

`check` reports changes since each provider's last bump. `update` bumps,
writes a changelog from commit subjects, and with `--commit` commits as
"Mondoo <hello@mondoo.com>". `--fast` skips counting changes; `--output=DIR`
writes PR `title.txt` and `body.md`. Existing bump PRs put the new version in
the title, e.g. `(os-13.53.5)`.

### Pre-release bump (`main`)

The utility only understands `patch`, `minor` and `major`, so a pre-release
bump is a one-line hand edit of `providers/<name>/config/config.go`:

```go
Version: "14.0.0-rc.2",
```

Match the anchored line, not `MinVersion` in the `Requires` block. Before
opening the PR, dry-run the scoping to see exactly what the push will
publish; any provider listed besides the one you bumped is a surprise to
resolve first:

```bash
T=$(mktemp -d); git archive origin/main providers | tar -x -C "$T"
for p in $(ls "$T/providers"); do
  f="$T/providers/$p/config/config.go"; [ -f "$f" ] || continue
  case " core iac " in *" $p "*) continue;; esac   # SKIP_PROVIDERS
  v=$(grep -m1 -E '^[[:space:]]*Version:' "$f" | cut -f2 -d'"')
  case $v in *-*) ptr=preview.json;; *) ptr=latest.json;; esac
  d=$(curl -s "https://releases.mondoo.com/providers/$p/$ptr" | jq -r .version)
  [ "$v" != "$d" ] && echo "BUILD $p local=$v remote=$d"
done; rm -rf "$T"
```

(Apply your bump to the extracted tree, or substitute the new version for the
provider in the loop, before running it.)

### Builtin providers are never published

`core` and `iac` ship inside the binary. Their `Version` is
`mql.GetVersion()`, not a quoted literal, so the scoping step reads an empty
string that never matches the published version and would build them on every
push. They must be listed in `SKIP_PROVIDERS` in `providers.yaml`. A builtin
missing from that list fails the build job on every push ("no Go files in
providers/<name>"), and because `provider-index` depends on the build, **no
provider publishes from that branch at all** until it is fixed. When a
provider becomes builtin, add it to `SKIP_PROVIDERS` in the same PR.

### Confirming a provider actually reached clients

A green workflow run is not the check. Publishing happens in stages, and the
stage clients read is the last one:

1. `providers/<name>/<version>/` archives exist (right after the build job).
2. `providers/<name>/<pointer>.json` moves to the new version.
3. `providers/<pointer>.json`, the **index**, moves. The `provider-index` job
   only dispatches an asynchronous reindex, so this lags the run's success by
   several minutes (observed once: about 20 minutes after the push).

Clients resolve through the index (`url.JoinPath(BaseURL, "preview.json")`),
so only step 3 counts:

```bash
curl -s "https://releases.mondoo.com/providers/preview.json?t=$RANDOM" \
  | jq -r '.providers[] | select(.name=="os") | .version'
```

The CDN caches pointers for 60 seconds; the query string avoids a stale read.
Anything downstream of the provider — an rc tag, an integration run — waits
until this prints the new version.

`.github/workflows/release-providers.yml` ("Trigger provider release") opens a
bump PR for providers when a **stable** mql release is published. It never
runs for a pre-release (providers have no channel design for that path yet,
#10782), so pre-release provider bumps are always the manual edit above.

## Cutting an rc (mql and cnspec together)

mql and cnspec always release together, on the same version. There is no
mql-only release. Order matters:

1. **Merge every provider bump the rc depends on, then confirm the index**
   serves it (above). Tagging first ships an rc whose clients install the old
   provider, and every scan reproduces the bug the rc was meant to fix.
2. **Check CI on the commit you will tag.** mql's goreleaser does not gate on
   tests, so this is on you:
   ```bash
   S=$(git rev-parse origin/main)
   gh api "repos/mondoohq/mql/commits/$S/check-runs?per_page=100" \
     --jq '[.check_runs[]|.conclusion // .status]|group_by(.)|map("\(.[0])=\(length)")|join(" ")'
   ```
   Wait for nothing to be `in_progress`, and for no `failure`.
3. **Tag mql** with a lightweight tag on that exact commit. Earlier tags are
   lightweight (`git cat-file -t v14.0.0-rc.10` prints `commit`), and a local
   `tag.gpgSign` otherwise turns `git tag` into an annotated tag that demands
   a message:
   ```bash
   git fetch origin --tags
   git ls-remote --tags origin refs/tags/v14.0.0-rc.N   # must print nothing
   git tag --no-sign v14.0.0-rc.N <sha>
   git push origin refs/tags/v14.0.0-rc.N
   ```
4. **goreleaser** (`.github/workflows/goreleaser.yml`) builds and publishes
   mql, then dispatches `update-mql` to cnspec. A pre-release publishes to the
   preview channel and is not promoted to latest.
5. **cnspec's `mql-update.yml`** opens a PR from `version/mql_update_vX.Y.Z-…`
   bumping the mql pin. A human merges it.
6. **cnspec's `auto-tag-after-mql-bump.yml`** tags the bump PR's merge commit
   with the same version, which starts cnspec's goreleaser. cnspec refuses to
   release a tag whose tests did not pass.

A stable release follows the same chain from the `v13` branch.

## Rules

- Never release `core` or `iac` on their own; they track mql's version.
- Never tag before the providers the release depends on are in the index.
- Tag the commit whose CI you checked, not "whatever `main` is now".
- Confirm with the user before pushing a tag or merging a bump; both are
  release actions that cannot be quietly undone.
