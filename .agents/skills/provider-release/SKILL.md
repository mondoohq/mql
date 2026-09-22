---
name: provider-release
description: Release mql providers by bumping their versions. Use when the user wants to release providers, bump provider versions, check which providers have changes, or prepare a provider release PR. Triggers on requests like "release providers", "bump provider versions", "check provider changes", "release aws provider", or "prepare provider release".
---

# Provider Release

Automate provider version bumping and release PR creation for the mql project.

## Core Command

```bash
go run providers-sdk/v1/util/version/version.go <command> <providers> [flags]
```

## Workflow

### 1. Check which providers have changes

```bash
# All providers
go run providers-sdk/v1/util/version/version.go check providers/*/

# Specific provider(s)
go run providers-sdk/v1/util/version/version.go check providers/aws/ providers/gcp/
```

Reports the number of changes since each provider's last version bump.

### 2. Update versions

```bash
# All changed providers (auto patch bump + commit)
go run providers-sdk/v1/util/version/version.go update providers/*/ --increment=patch --commit

# Specific provider(s)
go run providers-sdk/v1/util/version/version.go update providers/aws/ --increment=patch --commit

# Multiple specific providers
go run providers-sdk/v1/util/version/version.go update providers/aws/ providers/azure/ --increment=patch --commit
```

**Flags:**
- `--increment=patch|minor|major` - Version bump level (skip interactive prompt)
- `--commit` - Git commit the version change automatically
- `--fast` - Skip counting individual changes
- `--output=DIR` - Write PR `title.txt` and `body.md` to DIR

### 3. Push and create PR

After the utility commits, push the branch and create a PR.

## Notes

- The `core` provider tracks mql's version -- never release it independently.
- The utility generates a changelog from commit messages since the last version bump.
- With `--commit`, commits are authored as "Mondoo <hello@mondoo.com>".
- The CI workflow at `.github/workflows/release-providers.yml` can also trigger releases via workflow dispatch.

## Typical Flow

1. Run `check` to see what changed
2. Confirm with the user which providers to release
3. Run `update` with `--increment=patch --commit`
4. Push the branch and create a PR
