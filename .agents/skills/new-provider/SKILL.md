---
name: new-provider
description: Scaffold a new mql provider. Use when the user wants to create a new provider, bootstrap a provider, or add a new integration target (e.g., "create a provider for Datadog", "scaffold a new provider", "add a new provider").
argument-hint: "<provider-id> (e.g., datadog, snowflake, pagerduty)"
---

# Scaffold a New Provider

Create a new mql provider using the built-in scaffolding tool and walk through initial setup.

## Step 1: Gather Parameters

Use `AskUserQuestion` to collect the required parameters. Pre-fill from the skill argument if provided.

The scaffolding tool needs:
- **provider-id**: lowercase, hyphen-separated identifier (e.g., `datadog`, `google-workspace`). Used for directory name, Go package, and CLI commands.
- **provider-name**: human-readable display name (e.g., `Datadog`, `Google Workspace`). Used in help text and UI.

If the user already supplied both values (or one can be inferred from context), skip asking for that value. Always confirm what will be created before running the tool.

## Step 2: Run the Scaffold Tool

Run from the repository root:

```bash
go run apps/provider-scaffold/provider-scaffold.go \
  --path providers/<provider-id> \
  --provider-id <provider-id> \
  --provider-name "<Provider Name>"
```

The scaffold tool auto-registers the provider in `Makefile` and `DEVELOPMENT.md`.

## Step 3: Complete Manual Registration

After scaffolding, the provider must also be registered in:
- `providers/defaults.go` — add a default entry (alphabetically)
- `README.md` — add a row to the provider table (alphabetically)

## Step 4: Initialize the Go Module

```bash
cd providers/<provider-id> && go mod tidy
```

## Step 5: Generate Resource Code

Run from the repository root:

```bash
make providers/mqlr 2>/dev/null || true
./mqlr generate providers/<provider-id>/resources/<provider-id>.lr --dist providers/<provider-id>/resources
```

## Step 6: Build and Install the Provider

```bash
make providers/build/<provider-id>
make providers/install/<provider-id>
```

Both steps are required: `build` compiles the provider binary, `install` copies it to `~/.config/mondoo/providers/` so mql can discover it.

## Step 7: Report Results

Show the user:
1. The files that were created (list the directory tree)
2. The key files they should edit next:
   - `resources/<provider-id>.lr` — resource and field definitions (schema)
   - `resources/<provider-id>.go` — resource implementations (Go code)
   - `connection/connection.go` — authentication and API client setup
   - `config/config.go` — CLI flags and `AssetUrlTrees` for asset discovery grouping
3. The commands to rebuild and test after making changes:
   ```
   make providers/build/<provider-id> && make providers/install/<provider-id>
   mql shell <provider-id>
   ```
4. That the work from here on is resource development, and the **`new-resource`** skill covers it: grounding the schema in a real artifact, the traps that fire at codegen, and verifying each field against a live target.

## Important Reminders

- Every source file must start with the copyright header (see AGENTS.md)
- Every resource and field in `.lr` files must have a doc-comment (see AGENTS.md for format rules)
- All `.lr.versions` entries for a brand-new provider should use the same version as `config.go` `Version`
- If you add `mql*Internal` structs, run `./mqlr generate` twice (second pass detects and embeds them)
- Connection setup (API keys, OAuth, env vars) goes in `connection/connection.go`
