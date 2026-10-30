---
name: check-querypack-deprecations
description: Check content/ mql.yaml query packs for usage of deprecated resources or fields from .lr definitions
disable-model-invocation: true
argument-hint: "[path-to-mql-yaml (optional, defaults to all)]"
---

# Check Query Packs for Deprecated Resource Usage

Audit MQL query pack files (`*.mql.yaml` in `content/`) against the provider `.lr` resource definitions to find queries that reference deprecated resources or fields.

## Steps

### 1. Collect all deprecated items from .lr files

Search all `providers/*/resources/*.lr` files for comments containing "Deprecated" (case-insensitive). For each match, extract:
- The resource name (e.g., `microsoft.organizations`)
- The field name if it's a field deprecation (e.g., `createdTime`)
- What replaces it (from the deprecation comment)

Use Grep to find lines with `// Deprecated` or `/ Deprecated` in `.lr` files, then read surrounding context to get the resource/field names.

### 2. Determine which mql.yaml files to check

- If `$ARGUMENTS` is provided, check only that file
- Otherwise, find all `*.mql.yaml` files under `content/`

### 3. Cross-reference queries against deprecated items

Read each mql.yaml file and examine every `mql:` block. Check if any deprecated resource name or field appears in the query string. Be thorough:
- Check for resource names like `microsoft.organizations`
- Check for field access like `.createdTime`, `.vpcId`, `.staticWebsiteHosting`
- A field like `createdTime` on `aws.s3.bucket` would appear as something accessing `.createdTime` in a query that operates on s3 buckets

### 4. Report findings

For each deprecated usage found, report in a markdown table:
- File path
- Query UID
- Deprecated usage (the exact text in the query)
- Replacement (what it should be changed to)

If no deprecated usage is found, say so.

Do NOT make any changes to files. This skill is read-only — it only reports findings.
