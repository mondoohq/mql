# ADR 057: Snowflake tag references, and Unity Catalog tables, tags and column masks

## Status

Proposed

## Context

Snowflake and Unity Catalog both let an owner attach tags to tables and columns, and
both let a column be masked. A governance audit asks "which columns are tagged as
holding cardholder data, and is each one masked?". mql cannot answer it today:

- `snowflake.tag` lists the tags an account or database defines, with their allowed
  values, but not where each tag is set (`providers/snowflake/resources/snowflake.lr`,
  `snowflake.tag`; listed by `SHOW TAGS` in `providers/snowflake/resources/tags.go`).
  Accounts and databases expose `tags()`.
- `snowflake.table` has no columns.
- Masking policies report what they are attached to, including the column and, when
  attached through a tag, the tag (`snowflake.policyReference`). That gives masked
  columns, not tagged-and-unmasked ones.
- The provider already reads `SNOWFLAKE.ACCOUNT_USAGE` views, which need a warehouse
  and the privilege to read the `SNOWFLAKE` database (`key_rotation.go`), and memoizes
  one account-wide lookup instead of one per object (`policy_attachments.go`).
- `databricks.catalog` and `databricks.schema` carry no tags, and there is no table
  resource (`providers/databricks/resources/databricks.lr`). grep found no SQL statement
  execution in the databricks provider.

Both providers are at `Version: "14.1.2"` when this is written; new `.lr.versions`
entries go at the next patch after `Version` on the day of the implementing pull request.

## Decision

### 1. Snowflake: `snowflake.tagReference`

A new private resource, one row of `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES`:

```
private snowflake.tagReference @defaults("tagName domain objectName columnName value") {
  tag() snowflake.tag
  tagName string
  tagDatabase() snowflake.database
  tagSchema() snowflake.schema
  tagQualifiedName string
  value string
  domain string
  objectDatabase() snowflake.database
  objectSchema() snowflake.schema
  objectName string
  objectQualifiedName string
  columnName string
  table() snowflake.table
}
```

with `snowflake.account.tagReferences()`, `snowflake.table.tagReferences()` and
`snowflake.tag.references()`, each `[]snowflake.tagReference`.

- **One query per account.** `snowflake.account.tagReferences()` runs, once per account
  (`sync.Once` on the account's internal struct, value and error memoized):
  `SELECT TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_VALUE, DOMAIN, OBJECT_DATABASE,
  OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
  WHERE OBJECT_DELETED IS NULL`. The table and tag accessors filter that list, so a scan
  of many tables makes one query, not one per table.
- **Identity.** `__id` is `<DOMAIN>/<object qualified name>/<column>/<tag qualified name>`,
  so two tags on one column, or one tag on two columns, never collide in the cache. A
  NULL value or column reads `""`.
- **Typed references.** `tag()`, `table()`, `tagDatabase()`, `tagSchema()`,
  `objectDatabase()` and `objectSchema()` resolve against the account's already-listed
  tags, tables, databases and schemas, never a per-row `SHOW`, and set
  `StateIsSet | StateIsNull` before returning null. They are null for a dropped object,
  one the role cannot list, or a domain no resource models (a warehouse, a role, a user).
  The raw record for those cases is `objectQualifiedName` and `tagQualifiedName`.
  `objectName`, `tagName`, `columnName` and `domain` stay strings: `objectName` names
  objects of every domain, and Snowflake's set of domains is not closed.
- **Latency.** The view lags changes by up to two hours (Snowflake's documented figure
  for most account usage views, not measured here); the field description says so.

### 2. Databricks: tables, columns, tags and masks

New resources `databricks.table` (keyed by `fullName`) and private
`databricks.table.column` (keyed by table and name), and
`databricks.schema.tables() []databricks.table`:

| Field | Type |
|---|---|
| `databricks.table.name`, `fullName`, `catalogName`, `schemaName`, `owner`, `tableType`, `dataSourceFormat`, `storageLocation`, `comment` | `string` |
| `databricks.table.catalog()`, `databricks.table.schema()` | `databricks.catalog`, `databricks.schema` |
| `databricks.table.columns()` | `[]databricks.table.column` |
| `databricks.table.column.name`, `typeName`, `comment` | `string` (`typeName` is the full declared type text, for example `decimal(10,2)`) |
| `databricks.table.column.position` | `int` |
| `databricks.table.column.nullable` | `bool` |
| `databricks.table.column.mask()` | `databricks.function` (the column mask's function, resolved against the schema's listed functions; null when the column has no mask) |
| `databricks.catalog.tags()`, `databricks.schema.tags()`, `databricks.table.tags()`, `databricks.table.column.tags()` | `map[string]string` (tag key to value, empty value when set without one) |

- **Tables and columns** come from the Unity Catalog tables API, one list per schema;
  columns come from the same response, so no call is added per table. No column value,
  default or statistic is read.
- **Tags** come from the `information_schema` views `catalog_tags`, `schema_tags`,
  `table_tags` and `column_tags`. The first tag read of a catalog runs four statements,
  once per catalog per scan, through the Statement Execution API (30 s wait, inline
  JSON, every result chunk read), with the catalog name backtick-quoted. No other input
  reaches the statement.
- **Warehouse option.** The statements run on the SQL warehouse named by a new optional
  connection option `--warehouse-id` (env `DATABRICKS_WAREHOUSE_ID`, option
  `warehouse-id`), recorded in `config/cli-flags.json`. Without it every tag field
  returns `NotApplicable` "no SQL warehouse configured for tag reads", never an empty
  map. The flag is additive.
- **Account-plane connections.** A warehouse id belongs to one workspace, and
  account-plane discovery clones the account configuration into each workspace's.
  Discovery therefore removes `warehouse-id` from each discovered workspace's connection;
  those workspaces report tag fields as `NotApplicable`. Choosing a warehouse per
  discovered workspace is left open.

### 3. Errors

These are new fields, so they return classified errors directly, with no
`plugin.StructuredErrors()` branch:

| Cause | Kind |
|---|---|
| Snowflake: role cannot read `SNOWFLAKE.ACCOUNT_USAGE` (SQLSTATE `42501`) | `Forbidden`, naming `IMPORTED PRIVILEGES on database SNOWFLAKE` |
| Snowflake: no current warehouse | `NotApplicable` |
| Databricks: 403, or a statement refused for permissions | `Forbidden`, naming `USE CATALOG` and `SELECT` on `information_schema` |
| Databricks: no warehouse configured, or the warehouse is missing | `NotApplicable` |
| Databricks: statement still running after the wait | `Unavailable` |

An empty list or map means "read, and nothing is set", never "could not read". The table
and tag filters never turn an account-level error into an empty list.

### 4. Tests

Unit tests in the `_test.go` files named after the new source files: decoding of a
`TAG_REFERENCES` row with a column, without a column, and with an empty value; distinct
ids for two tags on one column and one tag on two columns; the account memo makes one
query for two tables and a tag; the table filter matches by stored name only; the typed
accessors resolve and set the null state; the decoding of a Unity Catalog table and its
columns; mask resolution; the `information_schema` fold, including a column with no tag;
identifier quoting; the error kinds for a denied view and a missing warehouse; discovery
dropping `warehouse-id`; the CLI flag and environment variable. Cases built from a live
account are labelled `Measured:`, the rest `Synthetic:`.

## Security implications

- **Threat model.** Read-only metadata queries with the connection's existing
  credentials; no new write path. The new Databricks option names a warehouse, not a
  credential.
- **Data handling.** Tag values are governance labels set by the owner, not table data;
  no row of any user table is read, and the statements read only `information_schema`
  views and an account usage view. Tag values can still be sensitive (a project code
  name), and are handled like other metadata fields.
- **Injection.** The only caller-controlled text in a Databricks statement is the
  catalog name, which is backtick-quoted with backticks doubled.
- **Authorization.** Reading `ACCOUNT_USAGE` needs the `SNOWFLAKE` database privilege,
  and `information_schema` tag views need `USE CATALOG` on each catalog; a missing
  privilege surfaces as `Forbidden`, so the user sees what to grant.
- **Supply chain.** No new dependency; the Snowflake driver and the Databricks SDK are
  already required, and the statement execution client is part of that SDK.
- **Residual risk.** `ACCOUNT_USAGE` latency means a tag set minutes ago is not listed;
  documented on the field.

## Performance implications

- **Expected impact.** Snowflake: one `TAG_REFERENCES` query per account per scan, only
  when a tag reference field is read; it needs a running warehouse, which the
  account-usage fields already need. Databricks: one tables-API list per schema and four
  `information_schema` statements per catalog, only when read.
- **Evidence.** Estimate from the statement counts of the code paths, not measured.
- **Scale assumptions.** Accounts with 10,000 tables and 100,000 tag references return
  one result set; the memo holds it for the scan.
- **Regression budget.** Scans that do not read these fields are unchanged. A scan that
  reads them adds at most one statement per account (Snowflake) or four per catalog
  (Databricks), and no more than 30 s of warehouse wait per statement.

## Consequences

### Positive

- A governance audit can check tag use and masking coverage per column in both
  warehouses.
- Typed references from a tag reference to its tag, table, database and schema, and from
  a column to its mask function.

### Negative

- Snowflake tag references lag by the account-usage latency.
- Databricks tag reads need a warehouse, a new option and running compute.
- Account-plane Databricks scans report tag fields as `NotApplicable` until a
  per-workspace warehouse choice exists.

### Follow-up

- `snowflake.table.columns` with types, if a check needs columns without tags.
- A warehouse choice per workspace discovered from an account-plane connection.
- Whether `storageLocation` gains a typed external-location accessor.

## Alternatives considered

### Option A - Snowflake `INFORMATION_SCHEMA.TAG_REFERENCES_ALL_COLUMNS` per table

No latency. Rejected as the default: one call per table turns a scan of 10,000 tables
into 10,000 statements. It can back a later per-table refresh.

### Option B - Databricks per-entity tag API

No warehouse needed. Rejected as the default: one call per catalog, schema, table and
column. Kept as the fallback if `information_schema` proves unavailable on some
workspaces.

### Option C - A raw `tags` dict on `snowflake.table` only

Smaller. Rejected: it cannot express column tags, and a raw table name where a typed
reference belongs is a breaking change to fix later.

### Option D - Raw database and schema names on `snowflake.tagReference`

Simpler to fill. Rejected: databases and schemas are modeled resources, so they are
typed accessors, with the qualified names kept as the raw record for what cannot be
resolved.

## References

- `providers/snowflake/resources/snowflake.lr`, `tags.go`, `tables.go`,
  `policy_attachments.go`, `key_rotation.go`, `errors.go`
- `providers/databricks/resources/databricks.lr`, `catalog.go`, `discovery.go`,
  `errors.go`; `providers/databricks/go.mod` (`databricks-sdk-go v0.199.0`)
- ADR 046 (structured provider errors)
