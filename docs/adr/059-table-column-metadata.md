# ADR 057: Column metadata on Snowflake, PostgreSQL, MySQL and AWS Glue tables

## Status

Proposed

- **Date:** 2026-11-27
- **Deciders:** TBD (snowflake, postgresdb, mysqldb and aws provider owners)
- **Consulted / Informed:** TBD (databricks and gcp provider owners, cnspec content owners)

## Context

A data governance review asks which tables hold a column named like a personal or
payment identifier, for example `ssn`, `iban` or `email`, and whether a nullable column
with a comment says what it holds. Answering it from names alone reads no data value.
mql lists the tables of four common stores but none of their columns:

- `snowflake.table` has name, database, schema, owner, size and retention, and no column
  field (`providers/snowflake/resources/snowflake.lr:2114-2166`). Tables are listed by
  `SHOW TABLES`, account-wide or per database (`providers/snowflake/resources/tables.go:20-47`).
- `postgresdb.table` is one `pg_class` relation (table, view, materialized view, foreign
  or partitioned table) with owner, privileges and row-level security, and no columns
  (`providers/postgresdb/resources/postgresdb.lr:194-213`); the schema lists its relations
  in one query (`providers/postgresdb/resources/tables.go:47-92`).
- `mysqldb.table` is one `information_schema.TABLES` row with engine, row format and
  encryption, and no columns (`providers/mysqldb/resources/mysqldb.lr:270-283`;
  `providers/mysqldb/resources/schemas.go:101-161`). `information_schema` lists only the
  rows the caller holds a privilege on; the provider guards that with
  `requireVisibility` and `CallerAccess.CanListTables` (global `SELECT`)
  (`providers/mysqldb/resources/mysqldb.go:76-104`, `providers/mysqldb/connection/access.go:36-41`).
- `aws.glue.database.table` carries the columns only inside the raw `storageDescriptor`
  dict (`Columns: [{Name, Type, Comment, Parameters}]`) and `partitionKeys []dict`
  (`providers/aws/resources/aws.lr:28395`, `:28401`), both already read by the
  `GetTables` call that lists the table (`providers/aws/resources/aws_glue.go:733-764`,
  `:800-853`). The table names its database by the raw `databaseName` string (`:28377`)
  and its S3 location only inside the dict. A refused `GetTables` is returned as the raw
  SDK error (`aws_glue.go:752-754`); a refused `GetDatabases` in one region is logged and
  skipped (`aws_glue.go:645-652`).
- BigQuery tables carry `schema []dict` with `Name`, `Type`, `Description`, `Required`,
  `Repeated` (`providers/gcp/resources/gcp.lr:4930`).

The S3 bucket behind a Glue table is a modeled resource, and an `s3://` URI already has
a resolver (`s3BucketRefFromUri`, `providers/aws/resources/aws.go:82-104`).
`glue:GetDatabases` and `glue:GetTables` are already in the AWS permission manifest
(`providers/aws/resources/aws.permissions.json:561`, `:567`).

Provider versions: snowflake `14.1.2` (`providers/snowflake/config/config.go:18`),
postgresdb and mysqldb `14.0.15` (`providers/postgresdb/config/config.go:17`,
`providers/mysqldb/config/config.go:17`), aws `14.14.1` (`providers/aws/config/config.go:18`).

## Decision

**1. One column shape in every provider.** Each table resource gains
`columns() []<table>.column`, a private column resource keyed by the table's `__id` plus
`/column/<name>`, with these fields where the source records them:

| Field | Type | Meaning |
|---|---|---|
| `name` | `string` | column name as stored |
| `position` | `int` | ordinal position as the source reports it (omitted where the source reports none) |
| `typeName` | `string` | declared type in the source's own spelling, for example `character varying(255)`, `VARCHAR(16777216)`, `decimal(10,2)` |
| `nullable` | `bool` | whether the column accepts null (omitted where the source has no such notion) |
| `comment` | `string` | column comment or description, empty when none |

The names follow the Databricks Unity Catalog column API (`name`, `type_name`,
`position`), so a Databricks column resource, which the provider does not model yet, can
use the same ones, and a query written for one store reads the same on another. No field holds
a column value, a default expression, a statistic, a histogram or a sample. Column
default expressions are left out on purpose: they can carry literals.

**2. Per provider.**

| Provider | Resource | Source | Calls |
|---|---|---|---|
| snowflake | `snowflake.table.column` (`name`, `typeName`, `nullable`, `comment`; no `position`) | `SHOW COLUMNS IN SCHEMA <db>.<schema>`; `data_type` is a JSON document holding the type, length, precision, scale and nullability (*inferred*) | one statement per schema, memoized on the account for the scan; no warehouse needed (`SHOW` runs in cloud services, *inferred*) |
| postgresdb | `postgresdb.table.column` (all five fields) | `pg_attribute` joined to `pg_class` for the schema, `attnum > 0 AND NOT attisdropped`; `format_type(atttypid, atttypmod)`, `NOT attnotnull`, `col_description(attrelid, attnum)` | one query per schema, memoized; shared by every relation of the schema |
| mysqldb | `mysqldb.table.column` (all five fields) | `information_schema.COLUMNS` for the schema: `COLUMN_NAME`, `ORDINAL_POSITION`, `COLUMN_TYPE`, `IS_NULLABLE`, `COLUMN_COMMENT` | one query per schema, memoized |
| aws | `aws.glue.database.table.column` (`name`, `position`, `typeName`, `comment`, plus `isPartitionKey bool` and `parameters map[string]string`; no `nullable`, Glue records none) | the `StorageDescriptor.Columns` and `PartitionKeys` of the `GetTables` response already read; partition keys follow the storage columns in position | no new call |

PostgreSQL reads `pg_catalog` rather than `information_schema.columns` because the
latter lists only columns the role holds a privilege on, and `pg_attribute` is readable
by every role by default. Snowflake's `SHOW COLUMNS` lists the columns of views as well;
a table's `columns()` keeps only rows whose table name matches it. Snowflake documents
a maximum row count for `SHOW` output (10,000 rows, *inferred*); a schema whose answer
reaches it is re-read one table at a time with `SHOW COLUMNS IN TABLE`, so a large schema
is never silently cut.

**3. Glue: typed references.** `aws.glue.database.table` gains
`database() aws.glue.database`, resolved against the region's already-listed databases
(`databaseName` stays, it is the raw record), and `s3Bucket() aws.s3.bucket`, resolved
from `StorageDescriptor.Location` through `s3BucketRefFromUri` after `s3a://` and
`s3n://` are normalised to `s3://`. A table whose location is not in S3 (a JDBC or
federated table) sets the field null with `StateIsSet | StateIsNull`.

**4. Errors.** The column fields are new, so a refusal is a classified error whatever
`plugin.StructuredErrors()` says; an empty list means "read, and the table has no
columns".
- Snowflake: SQLSTATE `42501` → `llx.Forbidden` naming the privilege (`USAGE` on the
  schema).
- PostgreSQL: SQLSTATE `42501` on `pg_attribute` (a hardened database that revoked it)
  → `llx.Forbidden` naming `SELECT ON pg_catalog.pg_attribute`.
- MySQL: a caller without global `SELECT` sees only the columns it holds a privilege on,
  without an error, so `columns()` returns `llx.Forbidden` naming `SELECT ON *.*` when
  `CanListTables()` is false, instead of a list that may be partial. A MySQL
  access-denied error number → `llx.Forbidden`.
- Glue: the column fields cannot be refused on their own (no call). The existing
  `aws.glue.database.tables()` returns `llx.Forbidden` naming `glue:GetTables` when
  `GetTables` is refused, behind `plugin.StructuredErrors()` (a changed field; it keeps
  returning the raw error with the flag off). A refused region in `databases()` stays a
  logged partial result.

**5. Discovery is unchanged.** No table or column becomes an asset; the fields are read
on the table resources that exist.

**6. Versions and tests.** `.lr.versions` entries at the next patch version of each
provider: snowflake `14.1.3`, postgresdb and mysqldb `14.0.16`, aws `14.14.2`. Unit tests
per provider in the `_test.go` of the file changed: row decoding (a nullable and a
non-nullable column, a comment, an empty comment), the memo making one statement for
two tables of a schema, the view-row filter (Snowflake), the cap fallback (Snowflake),
the partial-visibility refusal (MySQL), dropped and system columns excluded
(PostgreSQL), partition-key ordering and `s3a://` normalisation (Glue), and each
refusal's error kind. Each case is labelled measured or synthetic; the measured cases
come from a live database of each engine and one Glue catalog.

## Security implications

- **Threat model.** Read-only catalog queries over connections and credentials the
  providers already hold. No new write path, no new credential.
- **Data handling.** Column names, declared types, nullability and comments only; no row
  is read and no default expression is returned. A comment is free text the owner wrote
  and can name a project or a person; it is handled like the table comments mql already
  returns (`snowflake.lr:2161`, `aws.lr:28382`).
- **Authorization.** No privilege beyond what each provider already uses: `USAGE` on the
  Snowflake schema, PostgreSQL's default `pg_catalog` access, MySQL global `SELECT`
  (already needed by `tables()` under structured errors), `glue:GetTables` (already in
  the manifest). A missing privilege is reported as `Forbidden` with its name.
- **Supply chain.** No new dependency.
- **Residual risk.** A Glue table registered with Lake Formation returns to `GetTables`
  only what the scanning role may describe; whether column-level Lake Formation grants
  narrow the returned columns is *inferred* and not detectable from the response. The
  field description says the columns are "as the catalog returns them to the scanning
  role".

## Performance implications

- **Expected impact.** One statement per schema whose columns are read (Snowflake,
  PostgreSQL, MySQL); none for Glue. Fields are computed and read only when a query asks
  for them; a scan that does not read them is unchanged.
- **Evidence.** Statement counts from the code paths; not measured.
- **Scale assumptions.** A warehouse with 10^5 tables in 10^3 schemas is 10^3 statements
  when every column is read. A Snowflake schema above the `SHOW` cap costs one statement
  per table of that schema.
- **Regression budget.** No added call for queries that do not read `columns`; at most
  one statement per schema when they do, checked in the debug log of the live
  verification.

## Consequences

### Positive

- Column names, types and comments are queryable on every warehouse and catalog mql
  covers, with one field vocabulary.
- Glue tables point at their S3 bucket and database as typed references, so a finding on
  a column can be tied to the bucket that stores it.

### Negative

- Five resources to keep aligned in five modules; nothing but review keeps their field
  names the same.
- Snowflake columns carry no position.
- MySQL callers without global `SELECT` get an error rather than the columns they can
  see.

### Follow-up

- Column fields on Snowflake views and external tables, and on BigQuery as a typed
  resource if a check needs more than the dict.
- `snowflake.table.column.tagReferences()`, once the provider exposes the account's tag
  references.

## Alternatives considered

### Option A - `columns []dict` like BigQuery

Smaller schema. Rejected: a column has a natural key (table and name), is the subject of
its own checks, and in Unity Catalog already carries tags and a mask; a dict cannot grow a
typed accessor later without a breaking change.

### Option B - `information_schema.COLUMNS` in Snowflake

Carries `ORDINAL_POSITION`. Rejected as the default: it needs a running warehouse
(*inferred*), which a scan of metadata does not otherwise need, and costs compute.

### Option C - `information_schema.columns` in PostgreSQL

Portable across engines. Rejected: it hides columns the role holds no privilege on,
without an error, which reads as a table with fewer columns.

### Option D - One query per table

Simplest code. Rejected: 10^5 tables would be 10^5 statements.

## References

- mql `providers/snowflake/resources/snowflake.lr`, `tables.go`, `errors.go`;
  `providers/postgresdb/resources/postgresdb.lr`, `tables.go`, `postgresdb.go`;
  `providers/mysqldb/resources/mysqldb.lr`, `schemas.go`, `mysqldb.go`,
  `providers/mysqldb/connection/access.go`; `providers/aws/resources/aws.lr`,
  `aws_glue.go`, `aws.go`, `aws.permissions.json`; `providers/gcp/resources/gcp.lr`
  (at `d8f47a409`)
- mql `docs/adr/046-structured-provider-errors.md` (§3, §8, §9)
