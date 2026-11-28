# ADR 061: Record schema of the data-inventory dataset

## Status

Proposed. Implemented in `providers-sdk/v1/upstream/datasets/dspminventory`.

*Revised 2026-11-28: a data store the repository names is an
`inventory.AssetRelationship` (ADR 060) in the `Record` oneof, field 5, the
edge a scan writes too, instead of the dataset's own `StoreRef` message. The
store is an asset stub named by platform id or by claims. A reference whose
target could not be read is an `UnresolvedStore` record, field 6, not an
edge. Field 3 and the name `store_ref` are reserved. The package was not
released before the change, so it stays `v1`.*

## Context

A code scanner can produce an inventory of the data a repository's code
touches: the entities it declares (structs, ORM models, schemas), their
sensitive fields and the table columns those map to, the data stores the
repository declares in infrastructure as code or connects to through a URL
in configuration, and the flows of sensitive fields into sinks such as logs.
That inventory is what lets a platform join a code finding to a column a
data-store scan classified.

The inventory is uploaded as a dataset. A dataset upload carries records of a
versioned, public schema, so the platform can validate an upload without
depending on one producer's internal types, and so another producer can write
the same records. No schema exists for this inventory.

A store reference is an edge from the repository to a store the scanner
usually never scanned. Scans already report edges as `AssetRelationship`
(ADR 030), and ADR 060 gives that message the kinds, evidence and attributes
a store reference needs, so the platform reads a dataset edge as it reads a
scan edge.

The schema must not become a channel for the data it describes. The producer
reads configuration that holds connection strings with credentials; the
records must have no place to put them.

## Decision

### 1. One proto file, one package per dataset, one directory for all datasets

The schema is `providers-sdk/v1/upstream/datasets/dspminventory/dspm_inventory.proto`,
proto package `mondoo.datasets.dspm_inventory.v1`, Go package
`go.mondoo.com/mql/providers-sdk/v1/upstream/datasets/dspminventory`.

Every dataset record schema lives under `upstream/datasets/`, one subdirectory
per dataset. Each dataset gets its own Go package because every dataset has a
top-level `Record` type; in one Go package they would collide.

The version is in the package name. A breaking change is a new package
(`v2`), never an edited message. Adding a field or a record kind is additive
and stays in `v1`.

### 2. One `Record` with a `oneof`

| Message | Fields (number, type) |
|---|---|
| `Record` | `oneof record { Entity entity = 1; Field field = 2; Flow flow = 4; cnquery.providers.v1.AssetRelationship relationship = 5; UnresolvedStore unresolved_store = 6; }`, `reserved 3; reserved "store_ref";` |
| `Entity` | `name = 1`, `language = 2`, `file = 3`, `table = 4` (strings), `table_source = 5` `TableSource`, `schema = 6`, `subject = 7` (strings), `line = 8` uint32 |
| `Field` | `entity = 1`, `entity_file = 2`, `name = 3`, `column = 4`, `category = 5`, `confidence = 6`, `file = 7` (strings), `line = 8` uint32 |
| `Flow` | `rule_id = 1`, `finding_fingerprint = 2`, `field = 3`, `entity = 4`, `category = 5`, `sink = 6`, `file = 7` (strings), `line = 8` uint32 |
| `UnresolvedStore` | `kind = 1`, `file = 2` (strings), `line = 3` uint32, `reason = 4`, `resource_address = 5`, `resource_type = 6`, `scheme = 7` (strings) |

`TableSource` is an enum: `MAPPING` (the ORM's own metadata), `DDL` (a
`CREATE TABLE`), `CONVENTION` (a framework default that is exact without
anything outside the file). It is a closed set the producer computes.
Category, confidence, subject and sink stay strings, because their sets grow
with the classifier, and a new value must not need a schema change.

`Entity`, `Field` and `Flow` are not edges. An entity has no far end. A
field's `column` is the column name as the code writes it, before any store
is known: the field-to-column match exists only once the platform has
resolved the store. A flow's far end is a sink class, not an endpoint.

### 3. A store reference is an `AssetRelationship`

The upload is for one repository, which is the carrying asset of every store
relationship, so no record names it. A store the repository declares or
connects to is an `inventory.AssetRelationship` (ADR 060):

- `kind`: `declares` (infrastructure as code declares the store) or
  `connects-to` (a connection URL in configuration).
- `from_resource_type` `file` and `from_resource_id` the path of the file
  that names the store, relative to the repository root.
- `asset`: the store, as a stub. Its `platform_ids` hold the provider's
  platform id when the producer can build one (it knows the account and
  region); otherwise a claim names it: `cloud-resource` (`type`, `name`)
  for `declares`, `database-endpoint` (`scheme`, `host`, `port`,
  `database`) for `connects-to`.
- `evidence`: `RELATIONSHIP_EVIDENCE_DECLARED`.
- `attributes`: the kind's keys in `inventory.RelationshipKinds`.
  `declares`: `resource_address`, `root_module_dir`, `resolution`, `line`.
  `connects-to`: `resolution`, `line`. `line` is a positive integer;
  `resolution` is `literal`, `tfvars`, `fields` or `placeholder-default`.

The former `StoreRef` fields map as follows: the URL parts and the resource
type and name are the store's claim, the file is the from anchor, the line
and the declaring resource's details are attributes, and `resolved` and
`unresolved_reason` moved to `UnresolvedStore`.

`ValidateStoreRelationship` checks a record: `AssetRelationship.Validate`
(the kind's rules, a stub carrying identity only), one of the two kinds, a
`file` from anchor and declared evidence. `Write` and `Read` call it and
refuse a record that fails with `ErrInvalidRecord`.

### 4. An unreadable reference is not an edge

A reference whose target could not be read (a name the cloud generates, an
expression that needs planning, a CloudFormation intrinsic, ERB) names no
store. It is an `UnresolvedStore`: the kind it would have had, the file and
line, the reason (`omitted`, `expression`, `intrinsic`, `erb`) and what the
producer could read (the declaring resource's address and type, or the URL
scheme). Giving it an invented store identity would join unrelated
repositories that share a file layout into one store. `ValidateUnresolvedStore`
requires a store kind, a file and a reason.

### 5. Names and classes only

No message has a field for a data value, a sample, a configuration value
other than a normalized store identity, a credential, or a hash of any of
them. The producer reduces a connection URL before it reaches the record:
user information, every host after the first, the query and the fragment are
removed. The `database-endpoint` claim has no key that could hold them, and
`AssetRelationship.Validate` refuses an unknown claim key, an unknown
attribute, and anything on the store's asset but its identity.

`TestDatasetRecordsCarryNoValues` walks every field of every message in the
file, every attribute key of the two store kinds and every claim key that
names a store, and fails on a name matching
`value|sample|secret|password|passwd|token|credential|hash|key` that has no
reviewed entry in its allow list. The allow list starts empty.

### 6. Framing, order, digest and limits

- A dataset is a sequence of records, each prefixed with its length as a
  uvarint: the protobuf-delimited form that `protodelim` reads.
- `Sort` orders records into the canonical order: entities by (file, name),
  fields by (entity file, entity, name), store relationships by (file, line,
  kind, store), with the file from the from anchor, the line from the
  attributes and the store from its identity (MRN, else first platform id,
  else its claims in key order), unresolved stores by (file, line, kind),
  flows by (file, line, rule id). Records equal on those keys are ordered by
  their deterministic encoding, so the order depends only on the records: a
  producer that builds them from map iteration still writes one digest. A
  record is encoded for this only when it ties.
- `Write` encodes each record with deterministic map order and returns the
  lowercase hex SHA-256 of the bytes it wrote, the upload's content digest.
  Deterministic encoding is needed because attributes and claims are maps,
  and the default encoder orders map entries randomly.
- `Read` refuses a record whose length prefix is over 1 MiB before reading it,
  and a dataset with more than 10,000 entities, 100,000 fields, 1,000 store
  relationships, 1,000 unresolved stores or 100,000 flows, or more than
  212,000 records in all (their sum). The total also bounds records no
  per-kind limit counts, a record with no kind set or of a kind from a newer
  producer, which can be zero bytes long. `Write` refuses the same, so a
  producer cannot build an upload the reader refuses.

### 7. The generate wiring covers nested packages

`TestEveryProtoPackageIsWiredIntoTheMakefile` read only the direct children
of `upstream/`, so a dataset package under `datasets/` would have been
deleted by `make clean/proto` and never regenerated. The test now walks the
whole tree, and `shared/generate` calls
`go generate ./providers-sdk/v1/upstream/datasets/dspminventory`. The proto
imports `providers-sdk/v1/inventory/inventory.proto` by its repository path,
as the inventory's own imports do.

## Security implications

- **Threat model:** the dataset is producer input to the platform. A producer
  could put a value into a free-text field such as a file path or an entity
  name; the schema cannot prevent that, and the platform treats every field as
  untrusted input. What the schema prevents is a field whose purpose is a
  value, and the field-name test keeps a later edit from adding one silently.
- **Data handling:** a store's identity (its platform id or claim) is the only
  configuration value, and the producer normalizes it with credentials and
  query parameters stripped. Attributes and claims are closed key sets; an
  unknown key is refused, so a free-form `Struct` or claim map cannot carry a
  connection string under a new name. The store's `Asset` may carry only its
  identity: no connections, credentials, labels or nested assets.
- **Authentication and authorization:** unchanged. The SDK adds no RPC; the
  upload is authenticated and authorized by the platform as today.
- **Supply chain:** none added. The schema uses the protobuf toolchain already
  pinned under `scripts/protoc`. The package imports the inventory SDK
  package for `AssetRelationship`.
- **Resource exhaustion:** `Read` bounds the size of one record before
  allocating it, the count of each record kind, and the count of all records,
  so a stream of empty records cannot grow memory without bound. The stub
  rule refuses a nested `related_assets` tree, so a small record cannot
  decode into a deep one.

## Performance implications

- Measured: `BenchmarkWrite`, `Sort` plus `Write` of 100,000 records (1,000
  entities, 98,000 fields, 500 store relationships, 500 flows): about 80 ms
  and 7.3 MB allocated per run on a 16-vCPU workstation under other load
  (2026-11-28). Earlier runs on 4 vCPU were 57 to 63 ms and 6.4 to 6.6 MB;
  the machines differ, so read these as the same order, not as a change.
- The sample's store relationships are 148 to 240 bytes and its unresolved
  store 55 bytes (measured with `proto.Size`, 2026-11-28); at the limit of
  1,000 of each that is well under 1 MB.
- Estimate, not measured: records are 60 to 250 bytes each, so a repository
  with 500 entities, 5,000 fields, 50 store references and 200 flows writes
  about 1 MB before compression.
- No effect on any existing path: the package is new and nothing in mql reads
  it.

## Consequences

### Positive

- The data inventory has a public, versioned schema that any producer can
  write and the platform can validate.
- The record has no field that can hold a credential or a data value, and a
  test keeps it that way.
- A store reference is the edge a scan writes, and a store named by platform
  id joins the scanned asset without a dataset-specific path.

### Negative

- Another public contract to version and document.
- `TableSource` needs a schema change for a new value. That is deliberate.
- A store named only by a claim stays unjoined until the platform matches
  that claim kind (ADR 060, Follow-up).
- `resolution` and `UnresolvedStore.reason` are strings, so a misspelled
  value is not caught on decode.
- The package depends on the inventory SDK package, and a change to a store
  kind there is a change to this dataset.

## Alternatives considered

### Keep the schema private to the producer

Rejected: the dataset upload refuses an unknown schema, and a private schema
would make the platform depend on one producer's internal types.

### All dataset schemas in one Go package

Rejected: each dataset has a top-level `Record`, and several datasets in one
Go package would collide on it, or force every message to carry the dataset's
name as a prefix.

### Keep `StoreRef` as the dataset's own message

Rejected: the platform would read store references differently from every
other edge, and a later move to the shared edge would be a `v2` package.

### A key string for the store (`external_key`)

An earlier revision named the store by a normalized string and an
unreadable one by `unresolved:<repository>:<file>:<line>`. Rejected: a key
string joins nothing, and an unreadable reference is not a store at all.

### Strings instead of enums for the closed sets

Rejected for `TableSource`: a producer and the platform would drift on
spelling without either noticing, and the field-name test cannot catch a
value mismatch. Accepted for `resolution` and the unresolved reason, which
are a kind's attribute and a record of their own; checking their values
belongs to the kind registry (ADR 060).
