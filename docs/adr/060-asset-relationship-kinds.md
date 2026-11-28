# ADR 060: Kinds, evidence and attributes on asset relationships

## Status

Proposed. Extends [ADR 030](030-asset-tree-anchored-relationships.md).
Implemented in `providers-sdk/v1/inventory/inventory.proto`
(`AssetRelationship`, `RelationshipEvidence`), `asset_relationship.go` and
`asset_claim.go`.

## Context

ADR 030 gave an asset its edges: `Asset.relationships` (field 39), each an
`AssetRelationship` naming the asset at the other end and the resource on it
that anchors the edge. Three producers write them today: MCP server discovery
(`providers/os/resources/mcp_discovery.go`), docker containers
(`providers/os/resources/discovery/docker_engine/container.go`) and IaC
detections (`providers/iac/connection/detection.go`). Cross-asset traversal
(ADR 031) reads them in `providers/asset_resolver.go`.

Every ADR 030 edge means the same thing: the carrying asset hangs off the
anchor resource on the other asset. Other producers report edges that mean
something else. A code scanner uploading a dataset for a repository reports
which data stores the repository declares in infrastructure as code or
connects to through a connection URL. Those edges have a meaning (declares,
connects-to), a basis (a file states it), details (the declaring resource's
address, the line), and an end that was usually never scanned: the scanner
knows a bucket name or a database endpoint, not an MRN or a platform id.

`AssetRelationship` cannot say any of that. A second edge message would give
the inventory three edge shapes (`related_assets`, `relationships`, and the
new one) and a conversion between two of them, against ADR 030's own
direction of one edge that `related_assets` folds into.

## Decision

Complete the ADR 030 edge rather than add another.

### 1. Every end is an asset stub

The other end of an edge is always an `Asset`, carrying only its identity:
`id`, `mrn`, `platform_ids`, `name` and `claims`. It is identified by the
strongest identity the producer has:

1. `mrn`, once the platform has assigned one;
2. `platform_ids`, built with the provider's own function (for AWS,
   `MondooObjectID` in `providers/aws/resources/discovery_conversion.go`),
   never retyped, so the edge joins the asset a scan discovers;
3. `claims` (field 41, `AssetClaim`), kind-tagged facts, when there is no
   canonical id. Two claim kinds are added beside `container-image`:
   - `cloud-resource`: `type` (the declaring resource type as written, e.g.
     `aws_s3_bucket`, `AWS::S3::Bucket`) and `name`;
   - `database-endpoint`: `scheme` and `host`, optionally `port` and
     `database`, from a normalized connection URL.

`ValidateClaim` checks a claim's kind, its keys, the required keys and that
no value is empty. Claims are what the server already uses to recognise the
same thing across scans; until it learns these kinds, a claim-identified end
stays unjoined (Follow-up).

### 2. Five additive fields on `AssetRelationship`

```proto
message AssetRelationship {
  Asset  asset              = 1;  // unchanged
  string resource_type      = 2;  // unchanged: anchor on `asset`
  string resource_id        = 3;
  string kind               = 4;  // registered kind; empty = the ADR 030 edge
  string from_resource_type = 5;  // anchor on the carrying asset
  string from_resource_id   = 6;
  RelationshipEvidence evidence = 7;
  google.protobuf.Struct attributes = 8;  // per kind, at most 4 KiB
}
```

- The direction is fixed: from the carrying asset to `asset`. The kind says
  what that means.
- An anchor on the carrying asset is ADR 030's `fromResource`, sketched there
  and not built until now. A dataset edge anchors on the file that states it
  (`file`, the path relative to the repository root); the line is an
  attribute.
- `RelationshipEvidence`: `ATTESTED` (a verified signed statement),
  `DIGEST_EXACT` (both ends matched by one content digest), `RECORDED` (a
  system of record lists it), `DECLARED` (a configuration or source file
  states it). `UNSPECIFIED` means the producer does not say, which is every
  ADR 030 edge today.
- No producer, generation, confidence or derivation inputs. A scan's producer
  is mql and a dataset's is on its upload; the others belong to edges the
  platform derives in its own store.

### 3. One registry of kinds

`RelationshipKinds` in `asset_relationship.go` registers each kind with what
it allows: whether cross-asset traversal follows it, which anchors it
requires, which claim kinds may identify the other end, and its attribute
keys with their types.

| Kind | Traversable | Requires | Other end by claim | Attributes |
|---|---|---|---|---|
| (empty) | yes | anchor on `asset` | none (MRN or platform id) | none |
| `declares` | no | anchor on the carrier | `cloud-resource` | `resource_address`, `root_module_dir`, `resolution` (strings), `line` (positive integer) |
| `connects-to` | no | anchor on the carrier | `database-endpoint` | `resolution` (string), `line` (positive integer) |

`AssetRelationship.Validate` refuses an unknown kind, an end that is not a
stub or has no identity, a claim the kind does not allow, half an anchor or a
missing required one, an unknown evidence value, and an attribute the kind
does not register, of the wrong type, or past 4 KiB.

`AssetRelationship.Traversable` reports whether ADR 031 follows the edge. The
resolver in `providers/asset_resolver.go` skips edges that are not, so an
edge of another kind that names the same anchor never places an asset under
a resource.

### 4. What is not an edge

A reference whose target could not be read (a name the cloud generates, an
expression that needs planning, ERB) points at nothing, so it has no other
end. It is not given an invented identity; a producer reports it as a record
of its own, outside the relationships.

### 5. Compatibility

All fields are additive. The three producers write the empty kind and are
unchanged; their edges validate as they are. `related_assets` stays
deprecated in favor of `relationships`, as ADR 030 decided.

## Security implications

- **Threat model:** an edge is producer input. Every field is untrusted.
  Because `asset` is a full `Asset` on the wire, `Validate` refuses anything
  but identity on it: no connections or credentials, no labels or
  annotations, no nested `related_assets` tree to amplify memory on decode.
- **Data handling:** claims and attributes carry names and identifiers, never
  a credential. A producer that reads a connection URL normalizes it first
  (no user information, no query, no fragment); `database-endpoint` has no
  key that could hold them, and an unknown key is refused.
- **Authentication and authorization:** unchanged. No RPC is added.
- **Supply chain:** `google/protobuf/struct.proto` is part of the protobuf
  runtime already in use. No new dependency.

## Performance implications

- Existing producers set none of the new fields, so their assets encode to
  the same bytes.
- `Validate` clones the stub once and sizes the attributes once, both bounded.
  It runs where a producer or reader calls it, not on the scan path. Not
  measured; expected to be negligible next to decoding.

## Consequences

### Positive

- One edge type in the inventory. A scan edge and a dataset edge are read the
  same way, and a stub with a platform id joins without a conversion.
- An unscanned end is named by facts the server can match, not by a string
  only one producer understands.

### Negative

- `asset` stays a full `Asset` on the wire, so the stub rule is enforced by
  `Validate`, not the schema.
- Data-store kinds live in the inventory package. A new kind is an SDK
  change, which is the point of a registry, and its cost.

### Follow-up

- Server-side matching of `cloud-resource` and `database-endpoint` claims, so
  claim-identified ends join scanned assets.
- `related_assets` producers move onto the empty kind (ADR 030).
- Kinds for edges further producers report, each with its registry entry.

## Alternatives considered

### A separate relationship message

A first version of this ADR added `Relationship`, a record with its own end
type (`asset_mrn`, `asset`, or `external_key`). Rejected: every edge mql emits
already has a carrying asset (a scan's discovered asset, a dataset's
repository), so the message duplicated `AssetRelationship` and needed a
conversion between the two, and its follow-up was to add the same fields to
`AssetRelationship` anyway.

### `external_key` and `external_account` for unscanned ends

Rejected: a key string joins nothing and only its producer knows how to read
it. A platform id joins when the producer can compute one; claims name the
end by facts the server can learn to match. An account is part of a platform
id when it is known.

### Identity in labels, annotations or the name

Rejected: those are free-form and display fields with no defined meaning, and
free-form maps are exactly what the stub rule keeps out.

### Anchors that do not resolve

A dataset edge could anchor on a synthetic resource type. Rejected: ADR 030
and ADR 031 read an anchor as a resource in the asset's tree, and a type no
provider defines breaks that for every consumer.

## References

- [ADR 030](030-asset-tree-anchored-relationships.md): asset relationships
  anchored to the resource tree
- [ADR 031](031-in-query-cross-asset-traversal.md): in-query cross-asset
  traversal
