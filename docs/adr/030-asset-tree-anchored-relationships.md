# ADR 030: Asset relationships anchored to the resource tree

## Status

Proposed

## Context

The `os` provider models a large, growing family of developer/AI tools as
first-class resources (see [ADR 028](028-tool-install-indicator.md)). Several of
them expose configured **MCP (Model Context Protocol) servers** through per-tool
accessors: `claude.code.mcpServers`, `openai.codex.mcpServers`, `cursor.mcpServers`,
`github.copilot.mcpServers`, `gemini.mcpServers`, `windsurf.mcpServers`, each
returning a tool-specific `*.mcpServer` resource parsed from that tool's own config
files (`providers/os/resources/{claude_code,openai_codex,cursor,...}.go`, schema in
`providers/os/resources/os.lr`).

Today an MCP server is only a **leaf resource inside the host asset**. We want two
new capabilities:

1. **Discover MCP servers as their own assets** so cnspec can scan them (policies,
   later capability enumeration). Discovery must be opt-in — off by default, off
   under `auto`, on only when explicitly targeted or under `all` (that gating is a
   separate, already-understood piece; see Follow-Ups).
2. **Map the relationship back into the resource tree** so we know *which resource
   node* a discovered asset came from — `mcp1` from `claude.code`, `mcp2` from
   `openai.codex`, `mcp3` custom — not just "the host has some related assets."

The **future** goal that shapes this decision is cross-asset traversal in a single
query:

```
claude.code.mcpServers.first.running.tools
```

`.running` yields the MCP server as an asset; `.tools` resolves against *that
asset's* resource tree. This is federation across assets inside one query, and it is
what rules out the cheap options below.

### What we learned tracing the code

- **MRNs cannot be the join key.** Asset MRNs are assigned **upstream** by the
  Mondoo platform (`providers-sdk/v1/recording/upstream_recording.go:42`); in a
  local `mql` run there is no MRN at all
  (`apps/mql/cmd/shell.go:80`; the correlation sentinel
  `providers-sdk/v1/recording/recording.go:342` treats empty-MRN-with-platform-IDs
  as normal). A provider emitting a reference never talks to upstream about the
  referenced asset, so it cannot know that asset's MRN at emit time, and a
  referenced (child) asset's MRN is on an independent timeline — it may be assigned
  later, or never (if that discovery target is off).

- **The platform already correlates related assets with no MRN — by platform ID.**
  `inventory.Asset.RelatedAssets` (`inventory.proto:76`, field 33) is populated with
  stub assets carrying only a platform ID
  (`providers/os/provider/detector.go:138`: `&inventory.Asset{Id: ra.PlatformIDs[0]}`).
  This is the shipped rail for docker→containers, k8s→pods/namespaces, gcp, and OS
  cloud fingerprints.

- **But `RelatedAssets` is provenance-blind.** A flat
  `host.RelatedAssets: [{id: mcp1}, {id: mcp2}, {id: mcp3}]` records *that* the host
  relates to three assets and nothing about *where each hangs in the resource tree*.
  `RelatedAssets` is `[]*Asset` — the stub has only `Id`; there is no field that says
  "this one hangs off `claude.code.mcpServer/X`." It is flat, undirected, populated
  at connect/discovery time on the `Asset` struct, and shipped to the platform for
  correlation. It was never built to be produced from a query-field result, nor to be
  activated into a live connection.

So the relationship must be **anchored to the producing resource node** — the pair
`(resourceType, resourceID)` — carried on *both* sides of the join:

```
FORWARD (in-query, host policy):
  claude.code.mcpServer/X  --.running-->  asset-ref
      provenance is inherent: the field is defined ON that node, so the query path
      IS the anchor.

REVERSE (discovery, separate pass):
  discovered asset mcp1  carries  boundTo = (hostAsset, claude.code.mcpServer, X)
      provenance must be explicit, because the asset stands alone.

JOIN = match on (hostAsset, resourceType, resourceID) + child platform ID,
       NOT on a bare related-assets list.
```

The custom case (`mcp3`) is not special: any asset we support in discovery should,
going forward, be produced from *some* node in the resource tree. Absence of a
client anchor simply means it is a direct child of the host — the tuple degrades
correctly. This "everything discoverable is tree-anchored" is a direction we are
setting, not a state we reach overnight.

## Decision

Introduce a **first-class, directed asset relationship (edge)** anchored to the
resource tree, and **deprecate `RelatedAssets` in favor of it** over time.

### Edge shape (illustrative)

```
AssetRelationship {
  // the tree anchor: the resource node that produced this edge
  fromResource: { type: string, id: string }

  // which asset the edge points at, and (later) how to reach it
  toAsset: {
    platformIds: []string        // the correlation key — reuses today's join
    connection:  Config?         // deferred: how to activate into a runtime
  }

  relation: string               // e.g. "runs", "references"
}
```

Key properties:

- **The join stays platform-ID-based.** The edge still carries the child's platform
  ID, so correlation reuses the existing, MRN-free pipeline. We are adding the
  *anchor* and (later) the *connection handle* that `RelatedAssets` structurally
  cannot hold — not inventing a new correlation primitive.

- **Produced from both directions, from one source of truth.** The reverse
  (discovery) side and the forward (`running` field) side must derive the identical
  `(resourceType, resourceID)` anchor and child platform ID. This derivation MUST be
  a single shared function called by both the resource's `__id` construction and the
  discovery pass. Drift here = silent orphans (a `running` reference that never links
  to the discovered asset). This is the single most important correctness
  invariant.

- **`RelatedAssets` becomes the degenerate edge** — no `fromResource` anchor, no
  connection. Existing producers (docker, k8s, gcp, os) keep working unchanged and
  migrate onto the new edge opportunistically. No big-bang proto break.

### Scope of the first implementation slice

Deliver only:

1. **MCP-server discovery** for the `os` provider (opt-in gated per Follow-Ups).
2. **The anchored relationship**: the reverse-side anchor on discovered MCP-server
   assets, and the forward-side `running` field on the `*.mcpServer` resources
   returning the asset-reference value, both keyed on the shared-function
   `(resourceType, resourceID)` + parent-qualified platform ID.

Explicitly **defer** (design for, do not build):

- **Live cross-asset traversal** (`...running.tools`). This needs the engine to
  activate an edge's `toAsset.connection` into a runtime and route field calls to the
  referenced asset's provider (for MCP capability enumeration, the enterprise `ai`
  provider — capability enumeration lives there, not in a standalone provider). The
  edge is shaped so this is a later *capability on the same object* (populate
  `toAsset.connection` and add engine-side activation), not a redesign.
- **Full `RelatedAssets` migration** of existing providers.

## Alternatives considered

### A. Extend `RelatedAssets` in place

Add a resource anchor to field 33. Rejected as the primary mechanism:

- `RelatedAssets` is `[]*Asset`; adding an anchor means either polluting `Asset` with
  parent-relative context or wrapping the element — a proto change to a shipped field
  consumed by docker/k8s/gcp/os discovery and the platform, i.e. a broad, all-at-once
  blast radius.
- It is undirected, flat, and populated at connect time. It has no path to be
  produced from a query-field result (the forward `running` direction), and no notion
  of activation into a connection. Retrofitting `...running.tools` onto a static
  correlation list is a semantic mismatch.

The chosen approach still reuses the platform-ID *join* that `RelatedAssets` uses, so
we keep the proven part and replace only the structure that can't carry the anchor.

### B. Key the relationship on MRN

Rejected. MRNs are upstream-assigned, absent locally, unknown to the emitting
provider at emit time, and on an independent timeline for referenced assets. See
Context. Platform IDs are local, deterministic, and already the primitive the join
uses.

### C. Encode the anchor only inside the child's platform-ID string

Make the child platform ID the tree address
(`.../host/<hostPlatformID>/claude.code.mcpServer/<id>`) and recover provenance by
parsing it. Viable and cheap (rides `RelatedAssets` as-is), but the anchor is a
string convention rather than structured data, brittle to parse, and still gives no
home for the deferred connection handle. We adopt the parent-qualified platform ID as
the child's **identity**, but carry the anchor as **structured fields** on the edge
rather than relying on parsing.

## Consequences

- One new relationship concept to maintain alongside `RelatedAssets` during a
  migration window; two mechanisms until the migration completes.
- New plumbing on two sides: discovery emits the reverse anchor; query-field
  resolution emits the forward edge. Lifting a *field value* into a stored
  relationship is genuinely new (today relationships are only set at connect time).
- The shared ID-derivation function is a hard dependency for correctness and must be
  covered by tests on both the resource-creation and discovery paths.
- The design keeps `...running.tools` reachable without a later redesign, at the cost
  of specifying (but not building) `toAsset.connection` now.
- Cross-provider references (e.g. host → GitHub repo, where the repo is discovered by
  a different provider that never sees the host) join on the **target's own intrinsic
  platform ID**, not a host-scoped anchor. The edge representation is uniform; the
  key differs by mode (parent-qualified for parented children, target-intrinsic for
  independent assets). The reference-builder must know which mode it is minting.

## Follow-Ups

- **Discovery gating** for `mcp-servers`: off by default and under `auto`, on only
  when explicitly targeted or under `all`. In the `os` provider the default set lives
  in `providers/os/config/config.go` and each resolver block gates on
  `stringx.Contains(targets, "all") || stringx.Contains(targets, DiscoveryMCPServers)`
  (mirrors `providers/os/resources/discovery/docker_engine/resolver.go`). Leave
  `mcp-servers` out of the config default `Discovery` list.
- Define the shared `(resourceType, resourceID)` + parent-qualified platform-ID
  derivation function and unit-test the forward/reverse parity.
- Decide `running` semantics: liveness-gated (null when the server is not actually
  up — requires process/endpoint detection) vs. always-present reference (then the
  field is `asset`/`target`, not `running`).
- Sequence the `RelatedAssets` migration for docker/k8s/gcp/os.
- Specify engine-side edge activation for the deferred `...running.tools` traversal
  (runtime spin-up/reuse for the referenced asset, routing to the enterprise `ai`
  provider).
