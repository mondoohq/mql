# ADR 029: Network detail types for FEX Evidence

## Status

Proposed

## Context

`fex.Evidence` carries the facts behind a finding. Its `details` oneof models
the *kind* of artifact that triggered the finding — `User`, `File`, `Process`,
`Container`, `Kubernetes`, `RegistryKey`, `Connection`, and (recently)
`HttpRequest`. When a scanner's evidence fits one of these, consumers get typed,
renderable detail. When it doesn't, the producer has only two escape hatches:
the untyped `Evidence.properties` string map, or the finding's `Component` /
`FindingDetail`. Neither is a structured `details` variant, so the consuming
side can't render or reason about it as evidence — it is opaque key/value soup.

Network and infrastructure scanners hit this wall constantly. A review of
finding producers that emit FEX/VEX to the platform found whole classes of
findings whose evidence has **no matching `details` type**, so they ship with
either bare/empty evidence or everything crammed into `properties`:

| Finding source | Evidence with no home today |
|----------------|-----------------------------|
| Subdomain enumeration, dangling/misconfigured CNAME, reverse (PTR) lookup | the DNS resolution (name, type, resolved values) |
| Weak-TLS / bad-certificate checks (nmap `ssl-*`, httpx TLS) | the certificate + negotiated protocol/cipher |
| WHOIS/RDAP registration hygiene (imminent expiry, missing transfer lock) | the registration record (registrar, dates, name servers, EPP statuses) |
| ASN / owned-IP-range discovery | the announced BGP prefix / CIDR + origin AS |
| nmap NSE / banner-grab / TCP service probes | the *matched* banner or script string (there is no `Connection` analogue of `HttpRequest.evidence`) |

The last row is a gap in an existing type, not a missing type: `HttpRequest`
has an `evidence` field for the matched string that confirms a web finding, but
`Connection` — used for every non-web probe — has no equivalent, so the matched
banner/service string has nowhere structured to go.

`HttpRequest` (field 27) set the precedent: it was added specifically so DAST
evidence stops living in `properties`. The same argument applies to the
network artifacts above.

Note: this file's field and enum names intentionally mirror the server-internal
etl schema byte-for-byte (see the header comment in `fex.proto`). New `details`
variants are backward-compatible on the wire — an old consumer ignores unknown
oneof fields — but they only become *useful* once the server's etl schema learns
them. Until then a producer may emit them harmlessly; the server drops them.

## Decision

Add one field and four `details` variants to `fex.Evidence`, continuing the
oneof field numbering after `HttpRequest = 27`:

- **`Connection.evidence` (field 6)** — the matched banner or service string that
  confirms a non-web finding (a TCP banner, an nmap NSE hit). The `Connection`
  analogue of `HttpRequest.evidence`. Backward-compatible additive field on an
  existing message.
- **`DnsRecord dns_record = 28`** — a DNS resolution: `name`, `type` (A/AAAA/
  CNAME/MX/TXT/NS/PTR), resolved `values`, optional `ttl`.
- **`Certificate certificate = 29`** — a TLS certificate / handshake: subject,
  issuer, serial, SHA-256 fingerprint, SANs, validity window, and optional
  negotiated `protocol_version` / `cipher_suite`.
- **`DomainRegistration domain_registration = 30`** — WHOIS/RDAP data: domain,
  registrar, created/updated/expires timestamps, name servers, EPP statuses.
- **`NetworkRange network_range = 31`** — an IP block: `cidr`, optional origin
  `asn`, `as_name`, `country`.

These names are proposed; they must be reconciled with the server etl schema's
naming before merge (the byte-for-byte-mirror constraint). Field numbers 28-31
are chosen to follow the existing oneof sequence and are not reused.

## Consequences

- Network findings gain typed, renderable evidence instead of untyped
  `properties`, closing the same gap `HttpRequest` closed for web findings.
- **Server coordination is required.** The additions are wire-safe, but the
  consuming etl schema must add the mirrored fields before the evidence surfaces
  to users. Producers can adopt the new types ahead of that; the
  data is simply ignored until the server catches up. This is why the status is
  **Proposed**, not Accepted — it is gated on server-side alignment.
- Generated Go (`fex.pb.go`, `fex_vtproto.pb.go`) is regenerated via the existing
  `go:generate` directive; no hand-written code changes. `protolint` passes.
- The oneof stays a single-artifact model: each evidence still describes one
  kind of fact. A finding needing several (e.g. a TLS cert *and* the connection)
  uses multiple `Evidence` entries, as web findings already do (HttpRequest +
  Connection).

## Alternatives considered

- **Keep using `Evidence.properties`.** Rejected for the same reason
  `HttpRequest` was added: untyped maps can't be rendered or reasoned about as
  evidence, and that opacity is the concrete complaint driving this change.
- **One generic `NetworkArtifact` message with a `type` discriminator.** Rejected:
  it recreates the untyped-bag problem inside a message and defeats the point of
  a typed oneof; distinct messages give each artifact its real fields.
- **Also add `Breach` (dataset-membership), `PolicyAssessment` (cnspec check
  result), or `Indicator` (IOC bag) variants.** Deferred. Breach/HIBP membership
  and policy verdicts are real evidence with no `details` home either, but they
  are less central to the network-scanning cohort driving this ADR, and a
  policy-result type overlaps with cnspec's own reporting model. An `Indicator`
  type (matched IP/domain/URI/signature IOCs, as Google Cloud SCC models it) is
  threat-hunting centric and overlaps with the specific artifact types above.
  Propose separately if needed.
- **Fold negotiated TLS protocol/cipher into a separate `TlsConnection` type.**
  Rejected as over-modeling: weak-protocol and bad-certificate findings travel
  together in practice, so `Certificate` carries optional negotiated fields
  rather than splitting the handshake across two variants.

## Prior art

Benchmarked against Google Cloud Security Command Center's `Finding`
(`google/cloud/securitycenter/v2/finding.proto`), which uses the same
artifact-typed model: its `Connection`, `Process`, `File`, `Container`, and
`Kubernetes` detail types line up one-for-one with this proto's, and its
`MitreAttack` corresponds to `AttackTactic`/`AttackTechnique`. Notably SCC has no
certificate or domain-registration type, models DNS only as a loose
`Indicator.domains` string list, and models a network as a bare VPC resource name
(no CIDR/ASN) — so the four types added here cover network-scanning artifacts SCC
leaves unstructured. SCC types with no analogue here (`Vulnerability`,
`Compliance`, `Application`, `Indicator`, and the cloud-runtime / CSPM / DLP
families) are either handled elsewhere in this contract (`VulnerabilityExchange`
for CVEs, frameworks for compliance, `HttpRequest` for web URIs) or out of scope
for network findings.
