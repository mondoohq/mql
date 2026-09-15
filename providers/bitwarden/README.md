# Bitwarden Provider

The `bitwarden` provider connects to a Bitwarden Teams or Enterprise
organization through its Public API and inventories organization governance:
security policies, members, collections, and groups. It authenticates as an
organization, not a user, and never reads vault item secrets, folders, or
Send content, since the Public API has no endpoints for them.

**Client note:** Bitwarden's official Public API OpenAPI v3 spec is vendored
at `connection/openapi/swagger.json`, and a spec-tracked Go type layer is
generated from it into the `connection/bwapi` package (models only, no HTTP
client) with `oapi-codegen`. Regenerate from the provider directory with:

```shell
go generate ./connection/bwapi/...
```

`go generate` is the only supported invocation. The generator config sets
`output: models.gen.go`, a path oapi-codegen resolves against its working
directory, so running the tool by hand from elsewhere writes the file to the
wrong place. `go generate` always runs it with the working directory set to
`connection/bwapi`.

The provider keeps its own OAuth2 client-credentials transport and a
minimal, hand-written `net/http` client (`connection/client.go`) for the read
endpoints it needs. The request/response structs in `client.go` are **not**
the generated `bwapi` models, because the published spec is lossy for read
modeling. Concretely, against what this provider actually reads, the spec:

- omits `hidePasswords` and `manage` on the permission-grant model
  (`AssociationWithPermissionsResponseModel`), which the provider exposes on
  `collectionAccess` / `groupAccess` / `memberAccess`;
- omits `resetPasswordEnrolled` on the member model;
- omits `name` on the collection model;
- types policy `data` as a nested `map[string]map[string]interface{}`, which
  cannot decode the flat `data` objects the API returns;
- models `type`/`status` as incomplete plain integers (e.g. `PolicyType`
  enumerates 3 of ~23 values) and cannot represent the string wire form the
  provider's `flexEnum` tolerates;
- types every id as a UUID, rejecting non-UUID ids and turning a null
  `userId` (invited members) into a fabricated zero UUID.

Decoding into the generated models would therefore silently drop
security-relevant coverage. The `bwapi` package is instead used as a
spec-tracked reference and drift tripwire: `TestOpenAPISpecGaps` (in
`connection/client_test.go`) fails if a future re-vendor of the spec closes
one of these gaps, signaling that the corresponding hand-written struct can
then adopt the generated type.

## Prerequisites

The Public API is available to Bitwarden Teams and Enterprise organizations
(not Free/Families). You need an organization API key (`client_id` /
`client_secret`), obtained from the organization's Settings > Organization
info page in the Bitwarden web vault.

## Authentication

Authentication uses OAuth2 client-credentials: an organization `client_id`
(of the form `organization.<uuid>`) and `client_secret` are exchanged at
Bitwarden's identity endpoint for a bearer token.

Arguments:

- `--client-id` - the organization client ID (e.g. `organization.<uuid>`).
- `--client-secret` - the organization client secret.
- `--api-url` - optional, overrides the Public API base URL (self-hosted deployments).
- `--identity-url` - optional, overrides the identity token URL (self-hosted deployments).

```shell
mql shell bitwarden --client-id organization.00000000-0000-0000-0000-000000000000 --client-secret <secret>
```

> You can also set `BITWARDEN_CLIENT_ID` and `BITWARDEN_CLIENT_SECRET`
> (and, for self-hosted deployments, `BITWARDEN_API_URL` /
> `BITWARDEN_IDENTITY_URL`) as environment variables instead of flags.

## Usage

Open an interactive shell:

```shell
mql shell bitwarden
```

## Discovery

This provider models a single asset per connection: the Bitwarden
organization itself. There are no child assets to discover.

## Examples

**Organization-wide security policies**

```shell
mql> bitwarden.policies { policyType enabled data }
```

**Members without two-factor authentication**

```shell
mql> bitwarden.members.where( status == "confirmed" ).where( ! twoFactorEnabled ) { email role }
```

**Groups and the collections they can reach**

```shell
mql> bitwarden.groups { name collections { name } }
```

## Resources

See the `.lr` schema comments in `resources/bitwarden.lr` for the full
resource reference: `bitwarden`, `bitwarden.organization`,
`bitwarden.policy`, `bitwarden.member`, `bitwarden.collection`, and
`bitwarden.group`.

## Verification

```shell
mql> bitwarden.organization
mql> bitwarden.policies.length
```

An empty `policies` list on an organization known to have policies
configured usually means the API key lacks the `api.organization` scope, or
the organization's plan doesn't include policy enforcement.

## Troubleshooting

- **`a Bitwarden organization client ID and client secret are required`**:
  set `--client-id`/`--client-secret` or the `BITWARDEN_CLIENT_ID` /
  `BITWARDEN_CLIENT_SECRET` environment variables.
- **`failed to verify Bitwarden credentials`**: the client ID/secret pair
  was rejected during token exchange, or the organization's plan doesn't
  include Public API access (Teams/Enterprise only).
- **Self-hosted deployments**: set `--api-url`/`--identity-url` (or
  `BITWARDEN_API_URL`/`BITWARDEN_IDENTITY_URL`) to your instance's
  endpoints.
