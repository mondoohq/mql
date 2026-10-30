# Cloudflare Provider

The `cloudflare` provider connects to the Cloudflare API and inventories an
account and its zones through read-only queries. It exposes the edge security
posture that matters for auditing: WAF and ruleset enforcement, rate limits,
bot management, DNS and DNSSEC, TLS certificates, Zero Trust (Cloudflare One)
access policies, Gateway rules and device posture, Workers and Pages, R2 and
logpush configuration, plus account governance such as members, roles, audit
logs, and API tokens.

## Prerequisites

A Cloudflare account and an API token with read access to the resources you
want to query. No write permissions are needed; the provider never mutates
anything.

Some surfaces must be enabled on the account before they return data (R2,
Cloudflare Access, Log Explorer). Querying them on an account where the
product is not enabled returns an error from the API rather than an empty
list.

## Authentication

Authentication uses a Cloudflare API token, sent as a bearer token.

Arguments:

- `--token` - the Cloudflare API token.

```shell
mql shell cloudflare --token <token>
```

> You can also set `CLOUDFLARE_TOKEN` as an environment variable instead of
> passing `--token`, which keeps the credential out of your shell history.

> Create a token under **My Profile > API Tokens > Create Token** in the
> Cloudflare dashboard. Read-only scopes are sufficient. Which scopes you
> need depends on what you query: *Zone > Zone > Read* for zones and DNS,
> *Zone > Firewall Services > Read* for WAF and rulesets, *Account >
> Cloudflare One > Read* for Zero Trust and Gateway, *Account > Workers
> Routes > Read* for Workers, *Account > R2 > Read* for R2 buckets, and
> *Account > Logs > Read* for Log Explorer datasets.

## Usage

Open an interactive shell:

```shell
mql shell cloudflare
```

## Discovery

The provider discovers child assets from the credential. The `--discover`
targets are:

- `auto` (default) - the account and its zones.
- `all` - everything the token can reach.
- `accounts` - accounts only.
- `zones` - zones only.

```shell
mql scan cloudflare --discover zones
```

## Examples

**Accounts reachable by this token**

```shell
mql> cloudflare.accounts { id name }
```

**Zones and their activation status**

```shell
mql> cloudflare.zones { name status paused }
```

**Zones without DNSSEC enabled**

```shell
mql> cloudflare.zones.where( dnssec.status != "active" ) { name dnssec { status } }
```

**DNS records by zone**

```shell
mql> cloudflare.zones { name dns { records { name type } } }
```

**WAF and ruleset enforcement per zone**

```shell
mql> cloudflare.zones { name rulesets { name phase } }
```

**Account members and the roles they hold**

```shell
mql> cloudflare.accounts { members { email } roles { name } }
```

**API tokens defined on the account, and whether they are still active**

```shell
mql> cloudflare.apiTokens { id name status }
```

**Zero Trust Gateway configuration**

```shell
mql> cloudflare.one.gatewayConfiguration
```

## Resources

See the `.lr` schema comments in `resources/cloudflare.lr` for the full
resource reference. The tree is rooted at `cloudflare`, with `cloudflare.zone`
and `cloudflare.account` as the two main branches, and `cloudflare.one.*`
covering Zero Trust (access apps and policies, Gateway rules, device posture,
DLP profiles, service tokens, IdPs).

## Verification

```shell
mql> cloudflare.accounts { id name }
mql> cloudflare.zones.length
```

An empty `zones` list means the token cannot see any zone, either because the
account genuinely has none or because the token lacks *Zone > Zone > Read*.
An empty result on a product-specific resource (R2, Access, Log Explorer)
usually means the product is not enabled on the account rather than that the
token is wrong.

## Development

Build and install the provider, then query with your installed `mql` binary:

```shell
make providers/build/cloudflare && make providers/install/cloudflare
mql shell cloudflare
```

> **Newly added fields will not resolve until the provider version catches
> up.** A field whose `resources/cloudflare.lr.versions` entry is above the
> `Version` in `config/config.go` reports `cannot find field '<x>'` at
> runtime, which looks identical to a broken field. This is expected: new
> entries are written as `version + 1` and `config.go` is bumped by the
> release flow when the provider is promoted, not by the feature PR. To
> verify such fields locally, temporarily raise `Version` in
> `config/config.go` to match, rebuild, and **revert the change before
> committing** — a feature PR must never carry a version bump.

Run the unit tests:

```shell
go test ./... # from providers/cloudflare/
```

The provider has table tests covering the pure Go decode and predicate logic
(`resources/waf_test.go`, `firewall_test.go`, `dnssec_test.go`,
`workers_test.go`, `rate_limits_test.go`, `content_scanning_test.go`,
`turnstile_test.go`, and others). New parsing or derived-field logic should
get a test there rather than relying on interactive checks alone.

## Troubleshooting

- **`Invalid API Token` from `/user/tokens/verify`, but the provider works**:
  that endpoint is user-scoped, so an *account-owned* token fails it by
  design. Test an account token against `/accounts` or `/zones` instead.
- **`cannot find field '<x>'`**: see the version note under
  [Development](#development) before assuming the field is broken.
- **`Please enable R2 through the Cloudflare Dashboard`** or
  **`Access is not enabled`**: the product is not enabled on the account.
  Enable it in the dashboard, or skip those resources.
- **Empty results everywhere**: confirm the token's scopes cover the account
  and zones you expect; a token restricted to one zone returns nothing for
  the others.
