# Fastly Provider

The `fastly` provider connects to a Fastly account through the [Fastly API](https://www.fastly.com/documentation/reference/api/) and inventories it with read-only calls. It exposes the account's services with the domains they answer on and the backends they forward to, the origin health checks, the managed TLS subscriptions, the TLS certificates served for the account's domains with their validity windows, the TLS activations that enable TLS on each domain, and the account's users, so you can audit a Fastly account for the hostnames it serves, the origins behind them, backends reached without TLS or without certificate verification, and certificates that are expiring.

## Prerequisites

A Fastly API token. A read-only token with global scope can read every resource this provider exposes.

## Authentication

Arguments:

- `--api-token` - a Fastly API token.
- `--base-url` - the base URL of the Fastly API, only for a private API instance (default `https://api.fastly.com`).

> Create a token in the Fastly web interface under **Account > Personal API tokens**, or **Account > API tokens** for an automation token. Scope it to **Global** with **read-only** access.

```shell
mql shell fastly --api-token API_TOKEN
```

The `FASTLY_API_KEY` environment variable can replace the flag, and `FASTLY_API_URL` can set the base URL:

```shell
export FASTLY_API_KEY=API_TOKEN
mql shell fastly
```

## Usage

```shell
mql shell fastly --api-token API_TOKEN
cnspec scan fastly --api-token API_TOKEN
```

Each account is one asset, identified by its customer ID.

## Examples

**Every hostname the account serves**

The domains of a service are the public entry points for traffic to it. They are read from the service's active configuration version.

```shell
mql> fastly.services { name domains { name } }
```

**Backends reached without TLS**

`useSSL` is false when Fastly connects to the origin over plain HTTP.

```shell
mql> fastly.services { name backends.where(useSSL == false) { name address port } }
```

**Backends that skip certificate verification**

```shell
mql> fastly.services { name backends.where(useSSL == true && sslCheckCert == false) { name address } }
```

**TLS certificates expiring in the next 30 days**

```shell
mql> fastly.tlsCertificates.where(notAfter < time.now + 30*time.day) { name issuedTo notAfter domains }
```

**Domains with TLS enabled and the certificate serving them**

```shell
mql> fastly.tlsActivations { domain certificate { issuedTo issuer notAfter } }
```

**Managed TLS subscriptions that are not yet issued**

```shell
mql> fastly.tlsSubscriptions.where(state != "issued") { commonName state certificateAuthority }
```

**Users without two-factor authentication**

```shell
mql> fastly.users.where(twoFactorAuthEnabled == false) { login role }
```

## Resources

The provider exposes the `fastly` account root with `services`, `tlsSubscriptions`, `tlsCertificates`, `tlsActivations`, and `users`. Each `fastly.service` carries its `domains`, `backends`, and `healthChecks`. A `fastly.service.backend` links to the `fastly.service.healthCheck` that gates its traffic, and a `fastly.tls.activation` links to the `fastly.tls.certificate` it serves. See the generated resource reference for every field.

## Verification

```shell
mql> fastly.services.length
```

A connection error means the token is invalid or lacks read access. An empty result for a resource means the account holds none of that kind, not a permission problem; Fastly read tokens either see a resource type or fail the call.

## Troubleshooting

- **`a Fastly API token is required`** - pass `--api-token` or set `FASTLY_API_KEY`.
- **`failed to authenticate with Fastly`** - the token is invalid, expired, or revoked. Create a new token in the Fastly web interface.
