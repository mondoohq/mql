# Jenkins Provider

<!-- TODO: one to three sentences describing what this provider inventories and why
     someone would query it (the security posture or assets it exposes). -->
The `jenkins` provider connects to Jenkins and inventories it through
read-only queries.

## Prerequisites

<!-- TODO (optional): required tooling, versions, network access, or account permissions.
     Delete this section if there are none. -->

## Authentication

<!-- TODO: how to authenticate. List the connection flags/arguments, and give one runnable
     example per auth method. Use blockquote tips for how to obtain credentials. Keep it to a
     few lines for a simple token/env-var provider. -->

Arguments:

- `--user` - the user to authenticate as.
- `--ask-pass` - prompt for the password (or `--password`).

```shell
mql shell jenkins --user USER --ask-pass
```

## Usage

Open an interactive shell:

```shell
mql shell jenkins
```

## Discovery

<!-- TODO (optional): only for providers that emit child assets. Describe the asset model and
     the `--discover` targets, with a scan example. Delete this section if the provider emits a
     single asset. -->

## Examples

<!-- TODO: several labeled example queries. Each should have a short prose lead-in, a runnable
     `mql>` query, and its real output. These are what new developers rely on most, so make them
     copy-pasteable and representative of the provider's key resources. -->

**Example query**

Describe what this query returns.

```shell
mql> jenkins.<resource>
```

## Resources

<!-- TODO (optional): a short pointer to the resources this provider exposes. Do NOT hand-list
     every field; the resource reference is generated from the `.lr` schema comments. -->

## Verification

<!-- TODO (optional): one or two quick queries that confirm the connection and permissions work,
     plus what an empty result implies (e.g. missing read permission). -->

## Troubleshooting

<!-- TODO (optional): common errors and their fixes. Delete if not needed. -->
