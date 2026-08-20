# Notion Provider

The `notion` provider inventories a Notion workspace through read-only API
queries: the workspace members and bots, the databases and pages an
integration has been given access to, and the integration's own identity. Its
primary security signal is exposure, `publicUrl` and `isPubliclyShared` report
which pages and databases have been published to the web and are readable
without a Notion account.

## Prerequisites

- A Notion **internal integration** in the workspace you want to query, with
  these capabilities:
  - **Read content**, for `notion.pages` and `notion.databases`
  - **Read user information including email addresses**, if you want
    `notion.user.email` populated. Without it the field is empty for
    person-type users.
- **Content shared with the integration.** A new integration can see nothing.
  Notion has no "list everything" endpoint, so the provider enumerates through
  the search API, which only returns objects explicitly connected to the
  integration. Share a page or database with it (**⋯** menu, then
  **Connections**) and child content is inherited.

## Authentication

Provide an internal integration token with the `--token` flag or the
`NOTION_TOKEN` environment variable.

> Create a token at <https://www.notion.so/profile/integrations>. Internal
> integration secrets begin with `ntn_` (or `secret_` in older workspaces).

```shell
# via flag
mql shell notion --token ntn_...

# via environment variable
export NOTION_TOKEN=ntn_...
mql shell notion
```

## Usage

Open an interactive shell:

```shell
mql shell notion
```

Or run a single query:

```shell
mql run notion -c "notion.pages.where(isPubliclyShared)"
```

## Discovery

The provider emits a single asset, the connected workspace, as the root asset.
It does not discover child assets, so `--discover` has nothing extra to return.

## Examples

**Confirm the token and see which workspace it reaches**

```shell
mql> notion.bot { id name ownerType workspaceName }
```

**Find content published to the web**

The exposure query this provider exists for. Anything returned here is readable
by anyone with the link, with no Notion account required.

```shell
mql> notion.pages.where(isPubliclyShared) { title publicUrl lastEditedTime }
mql> notion.databases.where(isPubliclyShared) { title publicUrl }
```

**Review who is in the workspace**

```shell
mql> notion.users { name type email }
```

Bots are users too. `botOwnerType` distinguishes a workspace-owned integration
from one scoped to a single user:

```shell
mql> notion.users.where(type == "bot") { name botOwnerType }
```

**Summarize what the integration can see**

```shell
mql> notion.workspace { name userCount databaseCount pageCount }
```

**Find stale or archived content**

```shell
mql> notion.pages.where(archived) { title lastEditedTime }
```

## Resources

The provider exposes `notion`, `notion.bot`, `notion.workspace`, `notion.user`,
`notion.database`, and `notion.page`. Field-level documentation is generated
from the schema comments in `resources/notion.lr`.

All resources are marked `@maturity("experimental")`, their shape may still
change.

## Verification

This query confirms the token is valid and shows which workspace it reaches:

```shell
mql run notion -c "notion.bot { name workspaceName }"
```

If that succeeds but the content queries come back empty:

```shell
mql run notion -c "notion.workspace { userCount databaseCount pageCount }"
```

then the token is fine and nothing has been shared with the integration yet.
An empty `pages`/`databases` list is a permission result, not an error.

## Troubleshooting

**`invalid Notion integration token, verify the token and try again`**

The API rejected the token with a 401. Confirm you copied the internal
integration secret rather than an OAuth client secret, and that the integration
still exists in the workspace.

**`notion.pages` and `notion.databases` are empty**

The integration has no content connected to it. See
[Prerequisites](#prerequisites). This is the most common surprise, the token is
valid and the queries are correct, but search only returns shared objects.

**`notion.user.email` is empty for real people**

The integration lacks the *read user information including email addresses*
capability. Update it in the integration's settings and re-run.

**Admin and governance data is missing**

The base Notion API is scoped to content integrations. SSO, SCIM, and audit-log
data require Notion's Enterprise APIs and are not modeled here. See
`docs/adr/038-notion-provider.md`.
