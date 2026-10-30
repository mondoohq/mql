# Azure DevOps Provider

The `azuredevops` provider connects to an Azure DevOps Services organization
(`dev.azure.com`) and inventories its projects and Git repositories through
read-only REST queries. Use it to see which repositories exist, which ones can
be scanned, and to scan the Terraform and Kubernetes manifests they hold.

Azure DevOps Server (on-premises) is not supported.

## Prerequisites

- An Azure DevOps Services organization that the credential can read.
- A personal access token (PAT) with the `Code (Read)` and `Project and Team
  (Read)` scopes, or a Microsoft Entra service principal that was added to the
  organization.

## Authentication

Arguments:

- `org <name>` - an organization. The name works, and so does its `dev.azure.com/<name>` or
  `<name>.visualstudio.com` address, with or without `https://`.
- `repo <org>/<project>/<repo>` - a single repository.
- `--token` - a personal access token. Also read from `AZURE_DEVOPS_TOKEN`.
- `--tenant-id`, `--client-id`, `--client-secret` - a Microsoft Entra service principal. Also
  read from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`.

The provider picks the credential in this order:

1. A `--tenant-id` or `--client-id` flag selects the service principal, even when a token is
   also set. The provider logs a warning in that case.
2. Otherwise a token, from `--token` or `AZURE_DEVOPS_TOKEN`.
3. Otherwise a service principal from `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`, which are both
   required, and `AZURE_CLIENT_SECRET`.

A tenant that is set in the shell for another tool therefore does not override a token.

```shell
mql shell azuredevops org my-organization --token PAT --discover organization
```

> Create a PAT under User settings, Personal access tokens, in the Azure DevOps portal.

```shell
mql shell azuredevops org my-organization --discover organization \
  --tenant-id TENANT_ID --client-id CLIENT_ID --client-secret CLIENT_SECRET
```

> Add the service principal to the organization under Organization settings, Users, before
> you connect. Without that step Azure DevOps rejects every request.

## Usage

The organization connector produces an asset on the `azuredevops-org` platform and the
repository connector one on the `azuredevops-repo` platform. Policies target repositories
with `asset.platform == "azuredevops-repo"`.

Azure DevOps treats organization, project and repository names as case-insensitive, so the
asset id lower-cases all three (`MyOrg/App` and `myorg/app` are one asset). Asset names keep
the case Azure DevOps reports.

Open an interactive shell on an organization. The default `auto` target also emits every
repository, and `mql shell` connects to one asset, so ask for the organization alone:

```shell
mql shell azuredevops org my-organization --token PAT --discover organization
```

Open a shell on one repository:

```shell
mql shell azuredevops repo my-organization/my-project/my-repo --token PAT
```

Run a single query without a shell:

```shell
mql run azuredevops org my-organization --token PAT -c "azuredevops.organization.projects { name }"
```

## Discovery

Discovery on an organization emits an asset for the organization and one for each repository
that has commits and is not disabled. Disabled and empty repositories are reported and
skipped, and only `ready` repositories become assets. A project the credential cannot read is
reported and skipped. Discovery fails when the credential can read the repositories of no
project, which is what a token without the `Code (Read)` scope produces. It also fails when
the credential sees no project at all: Azure DevOps lists only the projects a credential may
read, so a service principal that is a member of the organization but of none of its projects
sees an empty organization. A repository filter (below) leaves the organization asset out.

A `repo` connection emits the repository you named, even when it is empty or disabled, but
gives such a repository no Terraform or Kubernetes child.

| Target          | Emits                                                         |
| --------------- | ------------------------------------------------------------- |
| `auto`          | the organization and its repositories (the default)           |
| `organization`  | the organization asset                                        |
| `repos`         | one asset per repository                                      |
| `terraform`     | a Terraform child for each repository that holds a `.tf` file |
| `k8s-manifests` | a Kubernetes child for each repository that holds YAML files  |
| `all`           | every target above                                            |

Terraform and Kubernetes detection reads the file tree of each repository. One `.tf` file, or
one `.yaml` or `.yml` file, is enough. The check goes by file name, so a Kubernetes child can
turn out to hold no manifest. Files under a hidden path (a segment that starts with a dot, such
as `.github` or `.azure`) are ignored, and so are `mql.yaml` and `mql.yml`.

`mql discover` prints how many assets of each platform a connection finds:

```shell
mql discover azuredevops org my-organization --token PAT --discover repos,terraform
```

Narrow discovery with `--repos` and `--repos-exclude`. Each takes a comma-separated list of
`<project>/<repo>` patterns, matched case-insensitively. An include list keeps what matches,
and the exclude list then removes what it matches. The star does not cross the slash, so
`my-project/*` is every repository of one project and `*/ado-*` is the repositories with that
prefix in any project. `**` does cross the slash. A pattern with no slash, such as `ado-*`,
matches nothing, and the provider logs a warning when an include list matches no repository.

```shell
mql discover azuredevops org my-organization --token PAT \
  --repos "my-project/*" --repos-exclude "my-project/archive-*"
```

Setting `--repos` or `--repos-exclude` also drops the organization asset, whatever the
discovery target is. A filter means you want those repositories, not the organization.

## Examples

**List the projects of an organization**

```shell
mql> azuredevops.organization.projects { name visibility state }
```

**List the repositories that can be scanned**

```shell
mql> azuredevops.organization.repositories.where(status == "ready") { fullName defaultBranch }
```

**Find the repositories that are skipped, and why**

```shell
mql> azuredevops.organization.repositories.where(status != "ready") { fullName status }
```

`status` is `ready`, `empty` (no commits yet) or `disabled`.

## Resources

- `azuredevops.organization` - the organization, its `projects` and its `repositories`.
- `azuredevops.project` - a project and its `repositories`.
- `azuredevops.repository` - a Git repository, with its clone addresses and scan `status`.

The resource reference is generated from the `.lr` schema comments.

## Verification

Run this to confirm that the connection and the permissions work:

```shell
mql> azuredevops.organization { name id deploymentType }
```

`deploymentType` is `hosted` for Azure DevOps Services. A name in
`azuredevops.organization.unreadableProjects` is a project the credential can see but whose
repositories it cannot list; those repositories are not in the inventory. An empty list does
not prove the credential reads every project: Azure DevOps leaves a project the credential has
no access to out of `projects` entirely, so it appears in neither list. Compare `projects`
with the projects you expect. The connection query above does not read repositories. When the
credential sees no project, or can read the repositories of none, a query on `projects`,
`repositories` or `unreadableProjects` fails with an error instead of returning a list.

## Troubleshooting

- `401` or a message about the personal access token: the token expired, was revoked, or
  belongs to another organization. Create a new one.
- Every request fails for a service principal: the principal is not a user of the
  organization yet. Add it under Organization settings, Users.
- An error that says the credential cannot read the repositories of any of the organization's
  projects: the token lacks the `Code (Read)` scope, or the service principal is not a member
  of the projects. Fix the scope or the membership.
- A repository is missing from a scan: a `--repos` or `--repos-exclude` filter may leave it
  out, its project may be listed in `azuredevops.organization.unreadableProjects`, or it may
  not be `ready`. Look at `azuredevops.organization.repositories` for its `status`. An
  organization scan only picks up `ready` repositories. A `repo` connection still emits an
  empty or disabled repository, without Terraform or Kubernetes children.
- A repository has no Terraform or Kubernetes child: the default `auto` target does not emit
  them, so pass `--discover terraform`, `k8s-manifests` or `all`. Past that, the file tree must
  hold a `.tf`, `.yaml` or `.yml` file outside a hidden path such as `.github`, and `mql.yaml`
  and `mql.yml` do not count.
- `429` or slow scans: Azure DevOps throttles by cost per user. The provider backs off on its
  own. Narrow the scan with `--repos` if it keeps happening.
