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

- `org <name>` - an organization. The name or the `https://dev.azure.com/<name>` address works.
- `repo <org>/<project>/<repo>` - a single repository.
- `--token` - a personal access token. Also read from `AZURE_DEVOPS_TOKEN`.
- `--tenant-id`, `--client-id`, `--client-secret` - a Microsoft Entra service principal. Also
  read from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`.

A token always wins over the `AZURE_*` variables, so a tenant that is set in the shell for
another tool does not change how a scan authenticates.

```shell
mql shell azuredevops org my-organization --token PAT
```

> Create a PAT under User settings, Personal access tokens, in the Azure DevOps portal.

```shell
mql shell azuredevops org my-organization \
  --tenant-id TENANT_ID --client-id CLIENT_ID --client-secret CLIENT_SECRET
```

> Add the service principal to the organization under Organization settings, Users, before
> you connect. Without that step Azure DevOps rejects every request.

## Usage

The organization connector produces an asset on the `azuredevops-org` platform and the
repository connector one on the `azuredevops-repo` platform. Policies target repositories
with `asset.platform == "azuredevops-repo"`.

Azure DevOps treats organization names as case-insensitive, so the asset id lower-cases the
organization (`MyOrg` and `myorg` are one asset). Project and repository names keep their case.

Open an interactive shell on an organization:

```shell
mql shell azuredevops org my-organization --token PAT
```

Open a shell on one repository:

```shell
mql shell azuredevops repo my-organization/my-project/my-repo --token PAT
```

## Discovery

An organization scan emits an asset for the organization and one for each repository that
has commits and is not disabled. Disabled and empty repositories are reported and skipped.
A project the credential cannot read is reported and skipped, and does not fail the scan.

| Target          | Emits                                                         |
| --------------- | ------------------------------------------------------------- |
| `auto`          | the organization and its repositories (the default)           |
| `organization`  | the organization asset                                        |
| `repos`         | one asset per repository                                      |
| `terraform`     | a Terraform child for each repository that holds a `.tf` file |
| `k8s-manifests` | a Kubernetes child for each repository that holds YAML files  |
| `all`           | every target above                                            |

```shell
mql scan azuredevops org my-organization --token PAT --discover repos,terraform
```

Narrow the scan with `<project>/<repo>` patterns. The star does not cross the slash.

```shell
mql scan azuredevops org my-organization --token PAT \
  --repos "my-project/*" --repos-exclude "my-project/archive-*"
```

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

`deploymentType` is `hosted` for Azure DevOps Services. An empty
`azuredevops.organization.unreadableProjects` means the credential can read every project.
A name in that list means the credential has no access to that project, and that project's
repositories are not in the inventory.

## Troubleshooting

- `401` or a message about the personal access token: the token expired, was revoked, or
  belongs to another organization. Create a new one.
- Every request fails for a service principal: the principal is not a user of the
  organization yet. Add it under Organization settings, Users.
- A repository is missing from a scan: look at `azuredevops.organization.repositories` for
  its `status`. Only `ready` repositories are scanned.
- `429` or slow scans: Azure DevOps throttles by cost per user. The provider backs off on its
  own. Narrow the scan with `--repos` if it keeps happening.
