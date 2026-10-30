# Exoscale Provider

The `exoscale` provider connects to an [Exoscale](https://www.exoscale.com/) organization and
inventories its compute instances, security groups, SKS Kubernetes clusters, network load
balancers, block storage, DBaaS services, KMS keys, IAM roles, API keys, users, and DNS through
read-only API calls. Use it to audit network exposure, encryption, and access control across every
zone of the organization.

## Prerequisites

An Exoscale API key and secret. A key bound to a role with read access to the services you want
to query is enough. The provider only calls `list-*` and `get-*` operations.

## Authentication

Arguments:

- `--api-key` - the API key (starts with `EXO`).
- `--api-secret` - the API secret.
- `--zones` - optional, restricts the zones queried (repeatable or comma-separated). Defaults to
  every zone.

```shell
mql shell exoscale --api-key EXO... --api-secret SECRET
```

The provider also reads the `EXOSCALE_API_KEY` and `EXOSCALE_API_SECRET` environment variables
(the names the Exoscale CLI and Terraform provider use), and the legacy `EXOSCALE_KEY` and
`EXOSCALE_SECRET`. `EXOSCALE_ZONES` sets the zone filter.

> Create an API key in the Exoscale portal under **IAM > API Keys**, or with
> `exo iam api-key create <name> <role>`.

## Usage

Open an interactive shell:

```shell
mql shell exoscale
```

Organization-wide resources (security groups, anti-affinity groups, SSH keys, IAM, DNS) are read
once. Zonal resources (instances, instance pools, templates, snapshots, private networks, elastic
IPs, NLBs, SKS clusters, block storage, DBaaS, KMS) are collected from every zone in parallel, and
each carries its `zone`. A zone that refuses a call (an IAM denial, or a feature not enabled for
the organization) is skipped and the other zones still answer.

## Discovery

The organization is the root asset. Discovery adds child assets for:

| target            | asset                                   |
| ----------------- | --------------------------------------- |
| `instances`       | each compute instance                   |
| `security-groups` | each security group                     |
| `sks-clusters`    | each SKS Kubernetes cluster             |
| `nlbs`            | each network load balancer              |
| `dbaas-services`  | each managed database service           |

`auto` and `all` select every target. A scan discovers them by default:

```shell
cnspec scan exoscale --discover instances,sks-clusters
```

Narrow the resources by label with `--filters`. `labels` keeps resources carrying any of the listed
labels (`key=value`, or a bare `key` for any value); `exclude:labels` drops resources carrying any of
them. The filters apply to queries as well as discovery. Security groups and DBaaS services carry no
labels, so an include filter drops them.

```shell
cnspec scan exoscale --filters labels=env=prod,team --filters exclude:labels=tier=dev
```

## Examples

**Zones the connection queries**

```shell
mql> exoscale.zones { name apiEndpoint }
exoscale.zones: [
  0: {
    name: "ch-gva-2"
    apiEndpoint: "https://api-ch-gva-2.exoscale.com/v2"
  }
  ...
]
```

**Security group rules open to the internet**

```shell
mql> exoscale.securityGroups { name rules.where(direction == "ingress" && network == "0.0.0.0/0") { protocol startPort endPort } }
```

**Instances with secure boot disabled or an unencrypted disk**

```shell
mql> exoscale.instances.where(securebootEnabled != true || diskEncrypted != true) { name zone securebootEnabled diskEncrypted }
```

**SKS clusters whose API server is reachable from anywhere**

```shell
mql> exoscale.sksClusters.where(allowedNetworks.contains("0.0.0.0/0")) { name zone version allowedNetworks }
```

**DBaaS services that accept connections from any address**

```shell
mql> exoscale.dbaasServices.where(ipFilter.contains("0.0.0.0/0")) { name type zone }
```

**KMS keys and their rotation**

```shell
mql> exoscale.kmsKeys { name originZone multiZone rotationEnabled rotationPeriod }
exoscale.kmsKeys: [
  0: {
    name: "Default"
    originZone: "ch-gva-2"
    multiZone: true
    rotationEnabled: true
    rotationPeriod: 365
  }
]
```

**API keys and the role each is bound to**

```shell
mql> exoscale.iamApiKeys { name key role { name } }
```

**Users without two-factor authentication**

```shell
mql> exoscale.iamUsers.where(twoFactorAuthentication != true) { email role { name } }
```

**Roles and their policies**

```shell
mql> exoscale.iamRoles { name editable policy { defaultServiceStrategy services { name type } } }
```

## Verification

```shell
mql run exoscale -c "exoscale.organization { name id }"
```

An empty collection means the organization has no such resources in the queried zones. A refused
call surfaces as an error on the field rather than an empty list.

## Troubleshooting

- `invalid Exoscale API credentials`: Exoscale answers a wrong secret with
  `403 Invalid request signature`. Check the key and secret pair.
- `unknown Exoscale zone`: a `--zones` value does not match a zone name. The error lists the
  available zones.
