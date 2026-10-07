# IBM Cloud Provider

The `ibm` provider connects to an [IBM Cloud](https://cloud.ibm.com/) account and inventories its
IAM configuration, resource groups and instances, VPC infrastructure, and Power Virtual Server
workspaces through read-only API calls. Use it to audit account settings such as MFA and session
limits, who holds which roles, network exposure in VPCs, and Power Virtual Server workloads.

## Prerequisites

An IBM Cloud API key. A key whose identity has the Viewer role on IAM Identity, IAM Access Groups,
and the services you query, plus Reader on VPC Infrastructure and Power Virtual Server, is enough.
The provider only reads.

## Authentication

Arguments:

- `--api-key` - the API key.
- `--api-key-file` - the JSON file the IBM Cloud console downloads, or that
  `ibmcloud iam api-key-create <name> --file <path>` writes.
- `--regions` - optional, restricts the VPC regions queried (repeatable or comma-separated).
  Defaults to every region.

```shell
mql shell ibm --api-key-file apikey.json
```

The provider also reads the `IBMCLOUD_API_KEY` environment variable (and the Terraform provider's
`IC_API_KEY`), and `IBMCLOUD_REGIONS` for the region filter.

> Create an API key in the IBM Cloud console under **Manage**, **Access (IAM)**, **API keys**.

## Usage

Open an interactive shell:

```shell
mql shell ibm --api-key-file apikey.json
```

Account-wide resources (IAM, resource groups, resource instances) are read once. VPC resources are
collected from every VPC region in parallel, and each carries its `region`. A region that refuses a
call is skipped and the other regions still answer. Power Virtual Server workspaces are found
through the resource controller and queried in their own zone.

## Discovery

The account is the root asset. Discovery adds child assets for:

| target                | asset                                  |
| --------------------- | -------------------------------------- |
| `vpc-instances`       | each VPC virtual server instance       |
| `vpc-security-groups` | each VPC security group                |
| `power-workspaces`    | each Power Virtual Server workspace    |

`auto` and `all` select every target. A scan discovers them by default:

```shell
cnspec scan ibm --api-key-file apikey.json --discover power-workspaces
```

Narrow the discovered instances, security groups, and workspaces by tag with `--filters`. A
`key:value` selector matches that tag, a bare `key` matches the plain tag and any value of it, and
both user and access management tags count. The same filter narrows `ibm.vpcInstances`,
`ibm.vpcSecurityGroups`, and `ibm.powerWorkspaces` in queries.

```shell
cnspec scan ibm --api-key-file apikey.json --filters tags=env:prod --filters exclude:tags=team:sandbox
```

## Examples

**Account IAM settings**

```shell
mql> ibm.iamAccountSettings { mfa restrictCreateServiceId sessionExpirationInSeconds publicAccessEnabled }
ibm.iamAccountSettings: {
  mfa: "NONE_NO_ROPC"
  restrictCreateServiceId: null
  sessionExpirationInSeconds: null
  publicAccessEnabled: true
}
```

A setting the account leaves at IBM Cloud's default (`NOT_SET`) reads as null.

**Policies that grant Administrator on the whole account**

```shell
mql> ibm.iamPolicies.where(roles.contains("Administrator")) { subjectAttributes resourceAttributes }
```

**API keys that never expire**

```shell
mql> ibm.iamApiKeys.where(expiresAt == null) { name iamId createdAt lastAuthentication }
```

**Security group rules open to the internet**

```shell
mql> ibm.vpcSecurityGroups { name rules.where(direction == "inbound" && remoteCidr == "0.0.0.0/0") { protocol portMin portMax } }
```

**Instances without secure boot or with an HTTP metadata service**

```shell
mql> ibm.vpcInstances.where(enableSecureBoot != true || metadataServiceProtocol != "https") { name region }
```

**Instances reachable from the internet**

```shell
mql> ibm.vpcInstances.where(exposure.internetReachable) { name floatingIps { address } exposure { openIngressRules { protocol portMin portMax } } }
```

`exposure` combines the floating IPs bound to the instance's network interfaces with the inbound
rules of their security groups that admit any address. Network ACLs are not taken into account.

**Resources without an owner tag**

```shell
mql> ibm.vpcs.where(tags.none(_ == /^owner:/)) { name region tags }
```

Tags are read once per scan through Global Search, for resource groups, resource instances, VPC
resources, and Power Virtual Server resources.

**Power Virtual Server workspaces and their images**

```shell
mql> ibm.powerWorkspaces { name zone images { name operatingSystem state } }
ibm.powerWorkspaces: [
  0: {
    name: "cep-testbeds-wdc06"
    zone: "wdc06"
    images: [
      0: { name: "7100-05-09" operatingSystem: "aix" state: "active" }
      ...
    ]
  }
]
```

## Verification

```shell
mql run ibm --api-key-file apikey.json -c "ibm { accountId vpcRegions.length }"
```

An empty collection means the account has no such resources in the queried regions. A refused call
surfaces as an error on the field rather than an empty list.

## Troubleshooting

- `invalid IBM Cloud API key`: the key was not accepted by IAM. Check it, and that it has not been
  disabled after being detected as leaked.
- `unknown IBM Cloud VPC region`: a `--regions` value does not match a region. The error lists the
  available regions.
