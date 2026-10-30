# IBM Cloud Provider

The `ibm` provider connects to an [IBM Cloud](https://cloud.ibm.com/) account and inventories its
IAM configuration and users, resource groups and instances, VPC infrastructure, Power Virtual Server
workspaces, Cloud Object Storage buckets, Key Protect keys, Activity Tracker Event Routing, IBM
Cloud Databases, IBM Cloud Kubernetes Service and Red Hat OpenShift on IBM Cloud clusters, and Cloud
Internet Services through read-only API calls. Use it to audit account settings such as MFA and
session limits, who holds which roles, network exposure in VPCs, TLS and firewall settings at the
edge, and Power Virtual Server workloads.

## Prerequisites

An IBM Cloud API key. A key whose identity has the Viewer role on IAM Identity, IAM Access Groups,
and the services you query, plus Reader on VPC Infrastructure, Power Virtual Server, Key Protect,
Activity Tracker Event Routing, IBM Cloud Databases, and Internet Services, and Viewer on
Kubernetes Service, is enough. Reading a bucket's firewall and activity tracking settings needs the
Manager role on Cloud Object Storage. Listing every user of the account (`ibm.iamUsers`) needs the
Viewer role on User Management; without it, IBM Cloud may return only the key's own user when the
account lets users see each other. The provider only reads.

## Authentication

Arguments:

- `--api-key` - the API key.
- `--api-key-file` - the JSON file the IBM Cloud console downloads, or that
  `ibmcloud iam api-key-create <name> --file <path>` writes.
- `--regions` - optional, restricts the VPC regions queried (repeatable or comma-separated), and
  the regions whose Kubernetes Service clusters are listed. Defaults to every region.

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
through the resource controller and queried in their own zone. Kubernetes Service clusters, VPC
and classic, are listed once for every region through the global Kubernetes Service API.

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

**API keys and service IDs not used in the last 90 days**

```shell
mql> ibm.iamApiKeys.where(lastAuthentication == null || lastAuthentication < time.now - 90 * time.day) { name iamId lastAuthentication authenticationCount }
mql> ibm.iamServiceIds.where(lastAuthentication == null || lastAuthentication < time.now - 90 * time.day) { name lastAuthentication }
```

`lastAuthentication` and `authenticationCount` of API keys, service IDs, and trusted profiles come
from IBM Cloud's activity data, which the list calls do not return. They are read with one extra
call per identity, and only when a query asks for them. IBM Cloud records activity only while it
has activity data for the identity: a key that never authenticated, or one IBM Cloud has no
activity data for, has a null `lastAuthentication`. Reading activity needs the same Viewer role on
IAM Identity as listing the identities; a refused call is an error on the field.

**Users and the account owner**

```shell
mql> ibm.iamUsers { userId state accountOwner mfa }
```

`mfa` is the user's own MFA setting from the account settings' per-user list, which overrides the
account-wide `ibm.iamAccountSettings.mfa`; it is null when the user has none.

**Does the account owner have API keys?**

```shell
mql> ibm.iamUsers.where(accountOwner) { userId apiKeys { name createdAt } }
```

**Users with policies assigned directly instead of through an access group**

```shell
mql> ibm.iamUsers.where(policies.length > 0) { userId policies { roles resourceAttributes } accessGroups { name } }
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

**Buckets without a customer-managed key or activity tracking**

```shell
mql> ibm.cosBuckets.where(!kmsEnabled || !activityTrackingManagementEvents) { name location kmsKey { name } }
```

**Boot volumes without a customer-managed key**

```shell
mql> ibm.vpcVolumes.where(attachmentTypes.contains("boot") && encryption != "user_managed") { name region instances { name } }
```

`attachmentTypes` lists the type of each of the volume's attachments, `boot` or `data`. An unattached
volume has none; its `attachmentState` is `unattached`.

**Root keys that do not rotate**

```shell
mql> ibm.kmsKeys.where(!standardKey && !rotationEnabled) { name instance { name } registrations { resourceCrn } }
```

**Is every region's audit trail routed somewhere?**

```shell
mql> ibm.atrackerRoutes { name rules { locations targets { name type writeStatus } } }
```

**Databases reachable from any address**

```shell
mql> ibm.databases.where(publicEndpointEnabled && allowlist.length == 0) { name type version region }
```

**Kubernetes workers with an update available**

```shell
mql> ibm.kubernetesClusters { name workers.where(updateAvailable) { id kubeVersion targetKubeVersion } }
```

`updateAvailable` is true when a worker runs a version other than the one IBM Cloud would update it
to, which `ibmcloud ks workers` marks with an asterisk.

**Clusters whose master is reachable through the public service endpoint**

```shell
mql> ibm.kubernetesClusters.where(publicServiceEndpointEnabled) { name region provider publicServiceEndpointUrl }
```

**Clusters without KMS encryption of their secrets, or without the image pull secret**

```shell
mql> ibm.kubernetesClusters.where(!kmsEnabled || !imagePullSecretsEnabled) { name type kmsKey { name } }
```

Monitoring and logging agents are not visible through the Kubernetes Service API: IBM retired the
observability endpoints (`v2/observe`) and the `ibmcloud ob` plug-in, and the agents are now
installed into the cluster. Check them with the `k8s` provider against the cluster itself.

**Cloud Internet Services: TLS and the web application firewall**

```shell
mql> ibm.cisInstances { zones { name minTlsVersion tls13 ssl alwaysUseHttps wafEnabled } }
```

**Cloud Internet Services: DNS records and global load balancers that bypass the edge**

```shell
mql> ibm.cisInstances { zones { dnsRecords.where(proxiable && !proxied) { name type } } }
mql> ibm.cisInstances { zones { globalLoadBalancers.where(!proxied) { name enabled } } }
```

Only proxied DNS records and global load balancers get the edge's TLS settings, web application
firewall, and DDoS protection. A record that is proxiable but not proxied resolves to its origin
directly. Zone settings are read when queried, one call per setting and zone.

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
