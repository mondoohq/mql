# Alibaba Cloud Provider

Query an Alibaba Cloud account: compute, networking, storage, managed databases, identity, and the security services.

```bash
cnspec shell alicloud
cnspec scan alicloud --regions cn-hangzhou,ap-southeast-1
```

## Authentication

Credentials are resolved in this order, stopping at the first that works:

1. **CLI flags** — `--access-key-id`, `--access-key-secret`, `--sts-token`
2. **Environment variables** — `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, `ALIBABA_CLOUD_SECURITY_TOKEN` (the legacy `ALICLOUD_ACCESS_KEY` / `ALICLOUD_SECRET_KEY` names are also accepted)
3. **Shared credentials file** — `~/.alibabacloud/credentials`
4. **ECS instance RAM role** — when running on an ECS instance with a role attached

### Access key

```bash
cnspec shell alicloud --access-key-id <id> --access-key-secret <secret>
```

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=<id>
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<secret>
cnspec shell alicloud
```

### Assuming a RAM role

Scanning a member account from a management account, or using a dedicated audit role:

```bash
cnspec scan alicloud \
  --role-arn acs:ram::<uid>:role/<role-name> \
  --access-key-id <id> --access-key-secret <secret>
```

`--role-session-name` sets the session name (default `mondoo`).

### Temporary credentials

```bash
export ALIBABA_CLOUD_SECURITY_TOKEN=<token>
cnspec shell alicloud --access-key-id <id> --access-key-secret <secret>
```

## Permissions

The credential needs read-only access. The `ReadOnlyAccess` system policy covers everything the provider queries. To scope it more tightly, grant the `Describe*`, `List*`, and `Get*` actions for the services you intend to query.

Some services answer only in the region or partition that owns them. WAF, Cloud Firewall, Anti-DDoS, and Security Center are center services reached through `cn-hangzhou` (China) or `ap-southeast-1` (international); CloudSSO through `cn-shanghai` or `us-east-1`. The provider probes both and reports an error only when neither answers, so a partition that legitimately has no such service reads as empty rather than failing the scan.

RAM, ActionTrail, Resource Management, and Cloud Enterprise Network are global and carry no region in their endpoint at all.

## Regions

By default every region enabled on the account is scanned. Narrow it with either flag:

```bash
cnspec scan alicloud --regions cn-hangzhou,ap-southeast-1
cnspec scan alicloud --filters regions=cn-hangzhou --filters exclude:regions=cn-beijing
```

`--region` sets only the region used for account resolution and global services; it does not restrict the scan.

## Discovery

Scanning an account discovers one asset per major service object, each scoped to that object:

| Target | Assets |
|---|---|
| `accounts` | the account itself (always the root asset) |
| `k8s-clusters` | ACK clusters |
| `albs` | Application Load Balancers |
| `nlbs` | Network Load Balancers |
| `vpcs` | VPC networks |
| `oss-buckets` | OSS buckets |
| `rds-instances` | RDS instances |
| `slbs` | Classic Load Balancers |
| `redis-instances` | ApsaraDB for Redis instances |
| `mongodb-instances` | ApsaraDB for MongoDB instances |
| `polardb-clusters` | PolarDB clusters |
| `fc-functions` | Function Compute functions |
| `acr-instances` | Container Registry instances |
| `es-clusters` | Elasticsearch clusters |
| `waf` | Web Application Firewall instances |
| `cloud-firewall` | the account's Cloud Firewall, when provisioned |
| `auto` / `all` | every target above |

```bash
cnspec scan alicloud --discover vpcs,albs
cnspec scan alicloud --discover accounts   # the account only, no child assets
```

## Filters

`--filters` narrows what discovery turns into assets. Filters are applied in the resource listers, so a scan and a plain MQL query see the same set.

| Filter | Effect |
|---|---|
| `regions=<csv>` | scan only these regions |
| `exclude:regions=<csv>` | skip these regions |
| `tag:<key>=<value[,value]>` | keep only objects carrying one of these tag values |
| `exclude:tag:<key>=<value[,value]>` | drop objects carrying one of these tag values |

```bash
cnspec scan alicloud --filters tag:Environment=production
cnspec scan alicloud --filters tag:Team=platform,security --filters exclude:tag:Lifecycle=temporary
```

An exclude filter always wins over an include filter. Tag filters apply to the objects that carry tags — ACK clusters, load balancers (ALB, NLB, and CLB), VPCs, ECS instances, OSS buckets, RDS/Redis/MongoDB instances, PolarDB clusters, and Function Compute functions. WAF and Cloud Firewall are untagged account-level services, so tag filters do not narrow them.

Tag lookups that cost a separate API call (OSS buckets, RDS instances) are only performed when a tag filter is actually set.

## Examples

```coffee
# ECS instances reachable from the internet whose metadata service
# hands out role credentials without requiring a token
alicloud.ecs.instances.where(internetExposed && metadataHttpTokens != "required") {
  instanceName ramRole { roleName }
}

# security groups open to the world
alicloud.ecs.securityGroups {
  securityGroupName
  permissions.where(sourceCidrIp == "0.0.0.0/0") { ipProtocol portRange }
}

# a rule scoped to a prefix list carries no CIDR of its own; the blocks it
# admits live on the list
alicloud.ecs.securityGroups {
  securityGroupName
  permissions { ipProtocol portRange sourcePrefixList { prefixListName cidrBlocks } }
}

# prefix lists that open every rule pointing at them
alicloud.ecs.prefixLists.where(cidrBlocks.contains("0.0.0.0/0")) {
  prefixListName associationCount
}

# what an internet-facing load balancer actually forwards to
alicloud.alb.loadBalancers.where(internetFacing) { loadBalancerName }
alicloud.alb.serverGroups {
  name
  servers { serverType port ecsInstance { instanceName internetExposed } }
}

# the same for a classic load balancer, both directly attached backends and
# those reached through a vServer group
alicloud.slb.loadBalancers.where(internetFacing) {
  loadBalancerName
  backends { serverId ecsInstance { instanceName } }
  vServerGroups { vServerGroupName backends { serverId port } }
}

# backends left in place but taking no traffic
alicloud.nlb.serverGroups { name servers.where(weight == 0) { serverId status } }

# network ACL rules that accept traffic from anywhere, evaluated before
# security groups ever see it
alicloud.vpc.networkAcls {
  networkAclName
  ingressEntries.where(policy == "accept" && sourceCidrIp == "0.0.0.0/0") {
    protocol port description
  }
}

# which route tables send everything out through a gateway
alicloud.vpc.routeTables {
  routeTableName
  routes.where(destinationCidrBlock == "0.0.0.0/0") { nextHopType nextHopId }
}

# OSS buckets without block-public-access
alicloud.oss.buckets.where(blockPublicAccess == false) { name acl policy }

# buckets a browser on any site can read, and buckets with no TLS floor
alicloud.oss.buckets { name corsRules.where(allowedOrigins.contains("*")) { allowedMethods } }
alicloud.oss.buckets.where(tlsEnforced == false) { name }

# objects that can still be deleted or overwritten, and object data leaving
# the bucket
alicloud.oss.buckets.where(objectLockState == "") { name versioning }
alicloud.oss.buckets { name replicationRules { targetBucket targetLocation action } }

# a referer restriction that any client can sidestep by omitting the header
alicloud.oss.buckets.where(refererAllowList != [] && allowEmptyReferer) { name }

# RDS instances allowing connections from anywhere
alicloud.rds.instances.where(securityIPList.contains("0.0.0.0/0")) {
  dbInstanceId engine sslEnabled tdeEnabled
}

# container images anyone can pull, and images whose tags can be
# repointed after they were reviewed
alicloud.acr.instances {
  instanceName
  repositories.where(isPublic) { repoNamespaceName repoName }
  repositories.where(tagImmutability == false) { repoNamespaceName repoName }
}

# registries reachable from the internet with no address list in front,
# and no rule that scans an image as it arrives
alicloud.acr.instances.where(internetEndpointEnabled && internetEndpointAclEnabled == false) {
  instanceName internetEndpointDomains
  scanRules.where(triggerType == "AUTO") { ruleName scanType }
}

# replication rules that copy images into another account
alicloud.acr.instances {
  syncRules.where(crossUser) {
    syncRuleName localNamespaceName targetInstanceId targetRegionId
  }
}

# Elasticsearch clusters on the internet, and what is allowed to reach them
alicloud.es.instances.where(internetExposed) {
  description esVersion protocol
  publicIpWhitelist kibanaPublicNetworkEnabled kibanaIpWhitelist
}

# clusters open to the whole internet, or serving over plain HTTP
alicloud.es.instances.where(publicIpWhitelist.contains("0.0.0.0/0")) { description }
alicloud.es.instances.where(protocol == "HTTP") { description domain diskEncrypted }

# RAM users holding administrator permissions directly
alicloud.ram.users.where(attachedPolicies.any(policyName == "AdministratorAccess")) {
  userName lastLoginDate mfaDevice
}

# who holds which access configuration on which member account
alicloud.cloudsso.directories {
  accessAssignments { principalName accessConfigurationName targetName }
}

# ActionTrail trails that are not logging
alicloud.actiontrail.trails.where(status != "Enable") { name ossBucket { name } }

# machines Security Center lists but is not actually protecting
alicloud.sas.machines.where(clientStatus != "Online") {
  instanceName ecsInstance { internetExposed }
}

# VPC reachability that security groups alone do not explain:
# transit attachments and VPN tunnels
alicloud.cen.instances { name attachments { childInstanceType childInstanceRegionId } }
alicloud.vpc.vpnConnections { name localSubnet remoteSubnet ikeEncryptionAlgorithm }
```

## Development

```bash
make providers/build/alicloud && make providers/install/alicloud
mql shell alicloud
```

Resources are defined in `resources/alicloud.lr`. After editing it, regenerate:

```bash
make providers/mqlr
./mqlr generate providers/alicloud/resources/alicloud.lr --dist providers/alicloud/resources
```

Adding a `mql<Resource>Internal` struct requires running the generator a second time so it is detected and embedded.
