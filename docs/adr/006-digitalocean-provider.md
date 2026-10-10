# ADR-003: DigitalOcean Provider Implementation

**Status:** Proposed
**Date:** 2026-04-16
**Author:** (Engineering Team)

---

## Context

DigitalOcean is a cloud infrastructure provider with a well-documented REST API and a mature Go SDK (`digitalocean/godo`). It has a familiar cloud resource model (droplets, firewalls, databases, load balancers, Kubernetes) but a much smaller surface area than AWS/GCP/Azure, making it a good candidate for validating new provider scaffolding. Authentication is a single API token with no complex OAuth/IAM flows.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `digitalocean` |
| **Provider ID** | `go.mondoo.com/mql/providers/digitalocean` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `digitalocean` |
| **Go SDK** | `github.com/digitalocean/godo` |
| **API Type** | REST (DigitalOcean API v2) |
| **Auth** | Personal Access Token (`DIGITALOCEAN_TOKEN` env var or `--token` flag) |

---

## Directory Structure

```
providers/digitalocean/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── config/
│   └── config.go
├── connection/
│   └── connection.go
├── provider/
│   └── provider.go
└── resources/
    ├── digitalocean.lr
    ├── digitalocean.lr.go              # generated
    ├── digitalocean.lr.versions        # generated
    ├── discovery.go
    ├── digitalocean.go                 # root resource + account
    ├── droplet.go
    ├── firewall.go
    ├── database.go
    ├── domain.go
    ├── space.go
    ├── volume.go
    ├── loadbalancer.go
    ├── vpc.go
    ├── kubernetes.go
    ├── project.go
    ├── sshkey.go
    └── certificate.go
```

---

## Resource Schema (`digitalocean.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/digitalocean"
option go_package = "go.mondoo.com/mql/providers/digitalocean/resources"

// DigitalOcean cloud provider
digitalocean {
  // Account information
  account() digitalocean.account
  // Droplets (virtual machines)
  droplets() []digitalocean.droplet
  // Firewalls
  firewalls() []digitalocean.firewall
  // Managed databases
  databases() []digitalocean.database
  // Domains
  domains() []digitalocean.domain
  // Spaces buckets (S3-compatible object storage)
  spaces() []digitalocean.space
  // Block storage volumes
  volumes() []digitalocean.volume
  // Load balancers
  loadBalancers() []digitalocean.loadBalancer
  // VPCs
  vpcs() []digitalocean.vpc
  // Kubernetes clusters
  kubernetesClusters() []digitalocean.kubernetes.cluster
  // Projects
  projects() []digitalocean.project
  // SSH keys
  sshKeys() []digitalocean.sshKey
  // TLS certificates
  certificates() []digitalocean.certificate
}

// DigitalOcean account information
digitalocean.account @defaults("email") {
  // Account email
  email string
  // Account UUID
  uuid string
  // Droplet limit
  dropletLimit int
  // Floating IP limit
  floatingIpLimit int
  // Volume limit
  volumeLimit int
  // Email verified
  emailVerified bool
  // Account status
  status string
  // Status message
  statusMessage string
  // Team information
  team dict
}

// DigitalOcean Droplet (virtual machine)
digitalocean.droplet @defaults("id name status") {
  // Droplet ID
  id int
  // Droplet name
  name string
  // Memory in MB
  memory int
  // Number of vCPUs
  vcpus int
  // Disk size in GB
  disk int
  // Region slug
  region string
  // Droplet image
  image() digitalocean.image
  // Size slug
  size string
  // Status (new, active, off, archive)
  status string
  // Created at
  createdAt time
  // Public IPv4 address
  publicIpv4 string
  // Private IPv4 address
  privateIpv4 string
  // Tags
  tags []string
  // VPC UUID
  vpcUuid string
  // VPC
  vpc() digitalocean.vpc
  // Volume IDs
  volumeIds []string
  // Volumes
  volumes() []digitalocean.volume
  // Features (e.g., monitoring, backups)
  features []string
  // Backup enabled
  backupsEnabled bool
  // Monitoring enabled
  monitoringEnabled bool
}

// DigitalOcean image
private digitalocean.image @defaults("id name") {
  // Image ID
  id int
  // Image name
  name string
  // Distribution
  distribution string
  // Image slug
  slug string
  // Whether the image is public
  public bool
  // Minimum disk size in GB
  minDiskSize int
  // Image type (snapshot, backup, custom)
  type string
  // Status
  status string
  // Description
  description string
  // Created at
  createdAt time
}

// DigitalOcean firewall
digitalocean.firewall @defaults("id name status") {
  // Firewall ID
  id string
  // Firewall name
  name string
  // Status (waiting, succeeded, failed)
  status string
  // Created at
  createdAt time
  // Inbound rules
  inboundRules() []digitalocean.firewall.inboundRule
  // Outbound rules
  outboundRules() []digitalocean.firewall.outboundRule
  // Droplet IDs protected by this firewall
  dropletIds []int
  // Tags used to target droplets
  tags []string
}

// DigitalOcean firewall inbound rule
private digitalocean.firewall.inboundRule @defaults("protocol ports") {
  // Firewall ID (parent)
  firewallId string
  // Protocol (tcp, udp, icmp)
  protocol string
  // Port range (e.g., "22", "80-443", "0" for all)
  ports string
  // Allowed source addresses (CIDR)
  sourceAddresses []string
  // Allowed source droplet IDs
  sourceDropletIds []int
  // Allowed source load balancer UIDs
  sourceLoadBalancerUids []string
  // Allowed source Kubernetes IDs
  sourceKubernetesIds []string
  // Allowed source tags
  sourceTags []string
}

// DigitalOcean firewall outbound rule
private digitalocean.firewall.outboundRule @defaults("protocol ports") {
  // Protocol (tcp, udp, icmp)
  protocol string
  // Port range
  ports string
  // Allowed destination addresses (CIDR)
  destinationAddresses []string
  // Allowed destination droplet IDs
  destinationDropletIds []int
  // Allowed destination load balancer UIDs
  destinationLoadBalancerUids []string
  // Allowed destination Kubernetes IDs
  destinationKubernetesIds []string
  // Allowed destination tags
  destinationTags []string
}

// DigitalOcean managed database cluster
digitalocean.database @defaults("id name engine") {
  // Database cluster ID
  id string
  // Database cluster name
  name string
  // Database engine (pg, mysql, redis, mongodb, kafka, opensearch)
  engine string
  // Database engine version
  version string
  // Number of nodes
  numNodes int
  // Size slug
  size string
  // Region slug
  region string
  // Status (creating, online, resizing, migrating, forking)
  status string
  // Created at
  createdAt time
  // Private network UUID
  privateNetworkUuid string
  // Connection URI
  uri string
  // Tags
  tags []string
  // Firewall rules
  firewallRules() []digitalocean.database.firewallRule
  // Maintenance window
  maintenanceWindow dict
  // Whether automatic backups are enabled
  backupsEnabled bool
  // Users
  users() []digitalocean.database.user
}

// DigitalOcean database firewall rule
private digitalocean.database.firewallRule @defaults("type value") {
  // Database ID (parent)
  databaseId string
  // Rule UUID
  uuid string
  // Source type (droplet, k8s, ip_addr, tag, app)
  type string
  // Source value
  value string
  // Created at
  createdAt time
}

// DigitalOcean database user
private digitalocean.database.user @defaults("name role") {
  // Database ID (parent)
  databaseId string
  // Username
  name string
  // Role (primary, normal)
  role string
}

// DigitalOcean domain
digitalocean.domain @defaults("name") {
  // Domain name
  name string
  // TTL in seconds
  ttl int
  // Zone file contents
  zoneFile string
  // DNS records
  records() []digitalocean.domain.record
}

// DigitalOcean DNS record
private digitalocean.domain.record @defaults("type name data") {
  // Domain name (parent)
  domainName string
  // Record ID
  id int
  // Record type (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA)
  type string
  // Record name (subdomain)
  name string
  // Record data (IP, hostname, etc.)
  data string
  // TTL in seconds
  ttl int
  // Priority (MX, SRV)
  priority int
  // Port (SRV)
  port int
  // Weight (SRV)
  weight int
  // Flags (CAA)
  flags int
  // Tag (CAA: issue, issuewild, iodef)
  tag string
}

// DigitalOcean Spaces bucket (S3-compatible object storage)
digitalocean.space @defaults("name region") {
  // Bucket name
  name string
  // Region slug
  region string
  // Created at
  createdAt time
}

// DigitalOcean block storage volume
digitalocean.volume @defaults("id name sizeGigabytes") {
  init(id string)
  // Volume ID
  id string
  // Volume name
  name string
  // Size in GB
  sizeGigabytes int
  // Region slug
  region string
  // Description
  description string
  // Filesystem type
  filesystemType string
  // Filesystem label
  filesystemLabel string
  // Created at
  createdAt time
  // Tags
  tags []string
  // Droplet IDs attached to
  dropletIds []int
}

// DigitalOcean load balancer
digitalocean.loadBalancer @defaults("id name") {
  // Load balancer ID
  id string
  // Name
  name string
  // Public IP address
  ip string
  // Status (new, active, errored)
  status string
  // Region slug
  region string
  // Created at
  createdAt time
  // Algorithm (round_robin, least_connections)
  algorithm string
  // Redirect HTTP to HTTPS
  redirectHttpToHttps bool
  // Enable proxy protocol
  enableProxyProtocol bool
  // Enable backend keepalive
  enableBackendKeepalive bool
  // VPC UUID
  vpcUuid string
  // Droplet IDs
  dropletIds []int
  // Tags
  tags []string
  // Forwarding rules
  forwardingRules []dict
  // Health check configuration
  healthCheck dict
  // Sticky sessions configuration
  stickySessions dict
  // Disable automatic DNS record
  disableLetsEncryptDnsRecords bool
  // Firewall configuration
  firewall dict
}

// DigitalOcean VPC
digitalocean.vpc @defaults("id name") {
  init(id string)
  // VPC ID
  id string
  // Name
  name string
  // Description
  description string
  // IP range (CIDR)
  ipRange string
  // Region slug
  region string
  // Created at
  createdAt time
  // Whether this is the default VPC
  default bool
}

// DigitalOcean Kubernetes cluster
digitalocean.kubernetes.cluster @defaults("id name") {
  // Cluster ID
  id string
  // Cluster name
  name string
  // Kubernetes version
  version string
  // Region slug
  region string
  // Status (running, provisioning, degraded, error, deleted, upgrading)
  status string
  // Created at
  createdAt time
  // Updated at
  updatedAt time
  // Cluster subnet
  clusterSubnet string
  // Service subnet
  serviceSubnet string
  // VPC UUID
  vpcUuid string
  // Auto-upgrade enabled
  autoUpgrade bool
  // Surge upgrade enabled
  surgeUpgrade bool
  // HA control plane enabled
  ha bool
  // Tags
  tags []string
  // Maintenance policy
  maintenancePolicy dict
  // Node pools
  nodePools() []digitalocean.kubernetes.nodePool
}

// DigitalOcean Kubernetes node pool
private digitalocean.kubernetes.nodePool @defaults("id name") {
  // Node pool ID
  id string
  // Cluster ID (parent)
  clusterId string
  // Name
  name string
  // Droplet size slug
  size string
  // Number of nodes
  count int
  // Auto-scale enabled
  autoScale bool
  // Minimum nodes (if auto-scale)
  minNodes int
  // Maximum nodes (if auto-scale)
  maxNodes int
  // Tags
  tags []string
}

// DigitalOcean project
digitalocean.project @defaults("id name") {
  // Project ID
  id string
  // Name
  name string
  // Description
  description string
  // Purpose
  purpose string
  // Environment (Development, Staging, Production)
  environment string
  // Created at
  createdAt time
  // Updated at
  updatedAt time
  // Whether this is the default project
  isDefault bool
}

// DigitalOcean SSH key
digitalocean.sshKey @defaults("id name") {
  // SSH key ID
  id int
  // Key name
  name string
  // Public key fingerprint
  fingerprint string
  // Public key content
  publicKey string
}

// DigitalOcean TLS certificate
digitalocean.certificate @defaults("id name") {
  // Certificate ID
  id string
  // Certificate name
  name string
  // SHA-1 fingerprint
  sha1Fingerprint string
  // State (pending, verified, error)
  state string
  // Type (custom, lets_encrypt)
  type string
  // DNS names
  dnsNames []string
  // Expiration
  notAfter time
  // Created at
  createdAt time
}
```

---

## Authentication

Single API token, same pattern as Shodan (`providers/shodan/connection/connection.go`):

```go
type DigitalOceanConnection struct {
    plugin.Connection
    Conf   *inventory.Config
    asset  *inventory.Asset
    client *godo.Client
}

func NewDigitalOceanConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DigitalOceanConnection, error) {
    conn := &DigitalOceanConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    token := os.Getenv("DIGITALOCEAN_TOKEN")
    if len(conf.Credentials) > 0 {
        for _, cred := range conf.Credentials {
            if cred.Type == vault.CredentialType_password {
                token = string(cred.Secret)
            }
        }
    }
    if token == "" {
        return nil, errors.New("a valid DigitalOcean token is required (set DIGITALOCEAN_TOKEN or use --token)")
    }

    tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
    oauthClient := oauth2.NewClient(context.Background(), tokenSource)
    conn.client = godo.NewClient(oauthClient)

    return conn, nil
}
```

---

## Implementation Patterns

### Paginated List (all list APIs)

DigitalOcean uses `godo.ListOptions` with page-based pagination:

```go
func (d *mqlDigitalocean) droplets() ([]any, error) {
    conn := d.MqlRuntime.Connection.(*connection.DigitalOceanConnection)
    client := conn.Client()

    var all []any
    opt := &godo.ListOptions{PerPage: 200}
    for {
        droplets, resp, err := client.Droplets.List(context.Background(), opt)
        if err != nil {
            return nil, err
        }
        for _, d := range droplets {
            r, err := CreateResource(d.MqlRuntime, "digitalocean.droplet", map[string]*llx.RawData{...})
            if err != nil { return nil, err }
            all = append(all, r)
        }
        if resp.Links == nil || resp.Links.IsLastPage() { break }
        page, _ := resp.Links.CurrentPage()
        opt.Page = page + 1
    }
    return all, nil
}
```

### Typed Resource References (via Internal struct)

Droplets store a VPC UUID but expose a typed `vpc()` method:

```go
type mqlDigitaloceanDropletInternal struct {
    cacheVpcUuid   string
    cacheVolumeIds []string
}

func (d *mqlDigitaloceanDroplet) vpc() (*mqlDigitaloceanVpc, error) {
    if d.cacheVpcUuid == "" {
        d.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    r, err := NewResource(d.MqlRuntime, "digitalocean.vpc",
        map[string]*llx.RawData{"id": llx.StringData(d.cacheVpcUuid)})
    if err != nil { return nil, err }
    return r.(*mqlDigitaloceanVpc), nil
}
```

### Child Resource Expansion (firewall rules)

Firewall rules are embedded in the API response. Expand into private child resources with composite `__id`:

```go
func (f *mqlDigitaloceanFirewall) inboundRules() ([]any, error) {
    return nil, f.fetchRules()
}

func (f *mqlDigitaloceanFirewall) fetchRules() error {
    // single API call populates both inbound + outbound
    conn := f.MqlRuntime.Connection.(*connection.DigitalOceanConnection)
    fw, _, err := conn.Client().Firewalls.Get(context.Background(), f.Id.Data)
    if err != nil { return err }

    var inbound []any
    for i, rule := range fw.InboundRules {
        r, err := CreateResource(f.MqlRuntime, "digitalocean.firewall.inboundRule", map[string]*llx.RawData{
            "__id":             llx.StringData(f.Id.Data + "/inbound/" + strconv.Itoa(i)),
            "firewallId":      llx.StringData(f.Id.Data),
            "protocol":        llx.StringData(rule.Protocol),
            "ports":           llx.StringData(rule.Ports),
            "sourceAddresses": llx.ArrayData(...),
            // ...
        })
        // ...
    }
    f.InboundRules = plugin.TValue[[]any]{Data: inbound, State: plugin.StateIsSet}
    // same for OutboundRules
    return nil
}
```

---

## Security Policies (MVP)

Ship as `mondoo-digitalocean-security.mql.yaml`:

**Network Security:**
- Firewalls must not allow unrestricted SSH (port 22) from `0.0.0.0/0`
- Firewalls must not allow all ports from `0.0.0.0/0`
- Load balancers must redirect HTTP to HTTPS

**Compute Security:**
- Droplets must have monitoring enabled
- Droplets must have backups enabled

**Database Security:**
- Managed databases must use private networking
- Managed databases must have firewall rules configured

**Kubernetes Security:**
- Clusters must have auto-upgrade enabled
- Clusters must have surge upgrade enabled
- Clusters must have HA control plane enabled

**Certificate Management:**
- Certificates must not be expired or in error state
- Certificates must not expire within 30 days

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/digitalocean` in `go.work` list
4. **`Makefile`** — `digitalocean` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/digitalocean/resources/digitalocean.lr \
  --dist providers/digitalocean/resources

# Build and install
make providers/build/digitalocean && make providers/install/digitalocean

# Test
export DIGITALOCEAN_TOKEN="dop_v1_xxxxx"
mql shell digitalocean
> digitalocean.account
> digitalocean.droplets { id name status region publicIpv4 }
> digitalocean.firewalls { name inboundRules { protocol ports sourceAddresses } }
> digitalocean.databases { name engine firewallRules }
> digitalocean.kubernetesClusters { name version autoUpgrade ha }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/digitalocean --provider-id digitalocean --provider-name "DigitalOcean"` then `cd providers/digitalocean && go mod tidy`
2. Root + Account (validates auth)
3. Droplets + VPCs (core compute)
4. Firewalls (critical for security policies)
5. Databases (firewall rules, users)
6. Load Balancers (HTTPS checks)
7. Kubernetes (clusters, node pools)
8. Domains + DNS records
9. Spaces, Volumes, Projects, SSH Keys, Certificates
10. Security policies
11. Discovery
12. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [DigitalOcean API v2](https://docs.digitalocean.com/reference/api/digitalocean/)
- [godo Go SDK](https://github.com/digitalocean/godo)
- [Terraform DigitalOcean Provider](https://github.com/digitalocean/terraform-provider-digitalocean)
- Reference providers: `providers/shodan/`, `providers/ipinfo/`
