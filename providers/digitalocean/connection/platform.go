// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Discovery targets. "auto" and "all" both expand to every specific
// child-asset type the provider knows how to split an account into.
const (
	DiscoveryAuto             = "auto"
	DiscoveryAll              = "all"
	DiscoveryDatabases        = "databases"
	DiscoveryKubernetes       = "kubernetes"
	DiscoveryLoadBalancers    = "loadbalancers"
	DiscoveryFirewalls        = "firewalls"
	DiscoverySpacesBuckets    = "spaces-buckets"
	DiscoveryGradientaiAgents = "gradientai-agents"
)

// Connection options that scope a connection to a single discovered
// sub-asset. When one of these is set on the connection config, the
// connection represents that specific resource (not the whole account),
// and the matching singular MQL resource (e.g. digitalocean.database)
// binds to it.
const (
	// OptionAccount carries the owning account UUID so child platform
	// ids stay stable and unique without an extra Account.Get at
	// child-connect time.
	OptionAccount      = "account"
	OptionDatabase     = "database"
	OptionKubernetes   = "kubernetes-cluster"
	OptionLoadBalancer = "loadbalancer"
	OptionFirewall     = "firewall"
	OptionSpacesBucket = "spaces-bucket"
	// OptionSpacesRegion is paired with OptionSpacesBucket because a
	// bucket is addressed by (region, name) on the S3-compatible API.
	OptionSpacesRegion    = "spaces-region"
	OptionGradientaiAgent = "gradientai-agent"
)

const platformIDBase = "//platformid.api.mondoo.app/runtime/digitalocean"

// basePlatform builds a runtime platform from the static catalog entry for the
// given name, keeping the catalog (platforms.go) as the single source of truth.
func basePlatform(name string) *inventory.Platform {
	p := &inventory.Platform{}
	PlatformByName(name).Apply(p)
	return p
}

// AccountPlatform is the root DigitalOcean account asset.
func AccountPlatform() *inventory.Platform {
	return basePlatform("digitalocean")
}

// DatabasePlatform is a single managed database cluster.
func DatabasePlatform() *inventory.Platform {
	return basePlatform("digitalocean-database")
}

// KubernetesPlatform is a single DOKS cluster.
func KubernetesPlatform() *inventory.Platform {
	return basePlatform("digitalocean-kubernetes-cluster")
}

// LoadBalancerPlatform is a single load balancer.
func LoadBalancerPlatform() *inventory.Platform {
	return basePlatform("digitalocean-loadbalancer")
}

// FirewallPlatform is a single cloud firewall.
func FirewallPlatform() *inventory.Platform {
	return basePlatform("digitalocean-firewall")
}

// SpacesBucketPlatform is a single Spaces bucket.
func SpacesBucketPlatform() *inventory.Platform {
	return basePlatform("digitalocean-spaces-bucket")
}

// GradientaiAgentPlatform is a single GradientAI agent.
func GradientaiAgentPlatform() *inventory.Platform {
	return basePlatform("digitalocean-gradientai-agent")
}

// NewAccountIdentifier builds the platform id for the account root. The
// UUID may be empty when the token isn't permitted to read the account.
func NewAccountIdentifier(accountUUID string) string {
	if accountUUID == "" {
		return platformIDBase
	}
	return platformIDBase + "/account/" + accountUUID
}

func childIdentifier(accountUUID, kind, id string) string {
	return NewAccountIdentifier(accountUUID) + "/" + kind + "/" + id
}

func NewDatabaseIdentifier(accountUUID, id string) string {
	return childIdentifier(accountUUID, "database", id)
}

func NewKubernetesIdentifier(accountUUID, id string) string {
	return childIdentifier(accountUUID, "kubernetes", id)
}

func NewLoadBalancerIdentifier(accountUUID, id string) string {
	return childIdentifier(accountUUID, "loadbalancer", id)
}

func NewFirewallIdentifier(accountUUID, id string) string {
	return childIdentifier(accountUUID, "firewall", id)
}

func NewSpacesBucketIdentifier(accountUUID, region, name string) string {
	return childIdentifier(accountUUID, "spaces-bucket", region+"/"+name)
}

func NewGradientaiAgentIdentifier(accountUUID, uuid string) string {
	return childIdentifier(accountUUID, "gradientai-agent", uuid)
}

// SubAssetPlatform reports the specific platform, platform id, and asset
// name when this connection is scoped to a single discovered sub-asset.
// It returns (nil, "", "") for a plain account connection. The account
// UUID is read from the OptionAccount the discovery step stamped on the
// child config.
func (c *DigitaloceanConnection) SubAssetPlatform() (*inventory.Platform, string, string) {
	opts := c.Conf.Options
	accountUUID := opts[OptionAccount]

	if id := opts[OptionDatabase]; id != "" {
		return DatabasePlatform(), NewDatabaseIdentifier(accountUUID, id), "DigitalOcean Database " + id
	}
	if id := opts[OptionKubernetes]; id != "" {
		return KubernetesPlatform(), NewKubernetesIdentifier(accountUUID, id), "DigitalOcean Kubernetes Cluster " + id
	}
	if id := opts[OptionLoadBalancer]; id != "" {
		return LoadBalancerPlatform(), NewLoadBalancerIdentifier(accountUUID, id), "DigitalOcean Load Balancer " + id
	}
	if id := opts[OptionFirewall]; id != "" {
		return FirewallPlatform(), NewFirewallIdentifier(accountUUID, id), "DigitalOcean Cloud Firewall " + id
	}
	if name := opts[OptionSpacesBucket]; name != "" {
		region := opts[OptionSpacesRegion]
		return SpacesBucketPlatform(), NewSpacesBucketIdentifier(accountUUID, region, name), "DigitalOcean Spaces Bucket " + name
	}
	if uuid := opts[OptionGradientaiAgent]; uuid != "" {
		return GradientaiAgentPlatform(), NewGradientaiAgentIdentifier(accountUUID, uuid), "DigitalOcean GradientAI Agent " + uuid
	}
	return nil, "", ""
}
