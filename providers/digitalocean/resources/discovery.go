// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"maps"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover expands a DigitalOcean account connection into the specific
// child assets the discovery targets ask for. The account itself stays
// the connected (root) asset; the returned inventory holds the children.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return nil, nil
	}

	targets := resolveDiscoveryTargets(conf.Discover.Targets)
	client := conn.Client()
	ctx := context.Background()

	// The owning account UUID anchors every child platform id so they
	// stay stable and unique across scans. It is cached on the
	// connection and shared with detect(), so this does not add an
	// Account.Get round-trip. An empty UUID (token without account read
	// access) still yields valid, account-relative ids.
	accountUUID := conn.AccountUUID()

	assets := []*inventory.Asset{}

	childAsset := func(platform *inventory.Platform, platformID, name string, opts map[string]string) *inventory.Asset {
		cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		cfg.Options[connection.OptionAccount] = accountUUID
		maps.Copy(cfg.Options, opts)
		return &inventory.Asset{
			PlatformIds: []string{platformID},
			Name:        name,
			Platform:    platform,
			Connections: []*inventory.Config{cfg},
		}
	}

	if stringx.Contains(targets, connection.DiscoveryDatabases) {
		opt := &godo.ListOptions{PerPage: 200}
		for {
			dbs, resp, err := client.Databases.List(ctx, opt)
			if err != nil {
				return nil, err
			}
			for _, db := range dbs {
				if skipDatabase(conn.Filters.General, &db) {
					continue
				}
				assets = append(assets, childAsset(
					connection.DatabasePlatform(),
					connection.NewDatabaseIdentifier(accountUUID, db.ID),
					"DigitalOcean Database "+db.Name,
					map[string]string{connection.OptionDatabase: db.ID},
				))
			}
			if resp.Links == nil || resp.Links.IsLastPage() {
				break
			}
			page, err := resp.Links.CurrentPage()
			if err != nil {
				return nil, err
			}
			opt.Page = page + 1
		}
	}

	if stringx.Contains(targets, connection.DiscoveryKubernetes) {
		opt := &godo.ListOptions{PerPage: 200}
		for {
			clusters, resp, err := client.Kubernetes.List(ctx, opt)
			if err != nil {
				return nil, err
			}
			for _, c := range clusters {
				if skipKubernetesCluster(conn.Filters.General, c) {
					continue
				}
				assets = append(assets, childAsset(
					connection.KubernetesPlatform(),
					connection.NewKubernetesIdentifier(accountUUID, c.ID),
					"DigitalOcean Kubernetes Cluster "+c.Name,
					map[string]string{connection.OptionKubernetes: c.ID},
				))
			}
			if resp.Links == nil || resp.Links.IsLastPage() {
				break
			}
			page, err := resp.Links.CurrentPage()
			if err != nil {
				return nil, err
			}
			opt.Page = page + 1
		}
	}

	if stringx.Contains(targets, connection.DiscoveryLoadBalancers) {
		opt := &godo.ListOptions{PerPage: 200}
		for {
			lbs, resp, err := client.LoadBalancers.List(ctx, opt)
			if err != nil {
				return nil, err
			}
			for _, lb := range lbs {
				if skipLoadBalancer(conn.Filters.General, &lb) {
					continue
				}
				assets = append(assets, childAsset(
					connection.LoadBalancerPlatform(),
					connection.NewLoadBalancerIdentifier(accountUUID, lb.ID),
					"DigitalOcean Load Balancer "+lb.Name,
					map[string]string{connection.OptionLoadBalancer: lb.ID},
				))
			}
			if resp.Links == nil || resp.Links.IsLastPage() {
				break
			}
			page, err := resp.Links.CurrentPage()
			if err != nil {
				return nil, err
			}
			opt.Page = page + 1
		}
	}

	if stringx.Contains(targets, connection.DiscoveryFirewalls) {
		opt := &godo.ListOptions{PerPage: 200}
		for {
			firewalls, resp, err := client.Firewalls.List(ctx, opt)
			if err != nil {
				return nil, err
			}
			for _, fw := range firewalls {
				if skipFirewall(conn.Filters.General, &fw) {
					continue
				}
				assets = append(assets, childAsset(
					connection.FirewallPlatform(),
					connection.NewFirewallIdentifier(accountUUID, fw.ID),
					"DigitalOcean Cloud Firewall "+fw.Name,
					map[string]string{connection.OptionFirewall: fw.ID},
				))
			}
			if resp.Links == nil || resp.Links.IsLastPage() {
				break
			}
			page, err := resp.Links.CurrentPage()
			if err != nil {
				return nil, err
			}
			opt.Page = page + 1
		}
	}

	// Spaces buckets can only be enumerated with the optional Spaces
	// (S3-compatible) credentials. Without them there is nothing to
	// discover — mirror the resource layer and skip silently.
	if stringx.Contains(targets, connection.DiscoverySpacesBuckets) {
		if _, _, ok := conn.SpacesCredentials(); ok {
			regions := []string{conn.SpacesRegion()}
			if regions[0] == "" {
				regions = knownSpacesRegions
			}
			refs, err := listSpacesBucketRefs(conn, regions)
			if err != nil {
				return nil, err
			}
			for _, ref := range refs {
				name := ""
				if ref.b.Name != nil {
					name = *ref.b.Name
				}
				assets = append(assets, childAsset(
					connection.SpacesBucketPlatform(),
					connection.NewSpacesBucketIdentifier(accountUUID, ref.region, name),
					"DigitalOcean Spaces Bucket "+name,
					map[string]string{
						connection.OptionSpacesBucket: name,
						connection.OptionSpacesRegion: ref.region,
					},
				))
			}
		}
	}

	if stringx.Contains(targets, connection.DiscoveryGradientaiAgents) {
		opt := &godo.ListOptions{PerPage: 200}
		for {
			agents, resp, err := client.AgentPlatform.ListAgents(ctx, opt)
			if err != nil {
				return nil, err
			}
			for _, a := range agents {
				if a == nil || skipGradientaiAgent(conn.Filters.General, a) {
					continue
				}
				assets = append(assets, childAsset(
					connection.GradientaiAgentPlatform(),
					connection.NewGradientaiAgentIdentifier(accountUUID, a.Uuid),
					"DigitalOcean GradientAI Agent "+a.Name,
					map[string]string{connection.OptionGradientaiAgent: a.Uuid},
				))
			}
			if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
				break
			}
			page, err := resp.Links.CurrentPage()
			if err != nil {
				return nil, err
			}
			opt.Page = page + 1
		}
	}

	return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
}

// resolveDiscoveryTargets expands the "auto"/"all" aliases into the full
// set of child-asset types the provider can split an account into.
func resolveDiscoveryTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) || stringx.Contains(targets, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryDatabases,
			connection.DiscoveryKubernetes,
			connection.DiscoveryLoadBalancers,
			connection.DiscoveryFirewalls,
			connection.DiscoverySpacesBuckets,
			connection.DiscoveryGradientaiAgents,
		}
	}
	return targets
}
