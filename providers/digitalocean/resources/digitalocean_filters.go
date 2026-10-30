// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// The helpers below decide whether a discovery-target object survives the
// --filters selection. Discovery enumerates each service itself rather than
// reading back through the MQL listers, so both paths call these shims to
// guarantee they derive the same region and tag set from a given object. A
// filtered scan and a plain query therefore return the same resources.
//
// Objects with no region (cloud firewalls are account-global) pass "" so
// region filters leave them alone; see GeneralDiscoveryFilters.IsFilteredOut.

func skipDatabase(f connection.GeneralDiscoveryFilters, db *godo.Database) bool {
	return f.IsFilteredOut(db.RegionSlug, db.Tags)
}

func skipKubernetesCluster(f connection.GeneralDiscoveryFilters, c *godo.KubernetesCluster) bool {
	if c == nil {
		return false
	}
	return f.IsFilteredOut(c.RegionSlug, c.Tags)
}

func skipLoadBalancer(f connection.GeneralDiscoveryFilters, lb *godo.LoadBalancer) bool {
	region := ""
	if lb.Region != nil {
		region = lb.Region.Slug
	}
	return f.IsFilteredOut(region, lb.Tags)
}

// skipFirewall filters on tags only. Cloud firewalls are account-global, so
// they carry no region to match against.
func skipFirewall(f connection.GeneralDiscoveryFilters, fw *godo.Firewall) bool {
	return f.IsFilteredOut("", fw.Tags)
}

func skipGradientaiAgent(f connection.GeneralDiscoveryFilters, a *godo.Agent) bool {
	return f.IsFilteredOut(a.Region, a.Tags)
}

// skipSpacesBucket filters on region only. DigitalOcean Spaces does not support
// bucket tagging, so a bucket carries no tags and an include-tag filter drops
// every bucket.
func skipSpacesBucket(f connection.GeneralDiscoveryFilters, region string) bool {
	return f.IsFilteredOut(region, nil)
}
