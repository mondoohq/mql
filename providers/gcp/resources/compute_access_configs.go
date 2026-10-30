// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/compute/v1"
)

type mqlGcpProjectComputeServiceInstanceNetworkInterfaceAccessConfigInternal struct {
	cacheSecurityPolicyUrl string
}

// accessConfigIDSegment names the list an access config was read from. The IPv4
// and IPv6 lists on a single NIC are allowed to reuse a name, so the segment has
// to be part of the cache key or the two entries collide and the second one is
// silently dropped in favour of the first.
const (
	accessConfigIDSegment     = "accessConfig"
	ipv6AccessConfigIDSegment = "ipv6AccessConfig"
)

// accessConfigID builds the cache key for one external IP configuration.
func accessConfigID(nicID string, segment string, name string) string {
	return nicID + "/" + segment + "/" + name
}

func newMqlComputeAccessConfig(runtime *plugin.Runtime, nicID string, segment string, cfg *compute.AccessConfig) (*mqlGcpProjectComputeServiceInstanceNetworkInterfaceAccessConfig, error) {
	res, err := CreateResource(runtime, "gcp.project.computeService.instance.networkInterface.accessConfig", map[string]*llx.RawData{
		"__id":                llx.StringData(accessConfigID(nicID, segment, cfg.Name)),
		"name":                llx.StringData(cfg.Name),
		"type":                llx.StringData(cfg.Type),
		"natIP":               llx.StringData(cfg.NatIP),
		"externalIpv6":        llx.StringData(cfg.ExternalIpv6),
		"networkTier":         llx.StringData(cfg.NetworkTier),
		"setPublicPtr":        llx.BoolData(cfg.SetPublicPtr),
		"publicPtrDomainName": llx.StringData(cfg.PublicPtrDomainName),
	})
	if err != nil {
		return nil, err
	}
	ac := res.(*mqlGcpProjectComputeServiceInstanceNetworkInterfaceAccessConfig)
	ac.cacheSecurityPolicyUrl = cfg.SecurityPolicy
	return ac, nil
}

func (g *mqlGcpProjectComputeServiceInstanceNetworkInterfaceAccessConfig) securityPolicy() (*mqlGcpProjectComputeServiceSecurityPolicy, error) {
	if g.cacheSecurityPolicyUrl == "" {
		g.SecurityPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	policy, err := getSecurityPolicyByUrl(g.cacheSecurityPolicyUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		g.SecurityPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return policy, nil
}

func (g *mqlGcpProjectComputeServiceInstanceNetworkInterface) externalIpConfigs() ([]any, error) {
	res := make([]any, 0, len(g.cacheAccessConfigs)+len(g.cacheIpv6AccessConfigs))
	for _, cfg := range g.cacheAccessConfigs {
		if cfg == nil {
			continue
		}
		ac, err := newMqlComputeAccessConfig(g.MqlRuntime, g.__id, accessConfigIDSegment, cfg)
		if err != nil {
			return nil, err
		}
		res = append(res, ac)
	}
	for _, cfg := range g.cacheIpv6AccessConfigs {
		if cfg == nil {
			continue
		}
		ac, err := newMqlComputeAccessConfig(g.MqlRuntime, g.__id, ipv6AccessConfigIDSegment, cfg)
		if err != nil {
			return nil, err
		}
		res = append(res, ac)
	}
	return res, nil
}
