// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
)

// The load balancer's probes, rules, pools and frontends reference each other
// by bare ARM sub-resource ID. Resolving one of those references through
// NewResource would run the target's init ahead of the runtime cache and turn a
// single load balancer into one lookup per reference. The parent already holds
// every child in a memoized collection, so each accessor here scans that
// collection instead: the parent's list is built once and every reference after
// the first is a lookup against values already in memory.

// lbChild is the shared shape of the load balancer's child resources: each one
// carries the ARM sub-resource ID the others reference it by.
type lbChild interface {
	GetId() *plugin.TValue[string]
}

// lbChildrenByID resolves a set of ARM sub-resource IDs against one of the
// parent load balancer's memoized child collections.
//
// A reference to a child the load balancer did not report is dropped rather
// than surfaced as an error: ARM occasionally reports a rule pointing at a
// pool in another load balancer, and losing that one edge is better than
// failing the whole collection.
func lbChildrenByID[T lbChild](collection *plugin.TValue[[]any], ids []string) ([]any, error) {
	res := []any{}
	if len(ids) == 0 {
		return res, nil
	}
	if collection.Error != nil {
		return nil, collection.Error
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		for _, raw := range collection.Data {
			child, ok := raw.(T)
			if !ok {
				continue
			}
			if strings.EqualFold(child.GetId().Data, id) {
				res = append(res, child)
				break
			}
		}
	}
	return res, nil
}

// lbChildByID resolves a single ARM sub-resource ID against one of the parent's
// memoized child collections. It marks the caller's field null and returns nil
// when the ID is empty or names a child the load balancer did not report, so
// the field reads as "no such reference" rather than leaving the runtime with
// an unresolved field.
func lbChildByID[T lbChild](collection *plugin.TValue[[]any], id string, markNull func()) (T, error) {
	var zero T
	if id == "" {
		markNull()
		return zero, nil
	}
	if collection.Error != nil {
		return zero, collection.Error
	}
	for _, raw := range collection.Data {
		child, ok := raw.(T)
		if !ok {
			continue
		}
		if strings.EqualFold(child.GetId().Data, id) {
			return child, nil
		}
	}
	markNull()
	return zero, nil
}

type mqlAzureSubscriptionNetworkServiceProbeInternal struct {
	cacheLoadBalancer      *mqlAzureSubscriptionNetworkServiceLoadBalancer
	cacheLoadBalancerRules []string
}

func (a *mqlAzureSubscriptionNetworkServiceProbe) loadBalancerRules() ([]any, error) {
	if a.cacheLoadBalancer == nil {
		return []any{}, nil
	}
	return lbChildrenByID[*mqlAzureSubscriptionNetworkServiceLoadBalancerRule](
		a.cacheLoadBalancer.GetLoadBalancerRules(), a.cacheLoadBalancerRules)
}

type mqlAzureSubscriptionNetworkServiceBackendAddressPoolInternal struct {
	cacheLoadBalancer      *mqlAzureSubscriptionNetworkServiceLoadBalancer
	cacheLoadBalancerRules []string
	cacheInboundNatRules   []string
	cacheOutboundRules     []string
}

func (a *mqlAzureSubscriptionNetworkServiceBackendAddressPool) loadBalancerRules() ([]any, error) {
	if a.cacheLoadBalancer == nil {
		return []any{}, nil
	}
	return lbChildrenByID[*mqlAzureSubscriptionNetworkServiceLoadBalancerRule](
		a.cacheLoadBalancer.GetLoadBalancerRules(), a.cacheLoadBalancerRules)
}

func (a *mqlAzureSubscriptionNetworkServiceBackendAddressPool) inboundNatRules() ([]any, error) {
	if a.cacheLoadBalancer == nil {
		return []any{}, nil
	}
	return lbChildrenByID[*mqlAzureSubscriptionNetworkServiceInboundNatRule](
		a.cacheLoadBalancer.GetInboundNatRules(), a.cacheInboundNatRules)
}

func (a *mqlAzureSubscriptionNetworkServiceBackendAddressPool) outboundRules() ([]any, error) {
	if a.cacheLoadBalancer == nil {
		return []any{}, nil
	}
	return lbChildrenByID[*mqlAzureSubscriptionNetworkServiceOutboundRule](
		a.cacheLoadBalancer.GetOutboundRules(), a.cacheOutboundRules)
}

type mqlAzureSubscriptionNetworkServiceInboundNatPoolInternal struct {
	cacheLoadBalancer     *mqlAzureSubscriptionNetworkServiceLoadBalancer
	cacheFrontendIpConfig string
}

func (a *mqlAzureSubscriptionNetworkServiceInboundNatPool) frontendIpConfig() (*mqlAzureSubscriptionNetworkServiceFrontendIpConfig, error) {
	markNull := func() { a.FrontendIpConfig.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceFrontendIpConfig](
		a.cacheLoadBalancer.GetFrontendIpConfigs(), a.cacheFrontendIpConfig, markNull)
}

type mqlAzureSubscriptionNetworkServiceInboundNatRuleInternal struct {
	cacheLoadBalancer      *mqlAzureSubscriptionNetworkServiceLoadBalancer
	cacheFrontendIpConfig  string
	cacheBackendAddressPol string
}

func (a *mqlAzureSubscriptionNetworkServiceInboundNatRule) frontendIpConfig() (*mqlAzureSubscriptionNetworkServiceFrontendIpConfig, error) {
	markNull := func() { a.FrontendIpConfig.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceFrontendIpConfig](
		a.cacheLoadBalancer.GetFrontendIpConfigs(), a.cacheFrontendIpConfig, markNull)
}

func (a *mqlAzureSubscriptionNetworkServiceInboundNatRule) backendAddressPool() (*mqlAzureSubscriptionNetworkServiceBackendAddressPool, error) {
	markNull := func() { a.BackendAddressPool.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceBackendAddressPool](
		a.cacheLoadBalancer.GetBackendPools(), a.cacheBackendAddressPol, markNull)
}

type mqlAzureSubscriptionNetworkServiceLoadBalancerRuleInternal struct {
	cacheLoadBalancer       *mqlAzureSubscriptionNetworkServiceLoadBalancer
	cacheFrontendIpConfig   string
	cacheBackendAddressPol  string
	cacheBackendAddressPols []string
	cacheProbe              string
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancerRule) frontendIpConfig() (*mqlAzureSubscriptionNetworkServiceFrontendIpConfig, error) {
	markNull := func() { a.FrontendIpConfig.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceFrontendIpConfig](
		a.cacheLoadBalancer.GetFrontendIpConfigs(), a.cacheFrontendIpConfig, markNull)
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancerRule) backendAddressPool() (*mqlAzureSubscriptionNetworkServiceBackendAddressPool, error) {
	markNull := func() { a.BackendAddressPool.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceBackendAddressPool](
		a.cacheLoadBalancer.GetBackendPools(), a.cacheBackendAddressPol, markNull)
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancerRule) backendAddressPools() ([]any, error) {
	if a.cacheLoadBalancer == nil {
		return []any{}, nil
	}
	return lbChildrenByID[*mqlAzureSubscriptionNetworkServiceBackendAddressPool](
		a.cacheLoadBalancer.GetBackendPools(), a.cacheBackendAddressPols)
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancerRule) probe() (*mqlAzureSubscriptionNetworkServiceProbe, error) {
	markNull := func() { a.Probe.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceProbe](
		a.cacheLoadBalancer.GetProbes(), a.cacheProbe, markNull)
}

type mqlAzureSubscriptionNetworkServiceOutboundRuleInternal struct {
	cacheLoadBalancer      *mqlAzureSubscriptionNetworkServiceLoadBalancer
	cacheBackendAddressPol string
	cacheFrontendIpConfigs []string
}

func (a *mqlAzureSubscriptionNetworkServiceOutboundRule) backendAddressPool() (*mqlAzureSubscriptionNetworkServiceBackendAddressPool, error) {
	markNull := func() { a.BackendAddressPool.State = plugin.StateIsSet | plugin.StateIsNull }
	if a.cacheLoadBalancer == nil {
		markNull()
		return nil, nil
	}
	return lbChildByID[*mqlAzureSubscriptionNetworkServiceBackendAddressPool](
		a.cacheLoadBalancer.GetBackendPools(), a.cacheBackendAddressPol, markNull)
}

func (a *mqlAzureSubscriptionNetworkServiceOutboundRule) frontendIpConfigs() ([]any, error) {
	if a.cacheLoadBalancer == nil {
		return []any{}, nil
	}
	return lbChildrenByID[*mqlAzureSubscriptionNetworkServiceFrontendIpConfig](
		a.cacheLoadBalancer.GetFrontendIpConfigs(), a.cacheFrontendIpConfigs)
}

// subResourceIDs returns the ARM IDs a []*SubResource points at, skipping
// entries the service returned without one.
func subResourceIDs(subs []*network.SubResource) []string {
	if len(subs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(subs))
	for _, sub := range subs {
		if id := subResourceID(sub); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
