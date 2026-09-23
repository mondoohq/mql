// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
)

// lowerSet folds a list of ARM resource ids for comparison. ARM resource ids are
// case-insensitive, and which casing a caller sees depends on which API returned
// the id, so every id comparison here goes through this.
func lowerSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			set[id] = struct{}{}
		}
	}
	return set
}

// subResourceID reads the id off an ARM sub-resource reference, or "" when either
// the reference or the id is absent.
func subResourceID(ref *network.SubResource) string {
	if ref == nil || ref.ID == nil {
		return ""
	}
	return *ref.ID
}

// publicFrontendIDs returns the load balancer's frontend configurations that have
// a public IP address, folded for comparison.
//
// A frontend with a private IP is an internal load balancer's, and traffic
// arriving through it is not from the internet.
func publicFrontendIDs(props *network.LoadBalancerPropertiesFormat) map[string]struct{} {
	if props == nil {
		return nil
	}
	var ids []string
	for _, frontend := range props.FrontendIPConfigurations {
		if frontend == nil || frontend.ID == nil || frontend.Properties == nil {
			continue
		}
		if frontend.Properties.PublicIPAddress != nil {
			ids = append(ids, *frontend.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return lowerSet(ids)
}

// internetForwardedIPConfigIDs returns the interface IP configurations this load
// balancer forwards internet traffic to, folded for comparison.
//
// Three things all have to hold, and each is checked rather than assumed:
// a frontend with a public IP, a rule bound to that frontend, and a backend the
// rule points at that the IP configuration is a member of. A public frontend with
// no rule forwards nothing; a rule on a private frontend forwards traffic that did
// not come from the internet.
//
// Inbound NAT rules are read two ways because ARM supports both: a rule bound to
// one IP configuration directly, and a rule bound to a backend pool.
func internetForwardedIPConfigIDs(props *network.LoadBalancerPropertiesFormat) map[string]struct{} {
	publicFrontends := publicFrontendIDs(props)
	if len(publicFrontends) == 0 {
		return nil
	}

	isPublicFrontend := func(ref *network.SubResource) bool {
		id := strings.ToLower(subResourceID(ref))
		if id == "" {
			return false
		}
		_, ok := publicFrontends[id]
		return ok
	}

	forwarded := map[string]struct{}{}
	pools := map[string]struct{}{}

	for _, rule := range props.LoadBalancingRules {
		if rule == nil || rule.Properties == nil || !isPublicFrontend(rule.Properties.FrontendIPConfiguration) {
			continue
		}
		if id := strings.ToLower(subResourceID(rule.Properties.BackendAddressPool)); id != "" {
			pools[id] = struct{}{}
		}
		for _, pool := range rule.Properties.BackendAddressPools {
			if id := strings.ToLower(subResourceID(pool)); id != "" {
				pools[id] = struct{}{}
			}
		}
	}

	for _, rule := range props.InboundNatRules {
		if rule == nil || rule.Properties == nil || !isPublicFrontend(rule.Properties.FrontendIPConfiguration) {
			continue
		}
		if id := strings.ToLower(subResourceID(rule.Properties.BackendAddressPool)); id != "" {
			pools[id] = struct{}{}
		}
		// A NAT rule can name one IP configuration instead of a pool, which is
		// how a single-VM RDP or SSH forward is written.
		if cfg := rule.Properties.BackendIPConfiguration; cfg != nil && cfg.ID != nil {
			if id := strings.ToLower(*cfg.ID); id != "" {
				forwarded[id] = struct{}{}
			}
		}
	}

	for _, pool := range props.BackendAddressPools {
		if pool == nil || pool.ID == nil || pool.Properties == nil {
			continue
		}
		if _, ok := pools[strings.ToLower(*pool.ID)]; !ok {
			continue
		}
		for _, cfg := range pool.Properties.BackendIPConfigurations {
			if cfg == nil || cfg.ID == nil {
				continue
			}
			if id := strings.ToLower(*cfg.ID); id != "" {
				forwarded[id] = struct{}{}
			}
		}
	}

	if len(forwarded) == 0 {
		return nil
	}
	return forwarded
}

// anyIPConfigForwarded reports whether any of the given interface IP
// configurations is one a public frontend of any of these load balancers forwards
// to.
func anyIPConfigForwarded(loadBalancerProps []*network.LoadBalancerPropertiesFormat, ipConfigIDs []string) bool {
	wanted := lowerSet(ipConfigIDs)
	if len(wanted) == 0 {
		return false
	}
	for _, props := range loadBalancerProps {
		for id := range internetForwardedIPConfigIDs(props) {
			if _, ok := wanted[id]; ok {
				return true
			}
		}
	}
	return false
}

// vmNicIPConfigIDs collects the ids of the IP configurations on a VM's network
// interfaces, read from the raw configurations already cached on each interface.
func vmNicIPConfigIDs(nics []any) []string {
	var ids []string
	for _, n := range nics {
		nic, ok := n.(*mqlAzureSubscriptionNetworkServiceInterface)
		if !ok {
			continue
		}
		for _, ipConfig := range nic.cacheIPConfigurations {
			if ipConfig != nil && ipConfig.ID != nil {
				ids = append(ids, *ipConfig.ID)
			}
		}
	}
	return ids
}

// behindPublicLoadBalancer reports whether a public load balancer forwards
// internet traffic to any of these network interfaces.
//
// This is the other way a virtual machine is reachable from the internet, and the
// one Azure's own reference architectures use: the public IP sits on the load
// balancer's frontend and the machine's interface holds only a private address, so
// reading public IPs off the interfaces alone reports a reachable machine as
// closed.
//
// The load balancers are read through the network service resource, so the listing
// is fetched once for the whole scan rather than once per machine.
func (a *mqlAzureSubscriptionComputeServiceVm) behindPublicLoadBalancer(nics []any) (bool, error) {
	ipConfigIDs := vmNicIPConfigIDs(nics)
	if len(ipConfigIDs) == 0 {
		return false, nil
	}

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return false, err
	}
	svc, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(resourceID.SubscriptionID),
	})
	if err != nil {
		return false, err
	}
	loadBalancers := svc.(*mqlAzureSubscriptionNetworkService).GetLoadBalancers()
	if loadBalancers.Error != nil {
		return false, loadBalancers.Error
	}

	props := make([]*network.LoadBalancerPropertiesFormat, 0, len(loadBalancers.Data))
	for _, lb := range loadBalancers.Data {
		mqlLB, ok := lb.(*mqlAzureSubscriptionNetworkServiceLoadBalancer)
		if !ok {
			continue
		}
		props = append(props, mqlLB.cacheProperties)
	}
	return anyIPConfigForwarded(props, ipConfigIDs), nil
}

// logLoadBalancerLookupFailure records why the load balancer signal is missing.
// The verdict stays provisional rather than claiming the machine is closed.
func logLoadBalancerLookupFailure(vmID string, err error) {
	log.Warn().Err(err).Str("vm", vmID).
		Msg("could not read load balancers while evaluating exposure")
}
