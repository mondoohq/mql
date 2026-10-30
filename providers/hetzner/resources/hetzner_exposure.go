// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// firewallRuleOpenToInternet reports whether a Hetzner firewall rule dict is an
// inbound rule whose source admits any address (0.0.0.0/0 or ::/0).
func firewallRuleOpenToInternet(rule map[string]any) bool {
	if direction, _ := rule["direction"].(string); direction != "in" {
		return false
	}
	sources, ok := rule["sourceIps"].([]any)
	if !ok {
		return false
	}
	for _, s := range sources {
		if cidr, ok := s.(string); ok && (cidr == "0.0.0.0/0" || cidr == "::/0") {
			return true
		}
	}
	return false
}

// firewallBindingRules pairs a firewall binding's application status with the
// rule dicts of the firewall it binds, the two inputs the ingress decision
// needs.
type firewallBindingRules struct {
	status string
	rules  []any
}

// serverFirewallIngress reports whether a server's firewall bindings admit
// traffic from any address, along with the inbound rules that do so.
//
// Only a binding whose status is applied enforces its rules; a pending binding
// has not taken effect yet. A server with no enforcing binding therefore admits
// ingress, which covers both the no-firewall case and the case where every
// attached firewall is still pending.
func serverFirewallIngress(bindings []firewallBindingRules) (bool, []any) {
	openRules := []any{}
	enforcing := 0
	for _, b := range bindings {
		if b.status != string(hcloud.FirewallStatusApplied) {
			continue
		}
		enforcing++
		for _, r := range b.rules {
			rule, ok := r.(map[string]any)
			if ok && firewallRuleOpenToInternet(rule) {
				openRules = append(openRules, rule)
			}
		}
	}
	return enforcing == 0 || len(openRules) > 0, openRules
}

// exposure breaks down whether the server is reachable from the internet: a
// public IP combined with firewall ingress that admits any address.
func (s *mqlHetznerServer) exposure() (*mqlHetznerNetworkExposure, error) {
	id := s.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	ipv4 := s.GetPublicIpv4()
	if ipv4.Error != nil {
		return nil, ipv4.Error
	}
	ipv6 := s.GetPublicIpv6()
	if ipv6.Error != nil {
		return nil, ipv6.Error
	}
	hasPublicIp := ipv4.Data != "" || ipv6.Data != ""

	bindings := s.GetFirewallBindings()
	if bindings.Error != nil {
		return nil, bindings.Error
	}
	collected := make([]firewallBindingRules, 0, len(bindings.Data))
	for _, b := range bindings.Data {
		binding, ok := b.(*mqlHetznerServerFirewallBinding)
		if !ok {
			continue
		}
		status := binding.GetStatus()
		if status.Error != nil {
			return nil, status.Error
		}
		entry := firewallBindingRules{status: status.Data}

		fw := binding.GetFirewall()
		if fw.Error != nil {
			return nil, fw.Error
		}
		if fw.Data != nil {
			rules := fw.Data.GetRules()
			if rules.Error != nil {
				return nil, rules.Error
			}
			entry.rules = rules.Data
		}
		collected = append(collected, entry)
	}

	firewallAllowsIngress, openRules := serverFirewallIngress(collected)
	internetReachable := hasPublicIp && firewallAllowsIngress

	res, err := CreateResource(s.MqlRuntime, "hetzner.network.exposure", map[string]*llx.RawData{
		"__id":                  llx.StringData(fmt.Sprintf("hetzner.server/%d/exposure", id.Data)),
		"internetReachable":     llx.BoolData(internetReachable),
		"hasPublicIp":           llx.BoolData(hasPublicIp),
		"firewallAllowsIngress": llx.BoolData(firewallAllowsIngress),
		"openIngressRules":      llx.ArrayData(openRules, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerNetworkExposure), nil
}

// loadBalancerHasPublicIp reports whether a Hetzner load balancer's public
// network is enabled and carries a public IPv4 or IPv6 address.
func loadBalancerHasPublicIp(pn hcloud.LoadBalancerPublicNet) bool {
	if !pn.Enabled {
		return false
	}
	return pn.IPv4.IP != nil || pn.IPv6.IP != nil
}

// loadBalancerServiceDicts renders a load balancer's forwarding services as
// dicts describing the public listeners that admit traffic from any address.
func loadBalancerServiceDicts(services []hcloud.LoadBalancerService) []any {
	out := make([]any, 0, len(services))
	for _, s := range services {
		out = append(out, map[string]any{
			"protocol":        string(s.Protocol),
			"listenPort":      int64(s.ListenPort),
			"destinationPort": int64(s.DestinationPort),
		})
	}
	return out
}

// exposure breaks down whether the load balancer is reachable from the internet.
// A Hetzner load balancer has no firewall; its public network being enabled with
// a public IP plus at least one forwarding service makes it internet-reachable.
func (m *mqlHetznerLoadBalancer) exposure() (*mqlHetznerNetworkExposure, error) {
	id := m.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	hasPublicIp := loadBalancerHasPublicIp(m.cachePublicNet)
	openRules := loadBalancerServiceDicts(m.cacheServices)
	servicesAllowIngress := len(openRules) > 0
	internetReachable := hasPublicIp && servicesAllowIngress

	res, err := CreateResource(m.MqlRuntime, "hetzner.network.exposure", map[string]*llx.RawData{
		"__id":                  llx.StringData(fmt.Sprintf("hetzner.loadBalancer/%d/exposure", id.Data)),
		"internetReachable":     llx.BoolData(internetReachable),
		"hasPublicIp":           llx.BoolData(hasPublicIp),
		"firewallAllowsIngress": llx.BoolData(servicesAllowIngress),
		"openIngressRules":      llx.ArrayData(openRules, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerNetworkExposure), nil
}
