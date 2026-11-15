// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"cmp"
	"fmt"
	"net"
	"slices"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// firewallRuleOpenToInternet reports whether a Hetzner firewall rule dict is an
// inbound rule whose source admits the internet: 0.0.0.0/0, ::/0, or ranges
// that together count as the same thing (see sourcesAdmitInternet).
func firewallRuleOpenToInternet(rule map[string]any) bool {
	if direction, _ := rule["direction"].(string); direction != "in" {
		return false
	}
	sources, ok := rule["sourceIps"].([]any)
	if !ok {
		return false
	}
	nets := make([]net.IPNet, 0, len(sources))
	for _, s := range sources {
		cidr, ok := s.(string)
		if !ok {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, *ipNet)
		}
	}
	return sourcesAdmitInternet(nets)
}

// sourcesAdmitInternet reports whether a rule's source ranges, taken together,
// admit a large part of the internet in either address family.
//
// 0.0.0.0/0 and ::/0 are the common case, but 0.0.0.0/1 plus 128.0.0.0/1,
// 2000::/3, or 256 adjacent /8s admit every internet host just the same, and so
// does a list of many narrow ranges whose union covers most of the address
// space. The verdict therefore depends on the union of the ranges, not on how
// they are written. A family is open when that union, restricted to the space
// internet hosts send from (IPv4 outside 224.0.0.0/3, IPv6 inside 2000::/3),
// either:
//
//   - contains an aligned IPv4 /7 or IPv6 /11, the next size up from the blocks
//     IANA allocates to the regional registries, or
//   - covers at least half of that space, however it is scattered.
//
// Private ranges never qualify on the first test: 10.0.0.0/8 is not a /7, and
// fc00::/7 lies outside 2000::/3. IPv6 ranges longer than /64 are ignored, since
// no realistic number of them adds up to either threshold, and so are IPv4
// ranges written as IPv4-mapped IPv6.
func sourcesAdmitInternet(nets []net.IPNet) bool {
	var spans4, spans6 []addrSpan
	for _, n := range nets {
		span, v4, ok := ipNetSpan(n)
		switch {
		case !ok:
		case v4:
			spans4 = append(spans4, span)
		default:
			spans6 = append(spans6, span)
		}
	}
	return ipv4InternetSpace.admittedBy(spans4) || ipv6InternetSpace.admittedBy(spans6)
}

// addrSpan is an inclusive range of addresses. IPv4 spans hold the 32-bit
// address; IPv6 spans hold the top 64 bits, so one unit is a /64.
type addrSpan struct{ lo, hi uint64 }

// ipNetSpan converts a network to the span it covers and reports its family.
// It reports false for an IPv6 network longer than /64, an IPv4-mapped IPv6
// network, or a malformed mask.
func ipNetSpan(n net.IPNet) (addrSpan, bool, bool) {
	ones, bits := n.Mask.Size()
	switch bits {
	case 32:
		ip := n.IP.Mask(n.Mask).To4()
		if ip == nil {
			return addrSpan{}, false, false
		}
		lo := uint64(ip[0])<<24 | uint64(ip[1])<<16 | uint64(ip[2])<<8 | uint64(ip[3])
		return addrSpan{lo, lo + (uint64(1) << (32 - ones)) - 1}, true, true
	case 128:
		ip := n.IP.Mask(n.Mask)
		if len(ip) != net.IPv6len || n.IP.To4() != nil || ones > 64 {
			return addrSpan{}, false, false
		}
		if ones == 0 {
			return addrSpan{0, ^uint64(0)}, false, true
		}
		var lo uint64
		for _, x := range ip[:8] {
			lo = lo<<8 | uint64(x)
		}
		return addrSpan{lo, lo + (uint64(1) << (64 - ones)) - 1}, false, true
	}
	return addrSpan{}, false, false
}

// mergeSpans returns the union of spans as sorted, disjoint, non-adjacent spans.
func mergeSpans(spans []addrSpan) []addrSpan {
	sorted := slices.Clone(spans)
	slices.SortFunc(sorted, func(a, b addrSpan) int { return cmp.Compare(a.lo, b.lo) })
	out := []addrSpan{}
	for _, sp := range sorted {
		if n := len(out); n > 0 && (sp.lo <= out[n-1].hi || sp.lo-out[n-1].hi == 1) {
			out[n-1].hi = max(out[n-1].hi, sp.hi)
			continue
		}
		out = append(out, sp)
	}
	return out
}

// internetSpace is the part of an address family internet hosts send from, in
// addrSpan units, with the block size whose presence alone counts as open.
type internetSpace struct {
	lo, hi uint64
	block  uint64
}

var (
	// IPv4 outside 224.0.0.0/3 (multicast plus the reserved 240.0.0.0/4); the
	// block is a /7.
	ipv4InternetSpace = internetSpace{lo: 0, hi: 224<<24 - 1, block: 1 << 25}
	// IPv6 2000::/3, the space routed on the internet, in /64 units; the block
	// is a /11.
	ipv6InternetSpace = internetSpace{lo: 0x2000 << 48, hi: 0x3fff_ffff_ffff_ffff, block: 1 << 53}
)

// admittedBy reports whether the union of spans opens this space to the
// internet: it contains an aligned block, or covers at least half the space.
func (s internetSpace) admittedBy(spans []addrSpan) bool {
	var total uint64
	for _, sp := range mergeSpans(spans) {
		lo, hi := max(sp.lo, s.lo), min(sp.hi, s.hi)
		if lo > hi {
			continue
		}
		total += hi - lo + 1
		// s.lo is block-aligned, so the first aligned block at or after lo
		// starts here.
		start := (lo + s.block - 1) / s.block * s.block
		if start <= hi && hi-start >= s.block-1 {
			return true
		}
	}
	return total >= (s.hi-s.lo+1)/2
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
