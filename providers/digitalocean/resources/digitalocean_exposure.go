// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// anyAddressCIDRs are the CIDR notations that mean "every address" — an
// open-to-the-internet source for either IP stack.
var anyAddressCIDRs = map[string]struct{}{
	"0.0.0.0/0": {},
	"::/0":      {},
}

// isAnyAddress reports whether a CIDR/IP string admits every address. Bare
// "0.0.0.0" / "::" (without a prefix) are also treated as any-address since
// DigitalOcean accepts them as wildcard sources.
func isAnyAddress(cidr string) bool {
	c := strings.TrimSpace(cidr)
	if _, ok := anyAddressCIDRs[c]; ok {
		return true
	}
	return c == "0.0.0.0" || c == "::"
}

// addressesCoverInternet reports whether a list of source addresses admits
// every internet address: the IPv4 entries together cover 0.0.0.0/0, or the
// IPv6 entries together cover ::/0. Split ranges such as 0.0.0.0/1 plus
// 128.0.0.0/1 count as open, which matters because DigitalOcean rejects a /0
// mask on some resources (database trusted sources) but accepts the halves.
// A broad prefix that leaves any address out, such as a /8, does not.
//
// Entries may carry the "cidr:" or "ip:" prefix that load balancer firewall
// rules use. A bare address is a single host, except the unspecified
// addresses "0.0.0.0" and "::", which isAnyAddress treats as wildcards. An
// entry that does not parse counts as open, so a value this function cannot
// read never reads as restricted. An empty list admits nothing; callers
// decide what an empty list means for their resource.
func addressesCoverInternet(addresses []string) bool {
	var v4, v6 []netip.Prefix
	for _, a := range addresses {
		s := strings.TrimSpace(a)
		if i := strings.IndexByte(s, ':'); i > 0 {
			switch strings.ToLower(s[:i]) {
			case "cidr", "ip":
				s = strings.TrimSpace(s[i+1:])
			}
		}
		if isAnyAddress(s) {
			return true
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			addr, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return true
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		p = p.Masked()
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return prefixesCoverAll(v4, netip.IPv4Unspecified()) ||
		prefixesCoverAll(v6, netip.IPv6Unspecified())
}

// prefixesCoverAll reports whether the prefixes, taken together, cover every
// address from first to the end of its address family.
func prefixesCoverAll(prefixes []netip.Prefix, first netip.Addr) bool {
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		return a.Addr().Compare(b.Addr())
	})
	next := first
	for _, p := range prefixes {
		if next.Less(p.Addr()) {
			return false
		}
		last := lastAddr(p)
		if !last.Less(next) {
			if !last.Next().IsValid() {
				return true
			}
			next = last.Next()
		}
	}
	return false
}

// lastAddr returns the highest address inside a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// stringEntries returns the string elements of a list, skipping any other
// type.
func stringEntries(list []any) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// databaseRuleOpensToInternet reports whether a single managed-database
// trusted-source rule admits traffic from any address. Only ip_addr rules can
// reference a CIDR; droplet/k8s/tag/app rules scope to specific resources and
// never open the cluster to the whole internet.
func databaseRuleOpensToInternet(ruleType, value string) bool {
	if ruleType != "ip_addr" {
		return false
	}
	return addressesCoverInternet([]string{value})
}

// databaseTrustedSourcesAllowAny inspects a managed database's trusted-source
// (firewall) rules and reports whether the public endpoint is open to any
// address. When no rules are configured at all DigitalOcean leaves the public
// connection endpoint reachable from every address, so an empty rule set also
// counts as open. The ip_addr rules are evaluated together, since the API
// rejects a /0 mask but accepts ranges that add up to the whole internet.
func databaseTrustedSourcesAllowAny(rules []any) bool {
	if len(rules) == 0 {
		return true
	}
	var addresses []string
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		ruleType, _ := rule["type"].(string)
		value, _ := rule["value"].(string)
		if ruleType == "ip_addr" {
			addresses = append(addresses, value)
		}
	}
	return len(addresses) > 0 && addressesCoverInternet(addresses)
}

// loadBalancerFirewallAllowsAny reports whether a load balancer's source
// firewall admits traffic from any address. The load balancer firewall is an
// allow/deny list of sources written as "cidr:<range>" or "ip:<address>":
// when the allow list is empty every source is permitted (subject to the deny
// list); when it is non-empty only those sources are permitted, so it is open
// to the internet only if its entries together cover every address.
func loadBalancerFirewallAllowsAny(allow []any) bool {
	if len(allow) == 0 {
		return true
	}
	return addressesCoverInternet(stringEntries(allow))
}

// exposure breaks down whether the droplet is reachable from the internet: a
// public IP combined with firewall ingress that admits any address. A droplet
// with no firewall attached is fully open, so missingFirewall counts as
// admitting ingress.
func (d *mqlDigitaloceanDroplet) exposure() (*mqlDigitaloceanNetworkExposure, error) {
	id := d.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	ipv4 := d.GetPublicIpv4()
	if ipv4.Error != nil {
		return nil, ipv4.Error
	}
	ipv6 := d.GetPublicIpv6()
	if ipv6.Error != nil {
		return nil, ipv6.Error
	}
	hasPublicIp := ipv4.Data != "" || ipv6.Data != ""

	missingFirewall := d.GetMissingFirewall()
	if missingFirewall.Error != nil {
		return nil, missingFirewall.Error
	}

	openRules := []any{}
	firewalls := d.GetFirewalls()
	if firewalls.Error != nil {
		return nil, firewalls.Error
	}
	for _, f := range firewalls.Data {
		fw, ok := f.(*mqlDigitaloceanFirewall)
		if !ok {
			continue
		}
		rules := fw.GetIngressRules()
		if rules.Error != nil {
			return nil, rules.Error
		}
		for _, r := range rules.Data {
			rule, ok := r.(*mqlDigitaloceanFirewallIngressRule)
			if !ok {
				continue
			}
			open := rule.GetOpenToInternet()
			if open.Error != nil {
				return nil, open.Error
			}
			if open.Data {
				openRules = append(openRules, rule)
			}
		}
	}

	firewallAllowsIngress := missingFirewall.Data || len(openRules) > 0
	internetReachable := hasPublicIp && firewallAllowsIngress

	res, err := CreateResource(d.MqlRuntime, "digitalocean.network.exposure", map[string]*llx.RawData{
		"__id":                  llx.StringData(fmt.Sprintf("digitalocean.droplet/%d/exposure", id.Data)),
		"internetReachable":     llx.BoolData(internetReachable),
		"hasPublicIp":           llx.BoolData(hasPublicIp),
		"firewallAllowsIngress": llx.BoolData(firewallAllowsIngress),
		"openIngressRules":      llx.ArrayData(openRules, types.Resource("digitalocean.firewall.ingressRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanNetworkExposure), nil
}

// internetReachable reports whether a managed database cluster is reachable
// from the internet: it has a public connection endpoint and its trusted-source
// firewall rules admit any address (or no rules are configured, which leaves
// the public endpoint open to every address). Managed databases use an
// authorized-networks model rather than droplet-style cloud firewalls, so this
// is a single predicate rather than the full network.exposure breakdown.
func (d *mqlDigitaloceanDatabase) internetReachable() (bool, error) {
	host := d.GetConnectionHost()
	if host.Error != nil {
		return false, host.Error
	}
	// No public connection endpoint means the cluster is private-only.
	if host.Data == "" {
		return false, nil
	}

	rules := d.GetFirewallRules()
	if rules.Error != nil {
		return false, rules.Error
	}

	return databaseTrustedSourcesAllowAny(rules.Data), nil
}

// exposure breaks down whether a load balancer is reachable from the internet:
// an EXTERNAL (internet-facing) load balancer has a public IP, and its source
// firewall admits traffic from any address (an empty allow list, or an allow
// entry that is itself an any-address CIDR). INTERNAL load balancers serve
// VPC-only traffic and are not internet-reachable.
func (l *mqlDigitaloceanLoadBalancer) exposure() (*mqlDigitaloceanNetworkExposure, error) {
	id := l.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	network := l.GetNetwork()
	if network.Error != nil {
		return nil, network.Error
	}

	ipv4 := l.GetIp()
	if ipv4.Error != nil {
		return nil, ipv4.Error
	}
	ipv6 := l.GetIpv6()
	if ipv6.Error != nil {
		return nil, ipv6.Error
	}
	// An INTERNAL load balancer is VPC-only; treat its address as non-public
	// even though the API may still report an IP.
	internalOnly := strings.EqualFold(network.Data, "INTERNAL")
	hasPublicIp := !internalOnly && (ipv4.Data != "" || ipv6.Data != "")

	allow := l.GetFirewallAllow()
	if allow.Error != nil {
		return nil, allow.Error
	}
	firewallAllowsIngress := loadBalancerFirewallAllowsAny(allow.Data)

	internetReachable := hasPublicIp && firewallAllowsIngress

	res, err := CreateResource(l.MqlRuntime, "digitalocean.network.exposure", map[string]*llx.RawData{
		"__id":                  llx.StringData(fmt.Sprintf("digitalocean.loadBalancer/%s/exposure", id.Data)),
		"internetReachable":     llx.BoolData(internetReachable),
		"hasPublicIp":           llx.BoolData(hasPublicIp),
		"firewallAllowsIngress": llx.BoolData(firewallAllowsIngress),
		// openIngressRules are droplet cloud-firewall rules; load balancers use
		// a source allow/deny list instead, so this is always empty for them.
		"openIngressRules": llx.ArrayData([]any{}, types.Resource("digitalocean.firewall.ingressRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanNetworkExposure), nil
}

// exposure breaks down whether the cluster's API server is reachable from the
// internet. A managed control plane is published on a public endpoint, so it
// answers every address unless the control-plane firewall is enabled and its
// allowed source addresses exclude the internet. An unset firewall flag counts
// as "no firewall", which reports the cluster as reachable rather than quietly
// clearing it on missing data.
func (c *mqlDigitaloceanKubernetesCluster) exposure() (*mqlDigitaloceanNetworkExposure, error) {
	id := c.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	endpoint := c.GetEndpoint()
	if endpoint.Error != nil {
		return nil, endpoint.Error
	}
	ipv4 := c.GetIpv4()
	if ipv4.Error != nil {
		return nil, ipv4.Error
	}
	hasPublicIp := endpoint.Data != "" || ipv4.Data != ""

	firewallEnabled := c.GetControlPlaneFirewallEnabled()
	if firewallEnabled.Error != nil {
		return nil, firewallEnabled.Error
	}
	allowed := c.GetControlPlaneFirewallAllowedAddresses()
	if allowed.Error != nil {
		return nil, allowed.Error
	}

	firewallAllowsIngress := !firewallEnabled.Data || anyAddressInList(allowed.Data)
	internetReachable := hasPublicIp && firewallAllowsIngress

	res, err := CreateResource(c.MqlRuntime, "digitalocean.network.exposure", map[string]*llx.RawData{
		"__id":                  llx.StringData("digitalocean.kubernetes.cluster/" + id.Data + "/exposure"),
		"internetReachable":     llx.BoolData(internetReachable),
		"hasPublicIp":           llx.BoolData(hasPublicIp),
		"firewallAllowsIngress": llx.BoolData(firewallAllowsIngress),
		// The control-plane firewall is a source address list rather than a set
		// of cloud-firewall rules, so there are no ingress rules to report.
		"openIngressRules": llx.ArrayData([]any{}, types.Resource("digitalocean.firewall.ingressRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanNetworkExposure), nil
}

// anyAddressInList reports whether a list of source CIDRs admits every address.
func anyAddressInList(addresses []any) bool {
	return addressesCoverInternet(stringEntries(addresses))
}

// spacesPolicyGrantsWildcard reports whether a parsed bucket policy has an Allow
// statement naming the wildcard principal. The policy arrives as decoded JSON,
// so every step uses the comma-ok form: an unparseable policy is stored as a
// plain string, and a hand-written document can put any shape in any field.
func spacesPolicyGrantsWildcard(policy any) bool {
	doc, ok := policy.(map[string]any)
	if !ok {
		return false
	}
	for _, statement := range asSlice(doc["Statement"]) {
		s, ok := statement.(map[string]any)
		if !ok {
			continue
		}
		effect, _ := s["Effect"].(string)
		if !strings.EqualFold(effect, "Allow") {
			continue
		}
		if principalIsWildcard(s["Principal"]) {
			return true
		}
	}
	return false
}

// principalIsWildcard reports whether a policy principal names "*". A principal
// is either the bare string "*" or a map keyed by principal type, whose values
// are a single string or a list of them.
func principalIsWildcard(principal any) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case map[string]any:
		for _, v := range p {
			for _, entry := range asSlice(v) {
				if s, ok := entry.(string); ok && s == "*" {
					return true
				}
			}
		}
	}
	return false
}

// asSlice normalizes a JSON field that may hold either a single value or a list
// into a list, so callers can iterate it either way.
func asSlice(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	default:
		return []any{v}
	}
}

// hasWildcardPolicy reports whether the bucket policy allows the wildcard
// principal, which grants the action to every requester.
func (b *mqlDigitaloceanSpacesBucket) hasWildcardPolicy() (bool, error) {
	policy := b.GetPolicy()
	if policy.Error != nil {
		return false, policy.Error
	}
	// A policy that was never read is not a policy that grants nothing.
	if !b.policyRead {
		b.HasWildcardPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return spacesPolicyGrantsWildcard(policy.Data), nil
}

// isPublic reports whether the bucket's contents are reachable by anyone on the
// internet: a public ACL grant or a wildcard bucket policy, with public access
// not blocked.
//
// The authenticated-users grant counts as public because it covers every
// account on the platform rather than only this one. publicAccessBlocked is
// only true when all four block-public-access settings are on, so a bucket with
// a public grant and partial blocking is reported as public rather than
// silently cleared. On DigitalOcean that field is null, because Spaces has no
// block-public-access control at all, and a control that does not exist
// cannot clear a public grant either: the verdict rests on the ACL and the
// policy.
func (b *mqlDigitaloceanSpacesBucket) isPublic() (bool, error) {
	blocked := b.GetPublicAccessBlocked()
	if blocked.Error != nil {
		return false, blocked.Error
	}
	if blocked.State&plugin.StateIsNull == 0 && blocked.Data {
		return false, nil
	}

	publicRead := b.GetPublicReadAcl()
	if publicRead.Error != nil {
		return false, publicRead.Error
	}
	publicWrite := b.GetPublicWriteAcl()
	if publicWrite.Error != nil {
		return false, publicWrite.Error
	}
	authenticatedRead := b.GetAuthenticatedReadAcl()
	if authenticatedRead.Error != nil {
		return false, authenticatedRead.Error
	}
	wildcardPolicy := b.GetHasWildcardPolicy()
	if wildcardPolicy.Error != nil {
		return false, wildcardPolicy.Error
	}

	// Any grant that was actually read and is public settles it, whatever else
	// could not be read.
	signals := []*plugin.TValue[bool]{publicRead, publicWrite, authenticatedRead, wildcardPolicy}
	unknown := false
	for _, s := range signals {
		if s.State&plugin.StateIsNull != 0 {
			unknown = true
			continue
		}
		if s.Data {
			return true, nil
		}
	}

	// Nothing read said public, but something was not read. Reporting false
	// here would clear the bucket on the strength of an answer nobody gave.
	if unknown {
		b.IsPublic.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return false, nil
}

// isPublic reports whether anyone on the internet can invoke the action: it is
// published as a web endpoint and does not require an API key.
func (a *mqlDigitaloceanFunctionAction) isPublic() (bool, error) {
	webExported := a.GetWebExported()
	if webExported.Error != nil {
		return false, webExported.Error
	}
	requiresApiKey := a.GetRequiresApiKey()
	if requiresApiKey.Error != nil {
		return false, requiresApiKey.Error
	}
	return webExported.Data && !requiresApiKey.Data, nil
}

// isPublic reports whether the agent's deployment answers anyone on the
// internet. DigitalOcean spells the visibility either as a bare "public" or as
// a "VISIBILITY_PUBLIC" enum name depending on the endpoint, so the check looks
// for the word rather than matching one spelling.
func (a *mqlDigitaloceanGradientaiAgent) isPublic() (bool, error) {
	visibility := a.GetDeploymentVisibility()
	if visibility.Error != nil {
		return false, visibility.Error
	}
	return strings.Contains(strings.ToLower(visibility.Data), "public"), nil
}

// publiclyRoutedComponents are the app spec component lists App Platform serves
// over HTTP. Workers and jobs run without a public route.
var publiclyRoutedComponents = []string{"services", "staticSites", "functions"}

// isPublic reports whether the app serves traffic to the internet: it has a
// live URL or a default ingress hostname, and its spec declares at least one
// publicly routed component.
func (a *mqlDigitaloceanApp) isPublic() (bool, error) {
	liveUrl := a.GetLiveUrl()
	if liveUrl.Error != nil {
		return false, liveUrl.Error
	}
	defaultIngress := a.GetDefaultIngress()
	if defaultIngress.Error != nil {
		return false, defaultIngress.Error
	}
	if liveUrl.Data == "" && defaultIngress.Data == "" {
		return false, nil
	}

	spec := a.GetSpec()
	if spec.Error != nil {
		return false, spec.Error
	}
	s, ok := spec.Data.(map[string]any)
	if !ok {
		return false, nil
	}
	for _, key := range publiclyRoutedComponents {
		if len(asSlice(s[key])) > 0 {
			return true, nil
		}
	}
	return false, nil
}
