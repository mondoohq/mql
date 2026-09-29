// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// openCIDRs are the source ranges that mean "the entire internet".
var openCIDRs = map[string]struct{}{
	"0.0.0.0/0": {},
	"::/0":      {},
}

// isOpenCIDR reports whether a CIDR string represents the whole internet
// (IPv4 0.0.0.0/0 or IPv6 ::/0). Surrounding whitespace is tolerated.
func isOpenCIDR(cidr string) bool {
	_, ok := openCIDRs[strings.TrimSpace(cidr)]
	return ok
}

// gkeControlPlaneInternetReachable derives whether a GKE cluster's control
// plane (Kubernetes API server) is reachable from the public internet.
//
// It is reachable when the public IP endpoint is enabled AND either:
//   - master authorized networks is NOT enforced (any source IP may connect), or
//   - the authorized-networks allowlist itself contains an open CIDR
//     (0.0.0.0/0 or ::/0), which whitelists the entire internet.
//
// When the public endpoint is disabled the control plane is private and never
// internet-reachable, regardless of the authorized-networks configuration.
func gkeControlPlaneInternetReachable(publicEndpointEnabled, authorizedNetworksEnforced bool, authorizedCIDRs []string) bool {
	if !publicEndpointEnabled {
		return false
	}
	if !authorizedNetworksEnforced {
		return true
	}
	for _, c := range authorizedCIDRs {
		if isOpenCIDR(c) {
			return true
		}
	}
	return false
}

func (g *mqlGcpProjectGkeServiceCluster) controlPlaneInternetReachable() (bool, error) {
	if g.ControlPlanePublicEndpointEnabled.Error != nil {
		return false, g.ControlPlanePublicEndpointEnabled.Error
	}
	if g.MasterAuthorizedNetworksAllowed.Error != nil {
		return false, g.MasterAuthorizedNetworksAllowed.Error
	}
	if g.MasterAuthorizedNetworksCidrs.Error != nil {
		return false, g.MasterAuthorizedNetworksCidrs.Error
	}

	cidrs := make([]string, 0, len(g.MasterAuthorizedNetworksCidrs.Data))
	for _, raw := range g.MasterAuthorizedNetworksCidrs.Data {
		if s, ok := raw.(string); ok {
			cidrs = append(cidrs, s)
		}
	}

	return gkeControlPlaneInternetReachable(
		g.ControlPlanePublicEndpointEnabled.Data,
		g.MasterAuthorizedNetworksAllowed.Data,
		cidrs,
	), nil
}

// firewallRuleOpenIngress reports whether a firewall rule admits inbound traffic
// from any address — an enabled INGRESS rule whose source ranges include
// 0.0.0.0/0 or ::/0.
func firewallRuleOpenIngress(isAllow bool, direction string, disabled bool, sourceRanges []any) bool {
	// A GCP VPC firewall rule is exclusively an allow rule or a deny rule. Only
	// allow rules can open ingress; a broad-source INGRESS deny rule (a common
	// "block all" pattern) must not be counted as reachable exposure.
	return isAllow && ingressFromInternet(direction, disabled, sourceRanges)
}

// openIngressPolicyRulesForInstance returns the network firewall policy rules
// that apply to an instance and admit ingress from any address.
//
// Only policies associated with one of the instance's networks are considered,
// because an unassociated policy enforces nothing. A regional policy is
// enforced only on instances in its region, so one from another region is
// skipped. When the instance's region is unknown every regional policy is
// kept, which can only over-report reachability, never hide it.
func openIngressPolicyRulesForInstance(
	svc *mqlGcpProjectComputeService,
	instanceRegion string,
	instanceNetworks, instanceServiceAccounts map[string]bool,
) ([]any, error) {
	policies := svc.GetFirewallPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}

	openRules := []any{}
	for _, p := range policies.Data {
		policy, ok := p.(*mqlGcpProjectComputeServiceFirewallPolicy)
		if !ok {
			continue
		}
		if !policyAppliesInRegion(policy.cacheRegionUrl, instanceRegion) {
			continue
		}
		associations := policy.GetAssociations()
		if associations.Error != nil {
			return nil, associations.Error
		}
		if !policyAppliesToNetworks(associations.Data, instanceNetworks) {
			continue
		}

		rules := policy.GetRules()
		if rules.Error != nil {
			return nil, rules.Error
		}
		for _, r := range rules.Data {
			rule, ok := r.(*mqlGcpProjectComputeServiceFirewallPolicyRule)
			if !ok {
				continue
			}
			action := rule.GetAction()
			if action.Error != nil {
				return nil, action.Error
			}
			direction := rule.GetDirection()
			if direction.Error != nil {
				return nil, direction.Error
			}
			disabled := rule.GetDisabled()
			if disabled.Error != nil {
				return nil, disabled.Error
			}
			srcIpRanges := rule.GetSrcIpRanges()
			if srcIpRanges.Error != nil {
				return nil, srcIpRanges.Error
			}
			if !policyRuleOpenIngress(action.Data, direction.Data, disabled.Data, srcIpRanges.Data) {
				continue
			}

			targetResources := rule.GetTargetResources()
			if targetResources.Error != nil {
				return nil, targetResources.Error
			}
			targetServiceAccounts := rule.GetTargetServiceAccounts()
			if targetServiceAccounts.Error != nil {
				return nil, targetServiceAccounts.Error
			}
			if policyRuleTargetsInstance(targetResources.Data, targetServiceAccounts.Data,
				instanceNetworks, instanceServiceAccounts) {
				openRules = append(openRules, rule)
			}
		}
	}
	return openRules, nil
}

// policyAppliesInRegion reports whether a network firewall policy is enforced
// on an instance in instanceRegion. A global policy (empty policyRegionUrl)
// applies everywhere; a regional one only in its own region. An unknown
// instance region keeps the policy.
func policyAppliesInRegion(policyRegionUrl, instanceRegion string) bool {
	if policyRegionUrl == "" || instanceRegion == "" {
		return true
	}
	return RegionNameFromRegionUrl(policyRegionUrl) == instanceRegion
}

// regionFromZoneName returns the region a zone belongs to, for example
// "us-central1" for "us-central1-a". It returns "" for a name that does not
// have the region-letter shape.
func regionFromZoneName(zone string) string {
	i := strings.LastIndex(zone, "-")
	if i <= 0 || i == len(zone)-1 {
		return ""
	}
	return zone[:i]
}

// policyRuleOpenIngress reports whether a network firewall policy rule admits
// ingress from the whole internet.
//
// Policy rules differ from legacy VPC firewall rules in two ways that matter
// here. Their effect is an `action` string rather than the presence of an allow
// block, and only "allow" opens traffic -- "deny", "goto_next" and
// "apply_security_profile_group" do not. And their sources live in
// `srcIpRanges` rather than `sourceRanges`.
func policyRuleOpenIngress(action, direction string, disabled bool, srcIpRanges []any) bool {
	if disabled || !strings.EqualFold(direction, "INGRESS") || !strings.EqualFold(action, "allow") {
		return false
	}
	for _, s := range srcIpRanges {
		if cidr, ok := s.(string); ok && isOpenCIDR(cidr) {
			return true
		}
	}
	return false
}

// policyRuleTargetsInstance reports whether a policy rule's targeting applies to
// an instance.
//
// The two fields are independent axes and compose with AND, which is what makes
// this different from the legacy rule above. targetResources holds network URLs
// and picks WHICH NETWORK the rule lands on; targetServiceAccounts picks WHICH
// INSTANCES within it. The API documents the composition on the sibling
// targetSecureTags field: "If neither targetServiceAccounts nor targetSecureTag
// are specified, the firewall rule applies to all instances on the specified
// network" -- the specified network being targetResources.
//
// So a rule with targetResources=[net-A] and targetServiceAccounts=[sa-B]
// applies only to instances in net-A running as sa-B. Treating the two as
// alternatives would report an instance in net-A running as sa-C as covered.
//
// An empty list on either axis means "all", so a rule with neither applies to
// every instance the policy reaches. Networks are compared by trailing name so a
// full URL and a partial reference match.
//
// The legacy firewallTargetsInstance above stays an OR for a real reason rather
// than an inconsistency: on a legacy VPC rule targetTags and
// targetServiceAccounts are mutually exclusive ("targetServiceAccounts cannot be
// used at the same time as targetTags"), so at most one is ever populated and
// the two spellings agree.
func policyRuleTargetsInstance(targetResources, targetServiceAccounts []any, instanceNetworks, instanceServiceAccounts map[string]bool) bool {
	networkMatch := len(targetResources) == 0
	for _, r := range targetResources {
		if url, ok := r.(string); ok && instanceNetworks[networkNameFromUrl(url)] {
			networkMatch = true
			break
		}
	}

	accountMatch := len(targetServiceAccounts) == 0
	for _, sa := range targetServiceAccounts {
		if email, ok := sa.(string); ok && instanceServiceAccounts[email] {
			accountMatch = true
			break
		}
	}

	return networkMatch && accountMatch
}

// policyAppliesToNetworks reports whether a firewall policy is associated with
// any of the instance's networks.
//
// A policy enforces nothing until it is associated with a network, so an
// unassociated policy must not contribute exposure no matter what its rules
// say. Each association is a dict whose attachmentTarget names the network.
func policyAppliesToNetworks(associations []any, instanceNetworks map[string]bool) bool {
	for _, a := range associations {
		assoc, ok := a.(map[string]any)
		if !ok {
			continue
		}
		target, ok := assoc["attachmentTarget"].(string)
		if !ok || target == "" {
			continue
		}
		if instanceNetworks[networkNameFromUrl(target)] {
			return true
		}
	}
	return false
}

// networkNameFromUrl returns the trailing network name from a GCP network URL or
// partial reference, so full URLs and short names compare equal.
func networkNameFromUrl(url string) string {
	if i := strings.LastIndex(url, "/networks/"); i >= 0 {
		return url[i+len("/networks/"):]
	}
	if i := strings.LastIndex(url, "/"); i >= 0 {
		return url[i+1:]
	}
	return url
}

// firewallTargetsInstance reports whether a firewall rule's targeting applies to
// an instance. A rule with no target tags and no target service accounts applies
// to every instance in its network; otherwise it applies only when a target tag
// or target service account matches the instance.
func firewallTargetsInstance(targetTags, targetServiceAccounts []any, instanceTags, instanceServiceAccounts map[string]bool) bool {
	if len(targetTags) == 0 && len(targetServiceAccounts) == 0 {
		return true
	}
	for _, t := range targetTags {
		if tag, ok := t.(string); ok && instanceTags[tag] {
			return true
		}
	}
	for _, sa := range targetServiceAccounts {
		if email, ok := sa.(string); ok && instanceServiceAccounts[email] {
			return true
		}
	}
	return false
}

// firewallProtocolAll is the wildcard protocol on a VPC firewall rule's layer 4
// match. Compute spells it "all".
const firewallProtocolAll = "all"

// gcpProtocolAliases folds the spellings a layer 4 match may carry onto one
// name, so an IANA protocol number and its name compare equal.
var gcpProtocolAliases = map[string]string{
	"1":       "icmp",
	"6":       "tcp",
	"17":      "udp",
	"47":      "gre",
	"50":      "esp",
	"51":      "ah",
	"58":      "ipv6-icmp",
	"94":      "ipip",
	"132":     "sctp",
	"icmpv6":  "ipv6-icmp",
	"icmp-v6": "ipv6-icmp",
}

// normalizeFirewallProtocol lowercases a protocol and resolves its numeric
// aliases. An absent protocol reads as the wildcard, which is how Compute treats
// a match that names none.
func normalizeFirewallProtocol(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if p == "" {
		return firewallProtocolAll
	}
	if name, ok := gcpProtocolAliases[p]; ok {
		return name
	}
	return p
}

// firewallProtocolCovers reports whether a rule for protocol outer matches every
// packet a rule for protocol inner matches. The wildcard covers everything;
// otherwise the two protocols must be the same.
func firewallProtocolCovers(outer, inner string) bool {
	o, i := normalizeFirewallProtocol(outer), normalizeFirewallProtocol(inner)
	return o == firewallProtocolAll || o == i
}

// firewallPortRange is an inclusive port span taken from one entry of a layer 4
// match's port list. all is true when the match names no ports at all, which
// Compute reads as every port of the protocol, and is also the only form
// protocols with no port concept (icmp, esp, ah) take.
type firewallPortRange struct {
	from int64
	to   int64
	all  bool
}

// parseFirewallPortSpec parses a single port entry, which is either one port
// ("22") or an inclusive range ("20-25"). Anything else returns false; a caller
// that cannot read a port must not pretend to know which ports it covers.
func parseFirewallPortSpec(spec string) (firewallPortRange, bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return firewallPortRange{}, false
	}
	low, high, isRange := strings.Cut(s, "-")
	if !isRange {
		high = low
	}
	from, err := strconv.ParseInt(strings.TrimSpace(low), 10, 64)
	if err != nil {
		return firewallPortRange{}, false
	}
	to, err := strconv.ParseInt(strings.TrimSpace(high), 10, 64)
	if err != nil {
		return firewallPortRange{}, false
	}
	if from > to {
		from, to = to, from
	}
	return firewallPortRange{from: from, to: to}, true
}

// covers reports whether every port in other falls inside r.
func (r firewallPortRange) covers(other firewallPortRange) bool {
	if r.all {
		return true
	}
	if other.all {
		// other spans every port; a bounded range cannot contain it.
		return false
	}
	return r.from <= other.from && r.to >= other.to
}

// firewallTraffic is one slice of the packets a firewall rule matches: an
// address family, a protocol, and a port span. A rule fans out into one entry
// per open source family and per port entry of its layer 4 match, because a
// deny only silences an allow for the traffic both of them match.
type firewallTraffic struct {
	ipv6     bool
	protocol string
	ports    firewallPortRange
}

// covers reports whether t matches every packet other matches.
//
// The address family is part of that: an IPv4 rule and an IPv6 rule never match
// the same packet, so a deny on 0.0.0.0/0 does not shadow an allow on ::/0.
func (t firewallTraffic) covers(other firewallTraffic) bool {
	if t.ipv6 != other.ipv6 {
		return false
	}
	if !firewallProtocolCovers(t.protocol, other.protocol) {
		return false
	}
	return t.ports.covers(other.ports)
}

// openSourceFamilies reports which address families a rule's source ranges open
// to the whole internet.
//
// Only the two all-address blocks count. A set of narrower ranges that together
// span the internet is not recognized, which leaves an allow rule counted as
// open and a deny rule counted as not covering: both err toward reporting an
// instance reachable.
func openSourceFamilies(sourceRanges []any) (v4 bool, v6 bool) {
	for _, s := range sourceRanges {
		cidr, ok := s.(string)
		if !ok {
			continue
		}
		switch strings.TrimSpace(cidr) {
		case "0.0.0.0/0":
			v4 = true
		case "::/0":
			v6 = true
		}
	}
	return v4, v6
}

// ingressFromInternet reports whether a firewall rule is an enabled INGRESS rule
// whose source ranges admit any address, without regard to whether it allows or
// denies that traffic.
func ingressFromInternet(direction string, disabled bool, sourceRanges []any) bool {
	if disabled || !strings.EqualFold(direction, "INGRESS") {
		return false
	}
	v4, v6 := openSourceFamilies(sourceRanges)
	return v4 || v6
}

// ingressTraffic expands a firewall rule into the internet-sourced traffic it
// matches: the cross product of the open address families in its source ranges
// and the port spans in its layer 4 match.
//
// widenUnreadable decides what an unreadable layer 4 match means, and the two
// callers need opposite answers. On an allow rule the match is the evidence of
// exposure, so an unreadable one widens to every protocol and port and the rule
// stays in the exposure list. On a deny rule the match is the evidence that
// traffic is blocked, so an unreadable one is dropped and the deny shadows
// nothing. Both directions keep an input that could not be read from reporting
// an instance as protected.
func ingressTraffic(sourceRanges []any, protocols map[string]any, widenUnreadable bool) []firewallTraffic {
	v4, v6 := openSourceFamilies(sourceRanges)
	families := []bool{}
	if v4 {
		families = append(families, false)
	}
	if v6 {
		families = append(families, true)
	}
	if len(families) == 0 {
		return nil
	}

	res := []firewallTraffic{}
	for _, ipv6 := range families {
		if len(protocols) == 0 {
			if widenUnreadable {
				res = append(res, firewallTraffic{ipv6: ipv6, protocol: firewallProtocolAll, ports: firewallPortRange{all: true}})
			}
			continue
		}
		for protocol, raw := range protocols {
			ports, ok := raw.([]any)
			if !ok || len(ports) == 0 {
				// A match that names no ports covers every port of the protocol.
				res = append(res, firewallTraffic{ipv6: ipv6, protocol: protocol, ports: firewallPortRange{all: true}})
				continue
			}
			parsed := 0
			for _, p := range ports {
				spec, ok := p.(string)
				if !ok {
					continue
				}
				span, ok := parseFirewallPortSpec(spec)
				if !ok {
					continue
				}
				parsed++
				res = append(res, firewallTraffic{ipv6: ipv6, protocol: protocol, ports: span})
			}
			if parsed == 0 && widenUnreadable {
				res = append(res, firewallTraffic{ipv6: ipv6, protocol: protocol, ports: firewallPortRange{all: true}})
			}
		}
	}
	return res
}

// allowIngressTraffic expands an allow rule's internet-sourced traffic.
func allowIngressTraffic(sourceRanges []any, protocols map[string]any) []firewallTraffic {
	return ingressTraffic(sourceRanges, protocols, true)
}

// denyIngressTraffic expands a deny rule's internet-sourced traffic.
func denyIngressTraffic(sourceRanges []any, protocols map[string]any) []firewallTraffic {
	return ingressTraffic(sourceRanges, protocols, false)
}

// firewallIngressRule is the shape of a VPC firewall rule needed to decide
// whether it leaves an instance reachable from the internet.
type firewallIngressRule struct {
	priority              int64
	direction             string
	disabled              bool
	allow                 bool
	network               string
	sourceRanges          []any
	protocols             map[string]any
	targetTags            []any
	targetServiceAccounts []any
}

// appliesToInstance reports whether the rule is enforced on an instance: it sits
// on one of the instance's networks and its targeting selects the instance.
func (r firewallIngressRule) appliesToInstance(instanceNetworks, instanceTags, instanceServiceAccounts map[string]bool) bool {
	if !instanceNetworks[networkNameFromUrl(r.network)] {
		return false
	}
	return firewallTargetsInstance(r.targetTags, r.targetServiceAccounts, instanceTags, instanceServiceAccounts)
}

// trafficIsCovered reports whether a single entry of covering matches every
// packet traffic matches.
//
// Coverage is asked of one entry at a time rather than of the union: several
// entries that jointly span a range do not count as covering it. Missing that
// case leaves an allow rule reported as open, which is the safe direction.
func trafficIsCovered(covering []firewallTraffic, traffic firewallTraffic) bool {
	for _, c := range covering {
		if c.covers(traffic) {
			return true
		}
	}
	return false
}

// ingressAllowSurvives reports whether any traffic an allow rule admits is left
// open by the deny rules that outrank it.
//
// Compute evaluates VPC firewall rules by priority, lowest number first, and the
// highest-priority rule matching a packet decides it. A deny at the same number
// also wins: "A rule with a deny action overrides another with an allow action
// only if the two rules have the same priority."
//
// Shadowing is decided per packet, so partial overlap is not shadowing. A deny
// on tcp/22 in front of an allow on tcp/1-1024 still leaves 1023 ports open, and
// a deny that covers only the IPv4 half of a dual-family allow still leaves the
// IPv6 half open.
func ingressAllowSurvives(allow firewallIngressRule, allowTraffic []firewallTraffic, denies []firewallIngressRule) bool {
	for _, traffic := range allowTraffic {
		shadowed := false
		for _, deny := range denies {
			if deny.priority > allow.priority {
				continue
			}
			if trafficIsCovered(denyIngressTraffic(deny.sourceRanges, deny.protocols), traffic) {
				shadowed = true
				break
			}
		}
		if !shadowed {
			return true
		}
	}
	return false
}

// unshadowedOpenIngressFirewalls returns the indexes of the rules that leave an
// instance reachable from the internet: enabled INGRESS allow rules with an
// all-address source that apply to the instance and are not fully shadowed by a
// deny rule of equal or lower priority number.
func unshadowedOpenIngressFirewalls(rules []firewallIngressRule, instanceNetworks, instanceTags, instanceServiceAccounts map[string]bool) []int {
	denies := []firewallIngressRule{}
	for _, r := range rules {
		if r.allow || !ingressFromInternet(r.direction, r.disabled, r.sourceRanges) {
			continue
		}
		if !r.appliesToInstance(instanceNetworks, instanceTags, instanceServiceAccounts) {
			continue
		}
		denies = append(denies, r)
	}

	open := []int{}
	for i, r := range rules {
		if !firewallRuleOpenIngress(r.allow, r.direction, r.disabled, r.sourceRanges) {
			continue
		}
		if !r.appliesToInstance(instanceNetworks, instanceTags, instanceServiceAccounts) {
			continue
		}
		if ingressAllowSurvives(r, allowIngressTraffic(r.sourceRanges, r.protocols), denies) {
			open = append(open, i)
		}
	}
	return open
}

func anyStringSet(items []any) map[string]bool {
	set := map[string]bool{}
	for _, i := range items {
		if s, ok := i.(string); ok && s != "" {
			set[s] = true
		}
	}
	return set
}

func (g *mqlGcpProjectComputeServiceInstance) exposure() (*mqlGcpProjectComputeServiceInstanceExposure, error) {
	id := g.GetId()
	if id.Error != nil {
		return nil, id.Error
	}
	hasPublicIp := g.GetHasPublicIp()
	if hasPublicIp.Error != nil {
		return nil, hasPublicIp.Error
	}
	projectId := g.GetProjectId()
	if projectId.Error != nil {
		return nil, projectId.Error
	}

	// Networks the instance is attached to.
	nics := g.GetNics()
	if nics.Error != nil {
		return nil, nics.Error
	}
	instanceNetworks := map[string]bool{}
	for _, n := range nics.Data {
		nic, ok := n.(*mqlGcpProjectComputeServiceInstanceNetworkInterface)
		if !ok {
			continue
		}
		if nic.cacheNetworkUrl != "" {
			instanceNetworks[networkNameFromUrl(nic.cacheNetworkUrl)] = true
		}
	}

	tags := g.GetTags()
	if tags.Error != nil {
		return nil, tags.Error
	}
	instanceTags := anyStringSet(tags.Data)

	serviceAccounts := g.GetServiceAccounts()
	if serviceAccounts.Error != nil {
		return nil, serviceAccounts.Error
	}
	instanceServiceAccounts := map[string]bool{}
	for _, s := range serviceAccounts.Data {
		sa, ok := s.(*mqlGcpProjectComputeServiceServiceaccount)
		if !ok {
			continue
		}
		email := sa.GetEmail()
		if email.Error != nil {
			return nil, email.Error
		}
		if email.Data != "" {
			instanceServiceAccounts[email.Data] = true
		}
	}

	svc, err := NewResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId.Data),
	})
	if err != nil {
		return nil, err
	}
	firewalls := svc.(*mqlGcpProjectComputeService).GetFirewalls()
	if firewalls.Error != nil {
		return nil, firewalls.Error
	}

	// Both the allow rules and the deny rules are collected, because a deny of
	// equal or lower priority number silences an allow for the traffic the two
	// share. Reading only the allow rules reports an instance behind a
	// higher-precedence deny as reachable.
	fws := []*mqlGcpProjectComputeServiceFirewall{}
	rules := []firewallIngressRule{}
	for _, f := range firewalls.Data {
		fw, ok := f.(*mqlGcpProjectComputeServiceFirewall)
		if !ok {
			continue
		}
		direction := fw.GetDirection()
		if direction.Error != nil {
			return nil, direction.Error
		}
		disabled := fw.GetDisabled()
		if disabled.Error != nil {
			return nil, disabled.Error
		}
		priority := fw.GetPriority()
		if priority.Error != nil {
			return nil, priority.Error
		}
		sourceRanges := fw.GetSourceRanges()
		if sourceRanges.Error != nil {
			return nil, sourceRanges.Error
		}
		allowed := fw.GetAllowed()
		if allowed.Error != nil {
			return nil, allowed.Error
		}
		allowedProtocols := fw.GetAllowedProtocols()
		if allowedProtocols.Error != nil {
			return nil, allowedProtocols.Error
		}
		deniedProtocols := fw.GetDeniedProtocols()
		if deniedProtocols.Error != nil {
			return nil, deniedProtocols.Error
		}
		targetTags := fw.GetTargetTags()
		if targetTags.Error != nil {
			return nil, targetTags.Error
		}
		targetServiceAccounts := fw.GetTargetServiceAccounts()
		if targetServiceAccounts.Error != nil {
			return nil, targetServiceAccounts.Error
		}

		// A rule carries either allow entries or deny entries, never both.
		isAllow := len(allowed.Data) > 0
		protocols := deniedProtocols.Data
		if isAllow {
			protocols = allowedProtocols.Data
		}

		fws = append(fws, fw)
		rules = append(rules, firewallIngressRule{
			priority:              priority.Data,
			direction:             direction.Data,
			disabled:              disabled.Data,
			allow:                 isAllow,
			network:               fw.cacheNetworkUrl,
			sourceRanges:          sourceRanges.Data,
			protocols:             protocols,
			targetTags:            targetTags.Data,
			targetServiceAccounts: targetServiceAccounts.Data,
		})
	}

	openFirewalls := []any{}
	for _, i := range unshadowedOpenIngressFirewalls(rules, instanceNetworks, instanceTags, instanceServiceAccounts) {
		openFirewalls = append(openFirewalls, fws[i])
	}

	// Network firewall policies are the second, newer way a VPC admits traffic,
	// and they are evaluated ahead of the legacy rules above. A VPC migrated to
	// them can have no legacy rules at all, in which case reading only those
	// reports internetReachable: false for a genuinely reachable instance.
	instanceRegion := ""
	if zone := g.GetZone(); zone.Error == nil && zone.Data != nil && zone.Data.Name.Error == nil {
		instanceRegion = regionFromZoneName(zone.Data.Name.Data)
	}
	openPolicyRules, err := openIngressPolicyRulesForInstance(
		svc.(*mqlGcpProjectComputeService), instanceRegion, instanceNetworks, instanceServiceAccounts)
	if err != nil {
		return nil, err
	}

	firewallAllowsIngress := len(openFirewalls) > 0 || len(openPolicyRules) > 0
	internetReachable := hasPublicIp.Data && firewallAllowsIngress

	res, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.instance.exposure", map[string]*llx.RawData{
		"__id":                   llx.StringData("gcp.project.computeService.instance/" + id.Data + "/exposure"),
		"internetReachable":      llx.BoolData(internetReachable),
		"hasPublicIp":            llx.BoolData(hasPublicIp.Data),
		"firewallAllowsIngress":  llx.BoolData(firewallAllowsIngress),
		"openIngressFirewalls":   llx.ArrayData(openFirewalls, types.Resource("gcp.project.computeService.firewall")),
		"openIngressPolicyRules": llx.ArrayData(openPolicyRules, types.Resource("gcp.project.computeService.firewallPolicy.rule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceInstanceExposure), nil
}

// internetReachable reports whether the Cloud SQL instance is reachable from the
// internet: it has a public IP and an authorized network that admits any address
// (0.0.0.0/0). Reuses the existing publicIpEnabled and hasOpenAuthorizedNetworks
// signals.
func (g *mqlGcpProjectSqlServiceInstance) internetReachable() (bool, error) {
	public := g.GetPublicIpEnabled()
	if public.Error != nil {
		return false, public.Error
	}
	if !public.Data {
		return false, nil
	}
	settings := g.GetSettings()
	if settings.Error != nil {
		return false, settings.Error
	}
	if settings.Data == nil {
		return false, nil
	}
	ipConfig := settings.Data.GetIpConfiguration()
	if ipConfig.Error != nil {
		return false, ipConfig.Error
	}
	if ipConfig.Data == nil {
		return false, nil
	}
	open := ipConfig.Data.GetHasOpenAuthorizedNetworks()
	if open.Error != nil {
		return false, open.Error
	}
	return open.Data, nil
}
