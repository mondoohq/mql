// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"math"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// --- Pure helpers (table-tested in azure_exposure_test.go) ---

// isInternetOpenSourcePrefix reports whether a single NSG source address prefix
// represents "any internet source". An inbound Allow rule whose source matches
// one of these exposes the destination to the public internet.
//
// The named forms are Azure's own vocabulary:
//   - "*" / "any"  wildcard, any source
//   - "internet"   the Azure "Internet" service tag (everything outside the VNet)
//
// Everything else is parsed as a prefix rather than string-compared, so any
// zero-length prefix counts -- "0.0.0.0/0" and "::/0", but equally "0.0.0.0/0 "
// or an IPv6 form written out in full. A string compare recognized only the two
// canonical spellings, and a rule written any other way read as closed.
//
// Note this deliberately answers only for ONE prefix. A source list can cover
// the whole internet without any single entry doing so -- see
// prefixesCoverInternet.
func isInternetOpenSourcePrefix(prefix string) bool {
	p := strings.ToLower(strings.TrimSpace(prefix))
	switch p {
	case "*", "any", "internet":
		return true
	}
	parsed, err := netip.ParsePrefix(p)
	if err != nil {
		return false
	}
	return parsed.Bits() == 0
}

// prefixesCoverInternet reports whether a set of source prefixes together cover
// the whole public address space, even though no single entry does.
//
// The case that matters is the split-halves form -- ["0.0.0.0/1",
// "128.0.0.0/1"] -- which is all of IPv4 written as two prefixes. It is a
// common way to express "any" and it defeats a per-entry check: every entry
// looks like an ordinary CIDR, so an NSG opened this way read as closed and the
// resource behind it reported internetReachable: false.
//
// The aggregation is IPv4 only. A prefix that is open on its own is caught for
// either family, so "::/0" still reports true, but IPv6 prefixes are not summed
// against each other: an all-of-IPv6 set written as ["::/1", "8000::/1"] is not
// recognized. The split-halves spelling exists to get past tooling that rejects
// 0.0.0.0/0, which is an IPv4 habit, so that gap has not been worth 128-bit
// range math.
func prefixesCoverInternet(prefixes []string) bool {
	var ranges []ipRange
	for _, p := range prefixes {
		if isInternetOpenSourcePrefix(p) {
			return true
		}
		r, ok := ipv4PrefixRange(p)
		if !ok {
			continue
		}
		ranges = append(ranges, r)
	}
	return rangesCoverAllIPv4(ranges)
}

// ipRange is an inclusive [lo, hi] IPv4 range held as unsigned integers.
type ipRange struct{ lo, hi uint64 }

func ipv4ToUint(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ipv4PrefixRange parses an IPv4 CIDR into the address range it covers. A
// prefix that does not parse, or that is not IPv4, is reported as unusable
// rather than as an empty range.
func ipv4PrefixRange(cidr string) (ipRange, bool) {
	parsed, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !parsed.Addr().Is4() {
		return ipRange{}, false
	}
	lo := uint64(ipv4ToUint(parsed.Masked().Addr()))
	size := uint64(1) << (32 - parsed.Bits())
	return ipRange{lo: lo, hi: lo + size - 1}, true
}

// mergeIPv4Ranges sorts the ranges and coalesces the ones that overlap or
// touch, returning disjoint ranges in ascending order. Inverted ranges admit
// nothing and are dropped.
//
// Every question asked of a SET of ranges -- does it span the whole space, how
// much of the internet does it admit -- is a question about the union, so the
// union is computed once here rather than reimplemented per caller. The input
// slice is copied: the caller's ranges are often the resource's own rule list
// and reordering it under them is not this function's business.
func mergeIPv4Ranges(ranges []ipRange) []ipRange {
	sorted := make([]ipRange, 0, len(ranges))
	for _, r := range ranges {
		if r.hi < r.lo {
			continue
		}
		sorted = append(sorted, r)
	}
	if len(sorted) == 0 {
		return nil
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].lo != sorted[j].lo {
			return sorted[i].lo < sorted[j].lo
		}
		return sorted[i].hi < sorted[j].hi
	})

	merged := []ipRange{sorted[0]}
	for _, r := range sorted[1:] {
		last := &merged[len(merged)-1]
		// a gap of even one address starts a new range; touching ranges merge
		if r.lo > last.hi+1 {
			merged = append(merged, r)
			continue
		}
		if r.hi > last.hi {
			last.hi = r.hi
		}
	}
	return merged
}

// rangesCoverAllIPv4 reports whether the ranges together span the entire IPv4
// address space.
func rangesCoverAllIPv4(ranges []ipRange) bool {
	merged := mergeIPv4Ranges(ranges)
	return len(merged) == 1 && merged[0].lo == 0 && merged[0].hi >= math.MaxUint32
}

// nonRoutableIPv4Blocks are the IPv4 blocks that are not part of the public
// internet: the special-purpose registry entries, multicast, and the reserved
// top of the space. Ascending and disjoint.
//
// A firewall range is judged by how much of the PUBLIC internet it admits, so
// these are discounted from that measure. Counting them made the threshold
// depend on address space nobody can reach a database from: a rule spanning
// 1.0.0.0 to 255.255.255.255, the whole routable internet, fell short of a raw
// half-of-IPv4 test by the size of 0.0.0.0/8 and scored as an allowlist.
var nonRoutableIPv4Blocks = ipv4Blocks(
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // 6to4 relay anycast
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, including the broadcast address
)

// routableIPv4Total is how many addresses are left once the non-routable blocks
// are removed: the size of the public IPv4 internet.
var routableIPv4Total = func() uint64 {
	total := uint64(1) << 32
	for _, b := range nonRoutableIPv4Blocks {
		total -= b.hi - b.lo + 1
	}
	return total
}()

// ipv4Blocks parses the fixed CIDR list above into sorted ranges. An entry that
// does not parse is dropped rather than panicking the provider at load; the
// resulting block count and total are pinned by a unit test, so a typo fails
// there instead of quietly shrinking the reserved space.
func ipv4Blocks(cidrs ...string) []ipRange {
	out := make([]ipRange, 0, len(cidrs))
	for _, c := range cidrs {
		if r, ok := ipv4PrefixRange(c); ok {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].lo < out[j].lo })
	return out
}

// ipv4RoutableCoverage counts how many public internet addresses the union of
// the ranges admits.
func ipv4RoutableCoverage(ranges []ipRange) uint64 {
	var covered uint64
	for _, r := range mergeIPv4Ranges(ranges) {
		covered += r.hi - r.lo + 1
		for _, b := range nonRoutableIPv4Blocks {
			if b.hi < r.lo || b.lo > r.hi {
				continue
			}
			covered -= min(b.hi, r.hi) - max(b.lo, r.lo) + 1
		}
	}
	return covered
}

// ipv4RangesAdmitInternet reports whether the ranges, TAKEN TOGETHER, admit at
// least half of the public IPv4 internet.
//
// The union is what matters. A server whose rules read 0.0.0.0-84.255.255.255,
// 85.0.0.0-169.255.255.255 and 170.0.0.0-255.255.255.255 has no single
// catch-all rule and is open to every address there is; judging one rule at a
// time reported it as closed. Halves, thirds and any other partition of the
// space are the same evasion written differently, so the ranges are coalesced
// before the question is asked.
func ipv4RangesAdmitInternet(ranges []ipRange) bool {
	return ipv4RoutableCoverage(ranges)*2 >= routableIPv4Total
}

// ipv6Range is an inclusive [lo, hi] IPv6 range. 128-bit endpoints need big
// integers so a span crossing the halfway point subtracts without carry
// handling of a uint64 pair.
type ipv6Range struct{ lo, hi *big.Int }

// mergeIPv6Ranges is mergeIPv4Ranges for the 128-bit space.
//
// A range whose bounds are nil is dropped rather than dereferenced. big.Int
// methods panic on a nil receiver, and a panic here would take down the whole
// scan rather than one field. Dropping does not weaken the safe-verdict rule
// the rest of this file follows: nil bounds can only come from a zero-value
// ipv6Range built in code, never from a firewall rule that failed to read, so
// there is no unread evidence being silently discounted.
func mergeIPv6Ranges(ranges []ipv6Range) []ipv6Range {
	sorted := make([]ipv6Range, 0, len(ranges))
	for _, r := range ranges {
		if r.lo == nil || r.hi == nil {
			continue
		}
		if r.hi.Cmp(r.lo) < 0 {
			continue
		}
		sorted = append(sorted, r)
	}
	if len(sorted) == 0 {
		return nil
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo.Cmp(sorted[j].lo) < 0 })

	merged := []ipv6Range{sorted[0]}
	for _, r := range sorted[1:] {
		last := &merged[len(merged)-1]
		if r.lo.Cmp(new(big.Int).Add(last.hi, big.NewInt(1))) > 0 {
			merged = append(merged, r)
			continue
		}
		if r.hi.Cmp(last.hi) > 0 {
			last.hi = r.hi
		}
	}
	return merged
}

// ipv6RangesAdmitInternet reports whether the ranges together span at least
// half of the IPv6 address space. Azure keeps IPv6 firewall rules in a list of
// their own, and they are as splittable as the IPv4 ones, so they are summed
// the same way. No non-routable carve-out is applied: the IPv6 space is mostly
// unallocated, which makes a fraction-of-the-space measure coarse in a way no
// block list would fix.
func ipv6RangesAdmitInternet(ranges []ipv6Range) bool {
	total := new(big.Int)
	for _, r := range mergeIPv6Ranges(ranges) {
		span := new(big.Int).Sub(r.hi, r.lo)
		span.Add(span, big.NewInt(1))
		total.Add(total, span)
	}
	return total.Cmp(halfOfIPv6) >= 0
}

// securityRuleAllowsInternetIngress reports whether a single NSG security rule
// opens inbound traffic to the public internet. A rule qualifies when it is an
// inbound Allow rule whose source (single prefix or any entry in the prefix
// list) is an internet-open source. Direction/access matching is
// case-insensitive to tolerate API casing variations.
func securityRuleAllowsInternetIngress(direction, access, sourcePrefix string, sourcePrefixes []string) bool {
	if !strings.EqualFold(strings.TrimSpace(direction), "Inbound") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(access), "Allow") {
		return false
	}
	if isInternetOpenSourcePrefix(sourcePrefix) {
		return true
	}
	return prefixesCoverInternet(sourcePrefixes)
}

// publicNetworkAccessEnabled interprets the Azure `publicNetworkAccess` string,
// which is "Enabled"/"Disabled" on most resources (and may be empty when the
// API omits it). Empty is treated as enabled because Azure defaults public
// access on when the property is not explicitly set to "Disabled".
func publicNetworkAccessEnabled(value string) bool {
	return !strings.EqualFold(strings.TrimSpace(value), "Disabled")
}

// firewallRangeSets splits (start IP, end IP) pairs into IPv4 and IPv6 ranges.
// A pair is dropped when either endpoint is unparseable, when the range is
// inverted, or when the two endpoints are from different families: none of
// those describe a range that admits anything. An IPv4-mapped IPv6 endpoint
// describes IPv4 space and is not measured against the 128-bit threshold.
func firewallRangeSets(ranges [][2]string) ([]ipRange, []ipv6Range) {
	var v4 []ipRange
	var v6 []ipv6Range
	for _, r := range ranges {
		start, err := netip.ParseAddr(strings.TrimSpace(r[0]))
		if err != nil {
			continue
		}
		end, err := netip.ParseAddr(strings.TrimSpace(r[1]))
		if err != nil {
			continue
		}

		switch {
		case start.Is4() && end.Is4():
			lo, hi := uint64(ipv4ToUint(start)), uint64(ipv4ToUint(end))
			if hi < lo {
				continue
			}
			v4 = append(v4, ipRange{lo: lo, hi: hi})

		case start.Is6() && !start.Is4In6() && end.Is6() && !end.Is4In6():
			lo, hi := ipv6ToBigInt(start), ipv6ToBigInt(end)
			if hi.Cmp(lo) < 0 {
				continue
			}
			v6 = append(v6, ipv6Range{lo: lo, hi: hi})
		}
	}
	return v4, v6
}

// firewallRangesAdmitInternet reports whether a server's database firewall
// rules, taken together, open it to the public internet.
//
// The rules are judged on how much of the address space they actually admit,
// not on the text of their endpoints, and they are judged as a SET. Both halves
// of that matter:
//
//   - Anchoring on the literal string "0.0.0.0" got single rules wrong in both
//     directions: 1.0.0.0 -> 255.255.255.255 is the whole routable internet and
//     read as closed, while 0.0.0.0 -> 0.0.0.1 is two addresses and read as
//     open.
//   - Judging one rule at a time missed the union: three rules reaching
//     0.0.0.0 -> 84.255.255.255, 85.0.0.0 -> 169.255.255.255 and
//     170.0.0.0 -> 255.255.255.255 are every address on the internet with no
//     catch-all rule to point at.
//
// The special "allow all Azure services" rule (0.0.0.0 -> 0.0.0.0) is NOT
// internet-open: it permits traffic only from Azure-internal service IPs. It
// admits one address, in a block that is not routable, so it adds nothing to
// the coverage measure either alone or alongside other rules.
//
// The two families are judged separately and either one is enough: a server can
// be tightly scoped on IPv4 and still admit the whole IPv6 internet.
func firewallRangesAdmitInternet(ranges [][2]string) bool {
	v4, v6 := firewallRangeSets(ranges)
	return ipv4RangesAdmitInternet(v4) || ipv6RangesAdmitInternet(v6)
}

// firewallRuleAllowsAnyInternet reports whether a single database firewall rule
// opens the server to the public internet on its own. A server is judged on all
// of its rules together (see firewallRangesAdmitInternet); this is the one-rule
// form of the same question.
func firewallRuleAllowsAnyInternet(startIp, endIp string) bool {
	return firewallRangesAdmitInternet([][2]string{{startIp, endIp}})
}

// halfOfIPv6 is 2^127, the threshold a rule has to span before it counts as
// admitting the IPv6 internet. Mirrors the IPv4 half-space test.
var halfOfIPv6 = new(big.Int).Lsh(big.NewInt(1), 127)

// ipv6ToBigInt renders a 128-bit address as an unsigned big integer so two
// addresses can be subtracted. uint64 pairs would need carry handling for a
// span that crosses the halfway point, which is exactly the case being tested.
func ipv6ToBigInt(addr netip.Addr) *big.Int {
	b := addr.As16()
	return new(big.Int).SetBytes(b[:])
}

// databaseInternetReachable combines the publicNetworkAccess gate with what the
// firewall rules admit. A database is internet-reachable only when public
// access is enabled AND the rules together permit an internet-wide source
// range.
//
// The rules are handed to firewallRangesAdmitInternet as a set rather than
// tested one at a time: a rule list that partitions the address space between
// its entries opens the server just as widely as a single catch-all, and
// per-rule judgement reported it as closed.
func databaseInternetReachable(publicNetworkAccess string, firewallRanges [][2]string) bool {
	if !publicNetworkAccessEnabled(publicNetworkAccess) {
		return false
	}
	return firewallRangesAdmitInternet(firewallRanges)
}

// aksApiServerInternetReachable reports whether an AKS API server is reachable
// from the public internet. It is reachable when the cluster is not private,
// public network access is not disabled, and no authorized-IP allowlist
// meaningfully restricts API access.
//
// An allowlist only counts as a restriction when it actually restricts
// something. Treating any non-empty list as a restriction meant a cluster
// allowlisted to 0.0.0.0/0 -- what several Terraform modules emit when the
// field cannot be left empty -- reported its API server as unreachable while it
// was open to the world. The same applies to a list written as the two IPv4
// halves.
func aksApiServerInternetReachable(enablePrivateCluster bool, publicNetworkAccess string, authorizedIPRanges []string) bool {
	if enablePrivateCluster {
		return false
	}
	if !publicNetworkAccessEnabled(publicNetworkAccess) {
		return false
	}
	if len(authorizedIPRanges) == 0 {
		return true
	}
	return prefixesCoverInternet(authorizedIPRanges)
}

// --- Resolvers ---

// ruleSourceIsInternet reports whether an Azure effective-security-rule object
// has a source that covers the public internet. It reads the source both as the
// configured prefix(es) and as the expanded set (service tags resolved to
// CIDRs), matching any internet-open source.
func ruleSourceIsInternet(rule map[string]any) bool {
	if sp, ok := rule["sourceAddressPrefix"].(string); ok && isInternetOpenSourcePrefix(sp) {
		return true
	}
	for _, key := range []string{"sourceAddressPrefixes", "expandedSourceAddressPrefix"} {
		arr, ok := rule[key].([]any)
		if !ok {
			continue
		}
		prefixes := make([]string, 0, len(arr))
		for _, p := range arr {
			if s, ok := p.(string); ok {
				prefixes = append(prefixes, s)
			}
		}
		// judged as a set, not entry by entry: a source list can cover the
		// whole internet without any single entry doing so
		if prefixesCoverInternet(prefixes) {
			return true
		}
	}
	return false
}

// effectiveRuleAllowsInternetIngress reports whether a single Azure
// effective-security-rule object (the raw dict returned by a NIC's
// effectiveSecurityRules) is an inbound Allow rule open to any internet source.
func effectiveRuleAllowsInternetIngress(rule map[string]any) bool {
	direction, _ := rule["direction"].(string)
	if !strings.EqualFold(strings.TrimSpace(direction), "Inbound") {
		return false
	}
	access, _ := rule["access"].(string)
	if !strings.EqualFold(strings.TrimSpace(access), "Allow") {
		return false
	}
	return ruleSourceIsInternet(rule)
}

// ruleInt extracts an integer field from an effective-rule dict. JSON numbers
// decode as float64 through encoding/json, so both float64 and integer forms
// are accepted.
func ruleInt(rule map[string]any, key string) (int, bool) {
	switch v := rule[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

// portInterval is an inclusive [lo, hi] port range.
type portInterval struct{ lo, hi int }

// rulePortIntervals reads a rule's destination port range(s) into intervals.
// "*", an empty value, or an absent value means all ports (0-65535). Both the
// single destinationPortRange and the destinationPortRanges list are read.
func rulePortIntervals(rule map[string]any) []portInterval {
	var out []portInterval
	add := func(s string) {
		s = strings.TrimSpace(s)
		// An empty string means "this form is not in use" (Azure populates
		// destinationPortRanges and leaves the singular empty, or vice versa),
		// not "all ports". Let the len(out) == 0 fallback below decide, so an
		// empty singular can't widen a deny rule to cover every port.
		if s == "" {
			return
		}
		if s == "*" {
			out = append(out, portInterval{0, 65535})
			return
		}
		if i := strings.IndexByte(s, '-'); i >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
			if err1 == nil && err2 == nil {
				out = append(out, portInterval{lo, hi})
			}
			return
		}
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, portInterval{n, n})
		}
	}
	if sp, ok := rule["destinationPortRange"].(string); ok {
		add(sp)
	}
	if arr, ok := rule["destinationPortRanges"].([]any); ok {
		for _, p := range arr {
			if s, ok := p.(string); ok {
				add(s)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, portInterval{0, 65535})
	}
	return out
}

// portsCover reports whether the deny intervals fully contain every allow
// interval (each allow interval must fall within a single deny interval).
func portsCover(deny, allow []portInterval) bool {
	for _, a := range allow {
		covered := false
		for _, d := range deny {
			if d.lo <= a.lo && a.hi <= d.hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// protocolCovers reports whether a deny rule's protocol covers an allow rule's
// protocol. "All"/"*"/"Any"/empty on the deny side covers every protocol.
//
// The effective-rules API emits "All" (armnetwork.EffectiveSecurityRuleProtocol
// is one of All, Tcp, Udp); the "*" and "Any" spellings come from the raw NSG
// rule model. Both are accepted so the helper works against either shape.
func protocolCovers(deny, allow string) bool {
	deny = strings.TrimSpace(deny)
	if deny == "" || deny == "*" || strings.EqualFold(deny, "Any") || strings.EqualFold(deny, "All") {
		return true
	}
	return strings.EqualFold(deny, strings.TrimSpace(allow))
}

// destAddressIsBroad reports whether a destination prefix covers all addresses.
func destAddressIsBroad(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "*" || s == "0.0.0.0/0" || s == "::/0"
}

// ruleDestPrefixes reads a rule's destination address prefix(es), reading both
// the single destinationAddressPrefix and the destinationAddressPrefixes list.
// An absent/empty destination means all addresses, represented as "*".
func ruleDestPrefixes(rule map[string]any) []string {
	var out []string
	if s, ok := rule["destinationAddressPrefix"].(string); ok && strings.TrimSpace(s) != "" {
		out = append(out, s)
	}
	if arr, ok := rule["destinationAddressPrefixes"].([]any); ok {
		for _, p := range arr {
			if s, ok := p.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		out = []string{"*"}
	}
	return out
}

// destCovers reports whether a deny rule's destination covers an allow rule's
// destination: every one of the allow rule's destinations must be an
// all-addresses prefix on the deny side or equal to one of the deny rule's
// destinations. Both the single and plural forms are read on each side. When a
// destination is not covered we conservatively report false, leaving the allow
// rule un-shadowed (a security audit should err toward reporting exposure
// rather than hiding it).
func destCovers(deny, allow map[string]any) bool {
	denyDests := ruleDestPrefixes(deny)
	covers := func(target string) bool {
		for _, d := range denyDests {
			if destAddressIsBroad(d) || strings.EqualFold(d, target) {
				return true
			}
		}
		return false
	}
	for _, a := range ruleDestPrefixes(allow) {
		if !covers(a) {
			return false
		}
	}
	return true
}

// denyDominatesAllow reports whether a higher-priority Deny rule fully shadows
// an Allow rule for internet ingress: it must cover the Allow's protocol,
// destination ports, and destination address.
func denyDominatesAllow(deny, allow map[string]any) bool {
	dproto, _ := deny["protocol"].(string)
	aproto, _ := allow["protocol"].(string)
	if !protocolCovers(dproto, aproto) {
		return false
	}
	if !portsCover(rulePortIntervals(deny), rulePortIntervals(allow)) {
		return false
	}
	return destCovers(deny, allow)
}

// nsgAllowsInternetIngress reports whether a single NSG's effective rules admit
// inbound traffic from the internet, honoring rule priority, and returns the
// surviving internet-open Allow rules. An inbound internet Allow rule survives
// when no higher-priority (lower-numbered) inbound internet Deny rule dominates
// it (same protocol, destination ports, and destination). When no internet
// source rule allows ingress the group admits nothing (Azure's default
// DenyAllInbound applies).
//
// Only rules whose source covers the internet are considered — for both Allow
// and Deny. A Deny whose source is a non-internet tag (VirtualNetwork,
// AzureLoadBalancer, a private CIDR) does not block internet-sourced traffic,
// so it correctly never shadows an internet Allow here.
func nsgAllowsInternetIngress(rules []map[string]any) (bool, []map[string]any) {
	type prioritized struct {
		rule  map[string]any
		prio  int
		allow bool
	}
	var internetRules []prioritized
	for _, r := range rules {
		dir, _ := r["direction"].(string)
		if !strings.EqualFold(strings.TrimSpace(dir), "Inbound") {
			continue
		}
		if !ruleSourceIsInternet(r) {
			continue
		}
		prio, ok := ruleInt(r, "priority")
		if !ok {
			prio = int(^uint(0) >> 1) // unknown priority sorts last
		}
		access, _ := r["access"].(string)
		internetRules = append(internetRules, prioritized{
			rule:  r,
			prio:  prio,
			allow: strings.EqualFold(strings.TrimSpace(access), "Allow"),
		})
	}
	sort.SliceStable(internetRules, func(i, j int) bool {
		return internetRules[i].prio < internetRules[j].prio
	})

	var open []map[string]any
	for i, a := range internetRules {
		if !a.allow {
			continue
		}
		shadowed := false
		for j := range i {
			d := internetRules[j]
			if d.allow {
				continue
			}
			if denyDominatesAllow(d.rule, a.rule) {
				shadowed = true
				break
			}
		}
		if !shadowed {
			open = append(open, a.rule)
		}
	}
	return len(open) > 0, open
}

// exposureVerdict is one exposure answer: the value, and whether it was
// actually determined. An undetermined verdict is reported as null rather than
// as false. A read that was refused, throttled, or impossible must never assert
// that a resource is protected, and false is exactly that assertion: a policy
// written as "not reachable from the internet" passes on it.
type exposureVerdict struct {
	value bool
	known bool
}

// exposureObservations is what the exposure walk actually observed, kept apart
// from the verdicts so the judgement is a pure function of it.
type exposureObservations struct {
	// hasPublicIp is read from the resource's own interfaces and is always
	// authoritative: the addresses are already cached on the VM.
	hasPublicIp bool
	// behindPublicLb and loadBalancersEvaluated pair a value with whether the
	// load-balancer listing could be read at all.
	behindPublicLb         bool
	loadBalancersEvaluated bool
	// sgAllowsIngress and nsgsEvaluated pair the OR across the NICs with
	// whether every NIC's effective rules came back authoritatively.
	sgAllowsIngress bool
	nsgsEvaluated   bool
}

// exposureVerdicts are the answers the exposure resource reports.
type exposureVerdicts struct {
	internetReachable          exposureVerdict
	behindPublicLoadBalancer   exposureVerdict
	securityGroupAllowsIngress exposureVerdict
}

// resolveExposureVerdicts turns the observations into verdicts, deciding for
// each one whether the answer was determined.
//
// The determinations are finer than "some read failed, so nothing is known",
// because each verdict has a side that a single observation settles on its own:
//
//   - securityGroupAllowsIngress is an OR across the NICs, so one NIC that
//     admits internet ingress makes it true no matter how many other NICs went
//     unread. Only a false is provisional.
//   - Traffic arriving is "public IP OR behind a public load balancer", so a
//     public IP settles it even when the load-balancer listing failed.
//   - internetReachable is an AND, so either half being a determined false
//     settles it. A deallocated VM with no public address and no load balancer
//     in front of it is genuinely unreachable, and stays a plain false even
//     though its effective rules could not be computed.
//
// What is left is the case this exists for: the machine can be reached and
// nothing authoritative is known about what filters it. That reports null.
func resolveExposureVerdicts(obs exposureObservations) exposureVerdicts {
	sg := exposureVerdict{
		value: obs.sgAllowsIngress,
		known: obs.nsgsEvaluated || obs.sgAllowsIngress,
	}
	lb := exposureVerdict{
		value: obs.behindPublicLb && obs.loadBalancersEvaluated,
		known: obs.loadBalancersEvaluated,
	}
	arrives := exposureVerdict{
		value: obs.hasPublicIp || lb.value,
		known: obs.hasPublicIp || lb.known,
	}

	reachable := exposureVerdict{value: arrives.value && sg.value}
	reachable.known = (arrives.known && sg.known) ||
		(arrives.known && !arrives.value) ||
		(sg.known && !sg.value)

	return exposureVerdicts{
		internetReachable:          reachable,
		behindPublicLoadBalancer:   lb,
		securityGroupAllowsIngress: sg,
	}
}

// rawVerdict renders a verdict for CreateResource: a determined verdict is its
// boolean, an undetermined one is null.
func rawVerdict(v exposureVerdict) *llx.RawData {
	if !v.known {
		return llx.NilData
	}
	return llx.BoolData(v.value)
}

// rawOpenIngressRules renders the surviving internet-open rules. An empty list
// says the NICs were examined and nothing admits internet traffic, so it is
// only reported when at least one NIC was examined: with no authoritative rule
// set anywhere and nothing found, the list is null instead.
//
// Rules that were found stay a list even when another NIC went unread. They
// were observed on an NSG Azure did answer for, and dropping them would hide a
// real finding to describe a gap the other fields already report.
func rawOpenIngressRules(openRules []any, nsgsEvaluated bool) *llx.RawData {
	if !nsgsEvaluated && len(openRules) == 0 {
		return llx.NilData
	}
	return llx.ArrayData(openRules, types.Dict)
}

// exposure builds the network-exposure summary for a VM from its already-cached
// public IPs and the effective security rules of its NICs.
//
// Inbound internet traffic must be admitted by every NSG in a NIC's effective
// chain (the subnet-level NSG and the NIC-level NSG are evaluated in sequence),
// so each NIC is evaluated per-NSG: the NIC admits internet ingress only when
// all of its effective NSGs do. The VM is exposed when any NIC admits it. A NIC
// that Azure reports as having no NSG at all admits every inbound flow and so
// counts as exposed; a NIC whose rules could not be computed (stopped VM,
// access denied) is skipped and clears securityGroupsEvaluated instead, so a
// "closed" verdict is never inferred from a failed lookup. Where the skipped
// read is what the answer turned on, internetReachable and
// securityGroupAllowsIngress report null instead of false -- Azure computes
// effective rules only for a NIC attached to a running VM, so stopping a VM
// used to flip both of them to false while its NSG still allowed 22/tcp from
// anywhere. Resolving effective rules is a live Azure call per NIC; it is only
// paid when exposure is queried.
//
// Rule priority is honored: within an NSG a higher-priority (lower-numbered)
// Deny rule shadows a lower-priority Allow-from-internet rule when it covers the
// same protocol, destination ports, and destination (see nsgAllowsInternetIngress).
//
// Limitation: AVNM security-admin rules, which override NSGs tenant-wide, are
// not folded into this evaluation.
func (a *mqlAzureSubscriptionComputeServiceVm) exposure() (*mqlAzureSubscriptionNetworkServiceExposure, error) {
	publicIps := a.GetPublicIpAddresses()
	if publicIps.Error != nil {
		return nil, publicIps.Error
	}
	hasPublicIp := len(publicIps.Data) > 0

	nics := a.GetNetworkInterfaces()
	if nics.Error != nil {
		return nil, nics.Error
	}

	securityGroupAllowsIngress := false
	// Every NIC must be evaluated authoritatively before a "closed" verdict
	// means anything; one degraded fetch makes the whole verdict provisional.
	nsgsEvaluated := true
	openRules := []any{}
	for _, n := range nics.Data {
		nic, ok := n.(*mqlAzureSubscriptionNetworkServiceInterface)
		if !ok {
			continue
		}
		groups, evaluated, err := nic.effectiveNsgGroupsCached()
		if err != nil {
			return nil, err
		}
		if !evaluated {
			nsgsEvaluated = false
			continue
		}
		if len(groups) == 0 {
			// Azure answered, and the NIC has no NSG on itself or its subnet.
			// Nothing filters inbound traffic, so this is the most exposed
			// configuration there is — not an absence of evidence.
			securityGroupAllowsIngress = true
			openRules = append(openRules, map[string]any{
				"name":                     "NoNetworkSecurityGroup",
				"access":                   "Allow",
				"direction":                "Inbound",
				"protocol":                 "All",
				"sourceAddressPrefix":      "*",
				"destinationAddressPrefix": "*",
				"destinationPortRange":     "0-65535",
			})
			continue
		}
		nicAdmits := true
		var nicRules []map[string]any
		for _, g := range groups {
			allows, surviving := nsgAllowsInternetIngress(g.rules)
			if !allows {
				nicAdmits = false
				break
			}
			nicRules = append(nicRules, surviving...)
		}
		if nicAdmits {
			securityGroupAllowsIngress = true
			for _, r := range nicRules {
				openRules = append(openRules, r)
			}
		}
	}

	// The other way in. Azure's own reference architectures put the public IP on a
	// load balancer frontend and leave the machine's interface with a private
	// address only, so reading public IPs off the interfaces alone reports the
	// recommended topology as closed.
	loadBalancersEvaluated := true
	behindPublicLb, err := a.behindPublicLoadBalancer(nics.Data)
	if err != nil {
		// One unreadable listing must not turn into "closed". Drop the signal,
		// mark the verdict provisional, and say why.
		logLoadBalancerLookupFailure(a.Id.Data, err)
		behindPublicLb = false
		loadBalancersEvaluated = false
	}

	verdicts := resolveExposureVerdicts(exposureObservations{
		hasPublicIp:            hasPublicIp,
		behindPublicLb:         behindPublicLb,
		loadBalancersEvaluated: loadBalancersEvaluated,
		sgAllowsIngress:        securityGroupAllowsIngress,
		nsgsEvaluated:          nsgsEvaluated,
	})

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceExposure, map[string]*llx.RawData{
		"__id":                       llx.StringData("azure.subscription.computeService.vm/" + a.Id.Data + "/exposure"),
		"internetReachable":          rawVerdict(verdicts.internetReachable),
		"hasPublicIp":                llx.BoolData(hasPublicIp),
		"behindPublicLoadBalancer":   rawVerdict(verdicts.behindPublicLoadBalancer),
		"securityGroupAllowsIngress": rawVerdict(verdicts.securityGroupAllowsIngress),
		"securityGroupsEvaluated":    llx.BoolData(nsgsEvaluated && loadBalancersEvaluated),
		"openIngressRules":           rawOpenIngressRules(openRules, nsgsEvaluated),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceExposure), nil
}

// sqlFirewallRanges collects (startIp, endIp) pairs from a list of MQL SQL
// firewall-rule resources, ignoring rules whose accessor lookups error.
func sqlFirewallRanges(rules []any) [][2]string {
	out := make([][2]string, 0, len(rules))
	for _, r := range rules {
		fr, ok := r.(*mqlAzureSubscriptionSqlServiceFirewallrule)
		if !ok {
			continue
		}
		out = append(out, [2]string{fr.GetStartIpAddress().Data, fr.GetEndIpAddress().Data})
	}
	return out
}

// internetReachable judges an Azure SQL server against both of its firewall
// rule lists.
//
// Reading only firewallRules answered for IPv4 alone, so a server whose only
// wide-open rule was an IPv6 one -- :: through
// ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, the entire IPv6 internet --
// reported false while it was reachable by anyone.
//
// When the IPv6 list cannot be read (see ipv6FirewallRules) and IPv4 alone does
// not already prove the server open, the answer is not known: this reports null
// rather than false, since false would be the same false negative in a
// different disguise.
func (a *mqlAzureSubscriptionSqlServiceServer) internetReachable() (bool, error) {
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	rules := a.GetFirewallRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	ipv6Rules := a.GetIpv6FirewallRules()
	if ipv6Rules.Error != nil {
		return false, ipv6Rules.Error
	}

	ranges := sqlFirewallRanges(rules.Data)
	ranges = append(ranges, sqlIPv6FirewallRanges(ipv6Rules.Data)...)
	reachable := databaseInternetReachable(pna.Data, ranges)

	if !reachable && ipv6Rules.IsNull() && publicNetworkAccessEnabled(pna.Data) {
		a.InternetReachable.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return reachable, nil
}

// sqlIPv6FirewallRanges collects (startIp, endIp) pairs from a list of MQL SQL
// IPv6 firewall-rule resources, ignoring rules whose accessor lookups error.
func sqlIPv6FirewallRanges(rules []any) [][2]string {
	out := make([][2]string, 0, len(rules))
	for _, r := range rules {
		fr, ok := r.(*mqlAzureSubscriptionSqlServiceServerIpv6FirewallRule)
		if !ok {
			continue
		}
		out = append(out, [2]string{fr.GetStartIpAddress().Data, fr.GetEndIpAddress().Data})
	}
	return out
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) internetReachable() (bool, error) {
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	rules := a.GetFirewallRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	return databaseInternetReachable(pna.Data, sqlFirewallRanges(rules.Data)), nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceServer) internetReachable() (bool, error) {
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	rules := a.GetFirewallRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	return databaseInternetReachable(pna.Data, sqlFirewallRanges(rules.Data)), nil
}

func (a *mqlAzureSubscriptionMySqlServiceServer) internetReachable() (bool, error) {
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	rules := a.GetFirewallRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	return databaseInternetReachable(pna.Data, sqlFirewallRanges(rules.Data)), nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) internetReachable() (bool, error) {
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	rules := a.GetFirewallRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	return databaseInternetReachable(pna.Data, sqlFirewallRanges(rules.Data)), nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) internetReachable() (bool, error) {
	priv := a.GetEnablePrivateCluster()
	if priv.Error != nil {
		return false, priv.Error
	}
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	rangesVal := a.GetApiServerAuthorizedIPRanges()
	if rangesVal.Error != nil {
		return false, rangesVal.Error
	}
	ranges := []string{}
	for _, r := range rangesVal.Data {
		if s, ok := r.(string); ok {
			ranges = append(ranges, s)
		}
	}
	return aksApiServerInternetReachable(priv.Data, pna.Data, ranges), nil
}

// storageAccountIsPublic combines the three gates that must all be open for a
// storage account to allow anonymous public reads: public network access not
// disabled, the network rule set defaulting to Allow, and blob containers
// permitted to be made anonymously public.
func storageAccountIsPublic(publicNetworkAccess, networkRuleDefaultAction string, allowBlobPublicAccess bool) bool {
	if !publicNetworkAccessEnabled(publicNetworkAccess) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(networkRuleDefaultAction), "Allow") {
		return false
	}
	return allowBlobPublicAccess
}

func (a *mqlAzureSubscriptionStorageServiceAccount) isPublic() (bool, error) {
	pna := a.GetPublicNetworkAccess()
	if pna.Error != nil {
		return false, pna.Error
	}
	defaultAction := a.GetNetworkRuleDefaultAction()
	if defaultAction.Error != nil {
		return false, defaultAction.Error
	}
	allowBlobPublic := a.GetAllowBlobPublicAccess()
	if allowBlobPublic.Error != nil {
		return false, allowBlobPublic.Error
	}
	return storageAccountIsPublic(pna.Data, defaultAction.Data, allowBlobPublic.Data), nil
}
