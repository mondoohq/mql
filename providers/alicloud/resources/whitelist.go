// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/netip"
	"strings"

	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// whitelistAllowsAllAddresses reports whether a database IP whitelist admits
// every source address, which is true as soon as one entry does.
//
// These whitelists are flat lists of entries written in several shapes, and
// every shape has its own way of saying "anywhere": the 0.0.0.0/0 block, the
// bare 0.0.0.0 the console writes for it, any other block with a zero-length
// prefix, the % wildcard, a range spanning the whole address space, and ::/0.
// Matching text rather than parsing it misses most of them: a check for the
// literal 0.0.0.0/0 catches only the first, and a check for the substring "/0"
// still misses the bare address, the wildcard and the ranges, while resting on
// the prefix length happening to be the last thing in the entry.
func whitelistAllowsAllAddresses(entries []string) bool {
	for _, entry := range entries {
		if whitelistEntryAllowsAllAddresses(entry) {
			return true
		}
	}
	return false
}

// whitelistEntryAllowsAllAddresses reports whether one whitelist entry admits
// every source address.
//
// An entry that does not parse is reported as not open. A whitelist can carry
// hostnames, security group ids, and typos, and none of those is evidence that
// the database is exposed: treating an unreadable entry as open would report an
// exposure that nobody can act on, while treating it as closed leaves the
// verdict resting only on the entries that were understood.
func whitelistEntryAllowsAllAddresses(entry string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	// the wildcard host these whitelists accept alongside addresses and blocks
	if entry == "%" {
		return true
	}

	// start-end range, for example 0.0.0.0-255.255.255.255
	if start, end, ok := strings.Cut(entry, "-"); ok {
		return addressRangeCoversEverything(start, end)
	}

	// CIDR block: a zero-length prefix admits every address regardless of the
	// address it is written against, so 10.0.0.0/0 is as open as 0.0.0.0/0.
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return false
		}
		return prefix.Bits() == 0
	}

	// bare address: the console writes 0.0.0.0 for "any source"
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return false
	}
	return addr.IsUnspecified()
}

// addressRangeCoversEverything reports whether a start-end whitelist range
// spans the whole address space of its family.
func addressRangeCoversEverything(startRaw, endRaw string) bool {
	start, err := netip.ParseAddr(strings.TrimSpace(startRaw))
	if err != nil {
		return false
	}
	end, err := netip.ParseAddr(strings.TrimSpace(endRaw))
	if err != nil {
		return false
	}
	if start.Is4() != end.Is4() {
		return false
	}
	if !start.IsUnspecified() {
		return false
	}
	return end == lastAddressOfFamily(start)
}

// lastAddressOfFamily returns the highest address in the family of the given
// address: 255.255.255.255 for IPv4, and the all-ones address for IPv6.
func lastAddressOfFamily(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return netip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff})
	}
	var full [16]byte
	for i := range full {
		full[i] = 0xff
	}
	return netip.AddrFrom16(full)
}

// resolveWhitelistAllowsAllAddresses classifies a whitelist that is itself a
// computed field, read through its resolver so the API call behind it happens
// once and is shared with anyone querying the list directly.
//
// A whitelist that could not be read is an error rather than a false: this
// field exists to fail a check, and answering "not open" for an instance nobody
// could read would let exactly the instance in question pass it.
func resolveWhitelistAllowsAllAddresses(field *plugin.TValue[[]any]) (bool, error) {
	if field.Error != nil {
		return false, field.Error
	}
	entries := make([]string, 0, len(field.Data))
	for _, raw := range field.Data {
		if entry, ok := raw.(string); ok {
			entries = append(entries, entry)
		}
	}
	return whitelistAllowsAllAddresses(entries), nil
}

// whitelistAllowsAllAddresses reports whether the RDS instance whitelist admits
// every source address.
func (r *mqlAlicloudRdsInstance) whitelistAllowsAllAddresses() (bool, error) {
	return resolveWhitelistAllowsAllAddresses(r.GetSecurityIPList())
}

// whitelistAllowsAllAddresses reports whether the Redis instance whitelist
// admits every source address.
func (r *mqlAlicloudRedisInstance) whitelistAllowsAllAddresses() (bool, error) {
	return resolveWhitelistAllowsAllAddresses(r.GetSecurityIPList())
}

// whitelistAllowsAllAddresses reports whether the MongoDB instance whitelist
// admits every source address.
func (r *mqlAlicloudMongodbInstance) whitelistAllowsAllAddresses() (bool, error) {
	return resolveWhitelistAllowsAllAddresses(r.GetSecurityIPList())
}

// whitelistAllowsAllAddresses reports whether the PolarDB cluster whitelist
// admits every source address.
func (r *mqlAlicloudPolardbCluster) whitelistAllowsAllAddresses() (bool, error) {
	return resolveWhitelistAllowsAllAddresses(r.GetAccessWhitelist())
}

// whitelistAllowsAllAddresses reports whether the Elasticsearch public endpoint
// whitelist admits every source address. The VPC and Kibana whitelists are
// separate fields and are not read here.
func (r *mqlAlicloudEsInstance) whitelistAllowsAllAddresses() (bool, error) {
	return resolveWhitelistAllowsAllAddresses(r.GetPublicIpWhitelist())
}
