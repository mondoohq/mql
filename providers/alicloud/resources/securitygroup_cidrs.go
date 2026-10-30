// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	addressFamilyIPv4 = "IPv4"
	addressFamilyIPv6 = "IPv6"
)

// mergeRuleCidrs merges a security group rule's own CIDR block with the blocks
// of the prefix list it is scoped to, keeping only what belongs to the wanted
// address family. listFamily is the family the prefix list itself declares, so
// an IPv6 list contributes nothing to an IPv4 answer and the reverse. The
// result is deduplicated and sorted, so two reads of the same rule agree, and
// it is never nil: a rule with no source or destination of that family admits
// nothing, which is an empty list rather than an unknown one.
func mergeRuleCidrs(ownCidr string, listFamily string, listBlocks []string, wantFamily string) []any {
	seen := map[string]struct{}{}
	if cidr := strings.TrimSpace(ownCidr); cidr != "" {
		seen[cidr] = struct{}{}
	}
	if strings.EqualFold(strings.TrimSpace(listFamily), wantFamily) {
		for _, block := range listBlocks {
			if cidr := strings.TrimSpace(block); cidr != "" {
				seen[cidr] = struct{}{}
			}
		}
	}

	cidrs := make([]string, 0, len(seen))
	for cidr := range seen {
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(cidrs)

	res := make([]any, 0, len(cidrs))
	for _, cidr := range cidrs {
		res = append(res, cidr)
	}
	return res
}

// rulePrefixList unwraps the prefix list a rule is scoped to. A list that was
// deleted, or that this credential may not read, resolves to null rather than
// failing the rule, so the caller falls back to the rule's own CIDR.
func rulePrefixList(ref *plugin.TValue[*mqlAlicloudEcsPrefixList]) *mqlAlicloudEcsPrefixList {
	if ref == nil {
		return nil
	}
	if ref.Error != nil {
		log.Warn().Err(ref.Error).
			Msg("alicloud> unable to resolve the prefix list of a security group rule")
		return nil
	}
	return ref.Data
}

// prefixListCidrs reads the address family and CIDR blocks of a prefix list.
// Entries that cannot be read contribute nothing, so the rule reports its own
// CIDR rather than failing, and the reason is logged. Reading through the
// generated accessor keeps one fetch per list no matter how many rules point at
// it.
func prefixListCidrs(list *mqlAlicloudEcsPrefixList) (string, []string) {
	if list == nil {
		return "", nil
	}
	blocks := list.GetCidrBlocks()
	if blocks.Error != nil {
		log.Warn().Err(blocks.Error).Str("prefixListId", list.PrefixListId.Data).
			Msg("alicloud> unable to read the CIDR blocks of a security group rule prefix list")
		return "", nil
	}

	res := make([]string, 0, len(blocks.Data))
	for _, entry := range blocks.Data {
		cidr, ok := entry.(string)
		if !ok {
			continue
		}
		res = append(res, cidr)
	}
	return list.AddressFamily.Data, res
}

// sourceCidrs reports every IPv4 address an inbound rule admits, whether the
// rule names the range itself or points at a prefix list holding it.
func (r *mqlAlicloudEcsSecuritygroupPermission) sourceCidrs() ([]any, error) {
	family, blocks := prefixListCidrs(rulePrefixList(r.GetSourcePrefixList()))
	return mergeRuleCidrs(r.SourceCidrIp.Data, family, blocks, addressFamilyIPv4), nil
}

// ipv6SourceCidrs reports every IPv6 address an inbound rule admits. An IPv4
// prefix list is skipped here, so the two families stay separately auditable.
func (r *mqlAlicloudEcsSecuritygroupPermission) ipv6SourceCidrs() ([]any, error) {
	family, blocks := prefixListCidrs(rulePrefixList(r.GetSourcePrefixList()))
	return mergeRuleCidrs(r.Ipv6SourceCidrIp.Data, family, blocks, addressFamilyIPv6), nil
}

// destinationCidrs reports every IPv4 address an outbound rule permits traffic
// to reach, whether the rule names the range itself or points at a prefix list.
func (r *mqlAlicloudEcsSecuritygroupPermission) destinationCidrs() ([]any, error) {
	family, blocks := prefixListCidrs(rulePrefixList(r.GetDestPrefixList()))
	return mergeRuleCidrs(r.DestCidrIp.Data, family, blocks, addressFamilyIPv4), nil
}

// ipv6DestinationCidrs reports every IPv6 address an outbound rule permits
// traffic to reach.
func (r *mqlAlicloudEcsSecuritygroupPermission) ipv6DestinationCidrs() ([]any, error) {
	family, blocks := prefixListCidrs(rulePrefixList(r.GetDestPrefixList()))
	return mergeRuleCidrs(r.Ipv6DestCidrIp.Data, family, blocks, addressFamilyIPv6), nil
}
