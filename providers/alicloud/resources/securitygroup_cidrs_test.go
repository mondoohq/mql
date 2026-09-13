// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// prefixListFixture builds a resolved prefix list whose entries are already
// read, so the accessor never reaches for a connection.
func prefixListFixture(id, family string, blocks ...any) *mqlAlicloudEcsPrefixList {
	return &mqlAlicloudEcsPrefixList{
		PrefixListId:  plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
		AddressFamily: plugin.TValue[string]{Data: family, State: plugin.StateIsSet},
		CidrBlocks:    plugin.TValue[[]any]{Data: blocks, State: plugin.StateIsSet},
	}
}

// unreadablePrefixListFixture builds a prefix list whose entries failed to
// load, which is what an account that may list prefix lists but not read their
// attributes sees.
func unreadablePrefixListFixture(id, family string) *mqlAlicloudEcsPrefixList {
	return &mqlAlicloudEcsPrefixList{
		PrefixListId:  plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
		AddressFamily: plugin.TValue[string]{Data: family, State: plugin.StateIsSet},
		CidrBlocks: plugin.TValue[[]any]{
			Error: errors.New("Forbidden.RAM: no permission to DescribePrefixListAttributes"),
			State: plugin.StateIsSet | plugin.StateIsNull,
		},
	}
}

// resolvedList wraps a prefix list as an already-resolved reference.
func resolvedList(list *mqlAlicloudEcsPrefixList) plugin.TValue[*mqlAlicloudEcsPrefixList] {
	return plugin.TValue[*mqlAlicloudEcsPrefixList]{Data: list, State: plugin.StateIsSet}
}

// unresolvedList is what resolvePrefixList leaves behind when the list was
// deleted or the credential may not enumerate prefix lists.
func unresolvedList() plugin.TValue[*mqlAlicloudEcsPrefixList] {
	return plugin.TValue[*mqlAlicloudEcsPrefixList]{State: plugin.StateIsSet | plugin.StateIsNull}
}

func TestMergeRuleCidrs(t *testing.T) {
	t.Run("own CIDR only", func(t *testing.T) {
		got := mergeRuleCidrs("10.0.0.0/8", "", nil, addressFamilyIPv4)
		assert.Equal(t, []any{"10.0.0.0/8"}, got)
	})

	t.Run("prefix list blocks join the rule's own CIDR", func(t *testing.T) {
		got := mergeRuleCidrs("10.0.0.0/8", "IPv4", []string{"192.168.0.0/16", "172.16.0.0/12"}, addressFamilyIPv4)
		assert.Equal(t, []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, got)
	})

	t.Run("a block repeated by the rule is reported once", func(t *testing.T) {
		got := mergeRuleCidrs("0.0.0.0/0", "IPv4", []string{"0.0.0.0/0", "10.0.0.0/8"}, addressFamilyIPv4)
		assert.Equal(t, []any{"0.0.0.0/0", "10.0.0.0/8"}, got)
	})

	t.Run("an IPv6 list contributes nothing to the IPv4 answer", func(t *testing.T) {
		got := mergeRuleCidrs("", "IPv6", []string{"::/0"}, addressFamilyIPv4)
		assert.Empty(t, got)
		assert.NotNil(t, got)
	})

	t.Run("an IPv4 list contributes nothing to the IPv6 answer", func(t *testing.T) {
		got := mergeRuleCidrs("", "IPv4", []string{"0.0.0.0/0"}, addressFamilyIPv6)
		assert.Empty(t, got)
	})

	t.Run("the address family match ignores case", func(t *testing.T) {
		got := mergeRuleCidrs("", "ipv6", []string{"2001:db8::/32"}, addressFamilyIPv6)
		assert.Equal(t, []any{"2001:db8::/32"}, got)
	})

	t.Run("blank entries are dropped", func(t *testing.T) {
		got := mergeRuleCidrs("  ", "IPv4", []string{"", "  ", "10.1.0.0/16"}, addressFamilyIPv4)
		assert.Equal(t, []any{"10.1.0.0/16"}, got)
	})

	t.Run("no source of the family yields an empty list, not nil", func(t *testing.T) {
		got := mergeRuleCidrs("", "", nil, addressFamilyIPv4)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("the order of the blocks does not change the answer", func(t *testing.T) {
		forward := mergeRuleCidrs("", "IPv4", []string{"10.0.0.0/8", "192.168.0.0/16"}, addressFamilyIPv4)
		reverse := mergeRuleCidrs("", "IPv4", []string{"192.168.0.0/16", "10.0.0.0/8"}, addressFamilyIPv4)
		assert.Equal(t, forward, reverse)
		assert.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"}, forward)
	})
}

func TestPrefixListCidrs(t *testing.T) {
	t.Run("a readable list reports its family and blocks", func(t *testing.T) {
		family, blocks := prefixListCidrs(prefixListFixture("pl-1", "IPv4", "10.0.0.0/8", "192.168.0.0/16"))
		assert.Equal(t, "IPv4", family)
		assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, blocks)
	})

	t.Run("an unreadable list contributes nothing", func(t *testing.T) {
		family, blocks := prefixListCidrs(unreadablePrefixListFixture("pl-1", "IPv4"))
		assert.Equal(t, "", family)
		assert.Empty(t, blocks)
	})

	t.Run("a nil list contributes nothing", func(t *testing.T) {
		family, blocks := prefixListCidrs(nil)
		assert.Equal(t, "", family)
		assert.Empty(t, blocks)
	})
}

func TestSecurityGroupPermissionSourceCidrs(t *testing.T) {
	t.Run("an inbound rule with only its own CIDR", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "0.0.0.0/0", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: unresolvedList(),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"0.0.0.0/0"}, v4)

		v6, err := perm.ipv6SourceCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v6)
	})

	t.Run("an inbound rule scoped to an IPv4 prefix list", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: resolvedList(prefixListFixture("pl-v4", "IPv4", "0.0.0.0/0", "10.0.0.0/8")),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"0.0.0.0/0", "10.0.0.0/8"}, v4)

		v6, err := perm.ipv6SourceCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v6)
	})

	t.Run("an IPv6 prefix list does not leak into the IPv4 field", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: resolvedList(prefixListFixture("pl-v6", "IPv6", "::/0")),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v4)

		v6, err := perm.ipv6SourceCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"::/0"}, v6)
	})

	t.Run("a rule's own CIDR repeated by its prefix list is reported once", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "10.0.0.0/8", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: resolvedList(prefixListFixture("pl-v4", "IPv4", "10.0.0.0/8", "172.16.0.0/12")),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"10.0.0.0/8", "172.16.0.0/12"}, v4)
	})

	t.Run("an unreadable prefix list leaves the rule's own CIDR", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "10.0.0.0/8", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: resolvedList(unreadablePrefixListFixture("pl-v4", "IPv4")),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"10.0.0.0/8"}, v4)
	})

	t.Run("a prefix list that could not be resolved leaves the rule's own CIDR", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "203.0.113.0/24", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: unresolvedList(),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"203.0.113.0/24"}, v4)
	})

	t.Run("an egress rule has no source of either family", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:        plugin.TValue[string]{Data: "egress", State: plugin.StateIsSet},
			SourceCidrIp:     plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			Ipv6SourceCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			SourcePrefixList: unresolvedList(),
			DestCidrIp:       plugin.TValue[string]{Data: "0.0.0.0/0", State: plugin.StateIsSet},
			Ipv6DestCidrIp:   plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			DestPrefixList:   unresolvedList(),
		}

		v4, err := perm.sourceCidrs()
		assert.NoError(t, err)
		assert.NotNil(t, v4)
		assert.Empty(t, v4)

		v6, err := perm.ipv6SourceCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v6)

		dst, err := perm.destinationCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"0.0.0.0/0"}, dst)
	})
}

func TestSecurityGroupPermissionDestinationCidrs(t *testing.T) {
	t.Run("an outbound rule scoped to an IPv4 prefix list", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:      plugin.TValue[string]{Data: "egress", State: plugin.StateIsSet},
			DestCidrIp:     plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			Ipv6DestCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			DestPrefixList: resolvedList(prefixListFixture("pl-v4", "IPv4", "198.51.100.0/24")),
		}

		v4, err := perm.destinationCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"198.51.100.0/24"}, v4)

		v6, err := perm.ipv6DestinationCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v6)
	})

	t.Run("an IPv6 prefix list does not leak into the IPv4 destination field", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:      plugin.TValue[string]{Data: "egress", State: plugin.StateIsSet},
			DestCidrIp:     plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			Ipv6DestCidrIp: plugin.TValue[string]{Data: "2001:db8::/32", State: plugin.StateIsSet},
			DestPrefixList: resolvedList(prefixListFixture("pl-v6", "IPv6", "::/0")),
		}

		v4, err := perm.destinationCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v4)

		v6, err := perm.ipv6DestinationCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"2001:db8::/32", "::/0"}, v6)
	})

	t.Run("an unreadable prefix list leaves the rule's own destination CIDR", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:      plugin.TValue[string]{Data: "egress", State: plugin.StateIsSet},
			DestCidrIp:     plugin.TValue[string]{Data: "192.0.2.0/24", State: plugin.StateIsSet},
			Ipv6DestCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			DestPrefixList: resolvedList(unreadablePrefixListFixture("pl-v4", "IPv4")),
		}

		v4, err := perm.destinationCidrs()
		assert.NoError(t, err)
		assert.Equal(t, []any{"192.0.2.0/24"}, v4)
	})

	t.Run("an ingress rule has no destination of either family", func(t *testing.T) {
		perm := &mqlAlicloudEcsSecuritygroupPermission{
			Direction:      plugin.TValue[string]{Data: "ingress", State: plugin.StateIsSet},
			DestCidrIp:     plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			Ipv6DestCidrIp: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
			DestPrefixList: unresolvedList(),
		}

		v4, err := perm.destinationCidrs()
		assert.NoError(t, err)
		assert.NotNil(t, v4)
		assert.Empty(t, v4)

		v6, err := perm.ipv6DestinationCidrs()
		assert.NoError(t, err)
		assert.Empty(t, v6)
	})
}
