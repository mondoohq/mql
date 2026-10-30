// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ARM reports a subnet's ipConfigurations ids upper-cased, while the owning
// interface reports the identical id in the casing it was created with. Matching
// them directly finds nothing, which is why a subnet whose addresses are all held
// by network interfaces reported none of them.
//
// These are the exact shapes observed live: the subnet's copy is upper-cased
// through the resource group and interface name, the interface's copy is not.
const (
	subnetCopyOfIPConfigID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/SECURITY-TEAM-RESOURCES/" +
		"providers/Microsoft.Network/networkInterfaces/SECURITY-TEAM-NIC-1/ipConfigurations/INTERNAL"
	interfaceCopyOfIPConfigID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Security-Team-resources/" +
		"providers/Microsoft.Network/networkInterfaces/Security-Team-nic-1/ipConfigurations/internal"
)

func TestSubnetIPConfigIDSetFoldsCase(t *testing.T) {
	set := subnetIPConfigIDSet([]string{subnetCopyOfIPConfigID})
	require.Len(t, set, 1)

	// The property the accessor relies on: the interface's own casing matches.
	_, ok := set[strings.ToLower(interfaceCopyOfIPConfigID)]
	assert.True(t, ok, "the same id in either casing must match")

	// And the pre-fix comparison does not, which is the bug.
	assert.NotEqual(t, subnetCopyOfIPConfigID, interfaceCopyOfIPConfigID,
		"a direct string comparison is what failed")
}

func TestSubnetIPConfigIDSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		want int
	}{
		{name: "several ids", ids: []string{"/a/IPCONFIGURATIONS/one", "/b/ipConfigurations/two"}, want: 2},
		{
			// Two casings of one id are one id: ARM resource ids are
			// case-insensitive, so folding must also deduplicate.
			name: "the same id twice in different casing",
			ids:  []string{subnetCopyOfIPConfigID, interfaceCopyOfIPConfigID},
			want: 1,
		},
		{name: "blank entries are dropped", ids: []string{"", "   ", "/a/ipConfigurations/one"}, want: 1},
		{name: "surrounding whitespace is trimmed", ids: []string{"  /a/ipConfigurations/one  "}, want: 1},
		{name: "nothing at all", ids: nil, want: 0},
		{name: "only blanks", ids: []string{"", " "}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Len(t, subnetIPConfigIDSet(tc.ids), tc.want)
		})
	}
}

func TestSubnetIPConfigIDSetLookupIsLowerCased(t *testing.T) {
	set := subnetIPConfigIDSet([]string{"/a/ipConfigurations/MixedCase"})
	for _, probe := range []string{
		"/a/ipconfigurations/mixedcase",
		strings.ToLower("/A/IPCONFIGURATIONS/MIXEDCASE"),
	} {
		_, ok := set[probe]
		assert.True(t, ok, "lookup with %q must hit", probe)
	}

	// A caller who forgets to fold its own side gets no match, so the accessor
	// has to lower-case what it probes with -- pinned so that stays true.
	_, ok := set["/a/ipConfigurations/MixedCase"]
	assert.False(t, ok, "the set holds folded keys only")
}

// A subnet with no ipConfigurations must report an empty list rather than null:
// a gateway subnet, or one nothing has an address in yet, is a normal state and a
// query should be able to assert on its length.
func TestSubnetWithNoIPConfigurationsReportsEmpty(t *testing.T) {
	subnet := &mqlAzureSubscriptionNetworkServiceSubnet{MqlRuntime: cacheIDTestRuntime()}
	got, err := subnet.interfaceIpConfigurations()
	require.NoError(t, err)
	assert.NotNil(t, got, "empty, not null")
	assert.Empty(t, got)
}
