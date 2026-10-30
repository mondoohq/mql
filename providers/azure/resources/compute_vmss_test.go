// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestVmScaleSetIDFromManagedBy(t *testing.T) {
	const vmssID = "/subscriptions/3bbaebfd-abfe-485c-8902-4391ad93a962/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/myVmss"

	tests := []struct {
		name      string
		managedBy string
		want      string
	}{
		{
			name:      "empty managedBy",
			managedBy: "",
			want:      "",
		},
		{
			name:      "malformed ID",
			managedBy: "not-a-resource-id",
			want:      "",
		},
		{
			name:      "non-VMSS resource (availability set)",
			managedBy: "/subscriptions/3bbaebfd-abfe-485c-8902-4391ad93a962/resourceGroups/rg/providers/Microsoft.Compute/availabilitySets/myAvSet",
			want:      "",
		},
		{
			name:      "VMSS resource — already lowercase",
			managedBy: "/subscriptions/3bbaebfd-abfe-485c-8902-4391ad93a962/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/myvmss",
			want:      "/subscriptions/3bbaebfd-abfe-485c-8902-4391ad93a962/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/myvmss",
		},
		{
			name:      "VMSS resource — mixed case (ARM canonical form)",
			managedBy: vmssID,
			want:      "/subscriptions/3bbaebfd-abfe-485c-8902-4391ad93a962/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/myvmss",
		},
		{
			name:      "VMSS resource — child VM path is truncated to the VMSS segment",
			managedBy: vmssID + "/virtualMachines/0",
			want:      "/subscriptions/3bbaebfd-abfe-485c-8902-4391ad93a962/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/myvmss",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := vmScaleSetIDFromManagedBy(tc.managedBy)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFindVmScaleSetByID(t *testing.T) {
	const (
		canonicalID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/foo"
		otherID     = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/bar"
	)

	mkVmss := func(id string) *mqlAzureSubscriptionComputeServiceVmScaleSet {
		return &mqlAzureSubscriptionComputeServiceVmScaleSet{
			Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
		}
	}

	scaleSets := []any{
		mkVmss(canonicalID),
		mkVmss(otherID),
		"not-a-vmss",
		nil,
	}

	t.Run("exact match", func(t *testing.T) {
		got := findVmScaleSetByID(scaleSets, canonicalID)
		assert.NotNil(t, got)
		assert.Equal(t, canonicalID, got.Id.Data)
	})

	t.Run("case-insensitive match (lowercased lookup)", func(t *testing.T) {
		got := findVmScaleSetByID(scaleSets,
			"/subscriptions/sub/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/foo")
		assert.NotNil(t, got)
		assert.Equal(t, canonicalID, got.Id.Data)
	})

	t.Run("case-insensitive match (uppercased lookup)", func(t *testing.T) {
		got := findVmScaleSetByID(scaleSets,
			"/SUBSCRIPTIONS/SUB/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/FOO")
		assert.NotNil(t, got)
		assert.Equal(t, canonicalID, got.Id.Data)
	})

	t.Run("no match", func(t *testing.T) {
		got := findVmScaleSetByID(scaleSets,
			"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/missing")
		assert.Nil(t, got)
	})

	t.Run("empty list", func(t *testing.T) {
		got := findVmScaleSetByID(nil, canonicalID)
		assert.Nil(t, got)
	})

	t.Run("non-vmss entries are skipped, not panicked on", func(t *testing.T) {
		got := findVmScaleSetByID([]any{"junk", nil}, canonicalID)
		assert.Nil(t, got)
	})
}
