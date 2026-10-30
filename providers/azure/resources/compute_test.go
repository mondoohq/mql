// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/stretchr/testify/assert"
)

func TestVmFlexPreferredSize(t *testing.T) {
	t.Run("nil properties returns nil", func(t *testing.T) {
		assert.Nil(t, vmFlexPreferredSize(nil))
	})
	t.Run("no flex profile returns nil", func(t *testing.T) {
		assert.Nil(t, vmFlexPreferredSize(&compute.VirtualMachineProperties{}))
	})
	t.Run("flex profile returns preferred size", func(t *testing.T) {
		props := &compute.VirtualMachineProperties{
			FlexProfile: &compute.FlexProfile{PreferredVMSize: new("Standard_D4s_v5")},
		}
		got := vmFlexPreferredSize(props)
		if assert.NotNil(t, got) {
			assert.Equal(t, "Standard_D4s_v5", *got)
		}
	})
}
