// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseTarget(t *testing.T) {
	t.Run("parse snapshot target with just a resource name", func(t *testing.T) {
		scanner := azureScannerInstance{
			resourceGroup: "my-rg",
			name:          "my-instance",
		}
		target := "my-other-snapshot"

		conf := &inventory.Config{
			Options: map[string]string{
				"target": target,
				"type":   "snapshot",
			},
		}
		scanTarget, err := ParseTarget(conf, scanner)
		assert.NoError(t, err)
		assert.Equal(t, "my-rg", scanTarget.ResourceGroup)
		assert.Equal(t, target, scanTarget.Target)
		assert.Equal(t, SnapshotTargetType, scanTarget.TargetType)
	})
	t.Run("parse instance target with just a resource name", func(t *testing.T) {
		scanner := azureScannerInstance{
			resourceGroup: "my-rg",
			name:          "my-instance",
		}
		target := "my-other-instance"

		conf := &inventory.Config{
			Options: map[string]string{
				"target": target,
				"type":   "instance",
			},
		}
		scanTarget, err := ParseTarget(conf, scanner)
		assert.NoError(t, err)
		assert.Equal(t, "my-rg", scanTarget.ResourceGroup)
		assert.Equal(t, target, scanTarget.Target)
		assert.Equal(t, InstanceTargetType, scanTarget.TargetType)
	})
	t.Run("parse disk target with just a resource name", func(t *testing.T) {
		scanner := azureScannerInstance{
			resourceGroup: "my-rg",
			name:          "my-instance",
		}
		target := "my-disk"

		conf := &inventory.Config{
			Options: map[string]string{
				"target": target,
				"type":   "disk",
			},
		}
		scanTarget, err := ParseTarget(conf, scanner)
		assert.NoError(t, err)
		assert.Equal(t, "my-rg", scanTarget.ResourceGroup)
		assert.Equal(t, target, scanTarget.Target)
		assert.Equal(t, DiskTargetType, scanTarget.TargetType)
	})
	t.Run("parse snapshot target with a fully qualified Azure resource ID", func(t *testing.T) {
		scanner := azureScannerInstance{}
		target := "/subscriptions/f1a2873a-6c27-4097-aa7c-3df51f103e91/resourceGroups/my-other-rg/providers/Microsoft.Compute/snapshots/test-snp"

		conf := &inventory.Config{
			Options: map[string]string{
				"target": target,
				"type":   "snapshot",
			},
		}
		scanTarget, err := ParseTarget(conf, scanner)
		assert.NoError(t, err)
		assert.Equal(t, "my-other-rg", scanTarget.ResourceGroup)
		assert.Equal(t, "test-snp", scanTarget.Target)
		assert.Equal(t, SnapshotTargetType, scanTarget.TargetType)
	})
	t.Run("parse instance target with a fully qualified Azure resource ID", func(t *testing.T) {
		scanner := azureScannerInstance{}
		target := "/subscriptions/f1a2873a-6b27-4097-aa7c-3df51f103e96/resourceGroups/debian_group/providers/Microsoft.Compute/virtualMachines/debian"

		conf := &inventory.Config{
			Options: map[string]string{
				"target": target,
				"type":   "instance",
			},
		}
		scanTarget, err := ParseTarget(conf, scanner)
		assert.NoError(t, err)
		assert.Equal(t, "debian_group", scanTarget.ResourceGroup)
		assert.Equal(t, "debian", scanTarget.Target)
		assert.Equal(t, InstanceTargetType, scanTarget.TargetType)
	})
	t.Run("parse disk target with a fully qualified Azure resource ID", func(t *testing.T) {
		scanner := azureScannerInstance{}
		target := "/subscriptions/f1a2873a-6b27-4097-aa7c-3df51f103e96/resourceGroups/debian_group/providers/Microsoft.Compute/disks/disk-1"

		conf := &inventory.Config{
			Options: map[string]string{
				"target": target,
				"type":   "disk",
			},
		}
		scanTarget, err := ParseTarget(conf, scanner)
		assert.NoError(t, err)
		assert.Equal(t, "debian_group", scanTarget.ResourceGroup)
		assert.Equal(t, "disk-1", scanTarget.Target)
		assert.Equal(t, DiskTargetType, scanTarget.TargetType)
	})
}
