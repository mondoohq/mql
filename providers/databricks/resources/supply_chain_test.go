// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/databricks/databricks-sdk-go/service/compute"
)

func TestPoolDiskSpec(t *testing.T) {
	t.Run("no disk spec reports no managed disks", func(t *testing.T) {
		count, size, diskType := poolDiskSpec(nil)
		if count != 0 || size != 0 || diskType != "" {
			t.Fatalf("poolDiskSpec(nil) = (%d, %d, %q), want (0, 0, \"\")", count, size, diskType)
		}
	})

	t.Run("a spec without a volume type still reports counts", func(t *testing.T) {
		count, size, diskType := poolDiskSpec(&compute.DiskSpec{DiskCount: 2, DiskSize: 100})
		if count != 2 || size != 100 {
			t.Fatalf("poolDiskSpec() = (%d, %d), want (2, 100)", count, size)
		}
		if diskType != "" {
			t.Fatalf("poolDiskSpec() diskType = %q, want empty", diskType)
		}
	})

	t.Run("reads the AWS volume type", func(t *testing.T) {
		_, _, diskType := poolDiskSpec(&compute.DiskSpec{
			DiskCount: 1,
			DiskType:  &compute.DiskType{EbsVolumeType: compute.DiskTypeEbsVolumeTypeGeneralPurposeSsd},
		})
		if diskType != "GENERAL_PURPOSE_SSD" {
			t.Fatalf("poolDiskSpec() diskType = %q, want GENERAL_PURPOSE_SSD", diskType)
		}
	})

	t.Run("falls through to the Azure volume type", func(t *testing.T) {
		// DiskType is a union set per cloud. Reading only the AWS field would
		// report an Azure pool as having no disk type at all.
		_, _, diskType := poolDiskSpec(&compute.DiskSpec{
			DiskCount: 1,
			DiskType:  &compute.DiskType{AzureDiskVolumeType: "PREMIUM_LRS"},
		})
		if diskType != "PREMIUM_LRS" {
			t.Fatalf("poolDiskSpec() diskType = %q, want PREMIUM_LRS", diskType)
		}
	})
}
