// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A physical Apple Silicon Mac names the vendor in fields that have nothing to
// do with virtualization ("Chip: Apple M4 Pro"). Matching the whole hardware
// profile picked up the "apple" key and reported every such Mac as running
// under Apple Virtualization, which also made the asset kind "virtualmachine".
const physicalAppleSiliconProfile = `Hardware:

    Hardware Overview:

      Model Name: MacBook Pro
      Model Identifier: Mac16,8
      Model Number: MX2J3LL/A
      Chip: Apple M4 Pro
      Total Number of Cores: 14 (10 Performance and 4 Efficiency)
      Memory: 24 GB
      System Firmware Version: 18000.121.3
      OS Loader Version: 18000.121.3
      Serial Number (system): DWKDWYVG4W
      Hardware UUID: 33822EE1-9366-5120-A0B1-6CCC4D8031FA
      Provisioning UDID: 00006040-000C31D03EF8801C
      Activation Lock Status: Disabled
`

const appleVirtualMachineProfile = `Hardware:

    Hardware Overview:

      Model Name: Apple Virtual Machine 1
      Model Identifier: VirtualMac2,1
      Chip: Apple M4 Pro
      Memory: 8 GB
`

const vmwareGuestProfile = `Hardware:

    Hardware Overview:

      Model Name: VMware Virtual Platform
      Model Identifier: VMware7,1
      Processor Name: Intel Core i7
`

func TestDarwinHardwareModelIgnoresNonModelFields(t *testing.T) {
	assert.Equal(t, "MacBook Pro\nMac16,8", darwinHardwareModel(physicalAppleSiliconProfile))
	assert.Equal(t, "Apple Virtual Machine 1\nVirtualMac2,1", darwinHardwareModel(appleVirtualMachineProfile))
}

func TestMapHypervisorPhysicalMacIsNotVirtual(t *testing.T) {
	v, ok := mapHypervisor(darwinHardwareModel(physicalAppleSiliconProfile))
	assert.False(t, ok, "a physical Mac must not be reported as virtualized, got %q", v)
	assert.Empty(t, v)
}

func TestMapHypervisorDarwinGuests(t *testing.T) {
	for name, tt := range map[string]struct {
		profile string
		want    string
	}{
		"apple virtualization": {appleVirtualMachineProfile, "Apple Virtualization"},
		"vmware fusion":        {vmwareGuestProfile, "VMware"},
	} {
		t.Run(name, func(t *testing.T) {
			v, ok := mapHypervisor(darwinHardwareModel(tt.profile))
			assert.True(t, ok, "guest must still be detected")
			assert.Equal(t, tt.want, v)
		})
	}
}
