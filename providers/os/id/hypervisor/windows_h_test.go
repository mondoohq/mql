// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	subject "go.mondoo.com/mql/providers/os/id/hypervisor"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

// The SMBIOS-derived input has the shape windowsDetectionCommand prints, so
// mapHypervisor gives the same answer for the same machine.
func TestWindowsDetectionInfoMatchesCommandShape(t *testing.T) {
	tests := []struct {
		name    string
		info    smbios.SmBiosInfo
		command string // what windowsDetectionCommand prints on such a host
		want    string
	}{
		{
			name:    "EC2 Nitro",
			info:    smbios.SmBiosInfo{SysInfo: smbios.SysInfo{Model: "t3.large", Vendor: "Amazon EC2"}, BIOS: smbios.BiosInfo{Version: "1.0"}},
			command: "t3.large|Amazon EC2|1.0\r\n",
			want:    "AWS Nitro System",
		},
		{
			name:    "VMware",
			info:    smbios.SmBiosInfo{SysInfo: smbios.SysInfo{Model: "VMware Virtual Platform", Vendor: "VMware, Inc."}, BIOS: smbios.BiosInfo{Version: "6.00"}},
			command: "VMware Virtual Platform|VMware, Inc.|6.00\r\n",
			want:    "VMware",
		},
		{
			name:    "Hyper-V",
			info:    smbios.SmBiosInfo{SysInfo: smbios.SysInfo{Model: "Virtual Machine", Vendor: "Microsoft Corporation"}, BIOS: smbios.BiosInfo{Version: "Hyper-V UEFI Release v4.1"}},
			command: "Virtual Machine|Microsoft Corporation|Hyper-V UEFI Release v4.1\r\n",
			want:    "Hyper-V",
		},
		{
			name:    "physical",
			info:    smbios.SmBiosInfo{SysInfo: smbios.SysInfo{Model: "PowerEdge R650", Vendor: "Dell Inc."}, BIOS: smbios.BiosInfo{Version: "1.8.2"}},
			command: "PowerEdge R650|Dell Inc.|1.8.2\r\n",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			native := subject.WindowsDetectionInfo(&tt.info)
			assert.Equal(t, tt.command[:len(tt.command)-2], native)

			gotNative, okNative := subject.MapHypervisor(native)
			gotCommand, okCommand := subject.MapHypervisor(tt.command)
			assert.Equal(t, gotCommand, gotNative)
			assert.Equal(t, okCommand, okNative)
			assert.Equal(t, tt.want, gotNative)
		})
	}
}
