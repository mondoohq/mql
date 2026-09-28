// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// FreeBSD 14.5 on an EC2 t3 (Nitro) instance: the kernel detects KVM, and the
// SMBIOS maker names the platform the same way Linux's DMI sys_vendor does.
func TestHypervisorFreebsdEC2Nitro(t *testing.T) {
	path, err := filepath.Abs("./testdata/freebsd_ec2_nitro.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(path))
	require.NoError(t, err)

	name, ok := Hypervisor(conn, &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}})
	require.True(t, ok)
	assert.Equal(t, "AWS Nitro System", name)
}

func TestParseFreebsdHypervisor(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
		ok   bool
	}{
		{
			name: "bare metal",
			// the SMBIOS strings of a physical board must not make it a guest
			out: "vm_guest=none\nPowerEdge R650\nDell Inc.\nDell Inc.\nDell Inc.\n",
			ok:  false,
		},
		{
			name: "SMBIOS names the platform",
			out:  "vm_guest=kvm\nStandard PC (i440FX + PIIX, 1996)\nQEMU\n\nSeaBIOS\npc-i440fx-8.1\n",
			want: "QEMU",
			ok:   true,
		},
		{
			name: "no SMBIOS, kernel guest detection",
			out:  "vm_guest=bhyve\n",
			want: "bhyve",
			ok:   true,
		},
		{
			name: "Hyper-V",
			out:  "vm_guest=hv\n",
			want: "Hyper-V",
			ok:   true,
		},
		{
			name: "unrecognized hypervisor",
			out:  "vm_guest=generic\n",
			ok:   false,
		},
		{
			// a failed sysctl leaves the prefix alone, and an SMBIOS string
			// must not be read as the guest type
			name: "sysctl failed",
			out:  "vm_guest=\nt3.medium\nAmazon EC2\n",
			ok:   false,
		},
		{
			name: "no output",
			out:  "",
			ok:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFreebsdHypervisor(tc.out)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
