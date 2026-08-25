// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// EC2 Nitro guests were reporting a null hypervisor: systemd-detect-virt says
// "amazon" and the DMI vendor fields say "Amazon EC2", neither of which had a
// mapping, so all three Linux detectors found their input and failed to map it.
//
// The value is the hypervisor, not the cloud: systemd emits "amazon" only for
// Nitro, while the older Xen instance families report "xen".
func TestMapHypervisorAmazonEC2(t *testing.T) {
	// systemd-detect-virt on a Nitro guest
	v, ok := mapHypervisor("amazon")
	assert.True(t, ok)
	assert.Equal(t, "AWS Nitro System", v)

	// DMI sys_vendor / board_vendor / bios_vendor
	v, ok = mapHypervisor("Amazon EC2")
	assert.True(t, ok)
	assert.Equal(t, "AWS Nitro System", v)

	// dmidecode output carries trailing whitespace and mixed case
	v, ok = mapHypervisor("  AMAZON EC2\n")
	assert.True(t, ok)
	assert.Equal(t, "AWS Nitro System", v)
}

// Older EC2 instances are Xen-based and must keep resolving to Xen, not be
// swallowed by the new entry.
func TestMapHypervisorXenStillWins(t *testing.T) {
	v, ok := mapHypervisor("xen")
	assert.True(t, ok)
	assert.Equal(t, "Xen", v)

	v, ok = mapHypervisor("Xen HVM domU")
	assert.True(t, ok)
	assert.Equal(t, "Xen", v)
}

// The existing mappings are unaffected, and an unknown vendor still reports
// nothing rather than guessing.
func TestMapHypervisorUnchanged(t *testing.T) {
	for input, want := range map[string]string{
		"kvm":         "KVM",
		"VMware, Inc": "VMware",
		"QEMU":        "QEMU",
		"hyper-v":     "Hyper-V",
	} {
		v, ok := mapHypervisor(input)
		assert.True(t, ok, input)
		assert.Equal(t, want, v, input)
	}

	_, ok := mapHypervisor("Some Unknown Vendor")
	assert.False(t, ok)
}
