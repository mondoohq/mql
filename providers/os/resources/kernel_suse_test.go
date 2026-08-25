// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuseKernelName(t *testing.T) {
	tests := []struct {
		pkg      string
		wantName string
		wantOK   bool
		why      string
	}{
		// Bootable kernels, as named in the openSUSE Leap 16.0 and SLE 16 repos.
		{"kernel-default", "kernel-default", true, "the stock flavor"},
		{"kernel-azure", "kernel-azure", true, "cloud flavor"},
		{"kernel-rt", "kernel-rt", true, "realtime flavor"},
		{"kernel-kvmsmall", "kernel-kvmsmall", true, "virtualization flavor"},
		{"kernel-default-base", "kernel-default-base", true, "stripped kernel MicroOS boots"},
		{"kernel-64kb", "kernel-64kb", true, "flavor not in any list still resolves"},
		{"kernel-longterm", "kernel-longterm", true, "flavor not in any list still resolves"},

		// Subpackages that carry no kernel. These are what a stock SUSE host
		// actually has installed alongside the kernel, and listing them invents
		// installed kernels.
		{"kernel-firmware-network", "", false, "firmware, installed on stock hosts"},
		{"kernel-firmware-all", "", false, "firmware meta package"},
		{"kernel-macros", "", false, "rpm macros, version tracks a newer kernel"},
		{"kernel-devel", "", false, "headers"},
		{"kernel-devel-azure", "", false, "per-flavor headers"},
		{"kernel-source", "", false, "sources"},
		{"kernel-source-vanilla", "", false, "sources"},
		{"kernel-syms", "", false, "module symbols"},
		{"kernel-syms-azure", "", false, "per-flavor module symbols"},
		{"kernel-docs", "", false, "documentation"},
		{"kernel-docs-html", "", false, "documentation"},
		{"kernel-install-tools", "", false, "tooling"},
		{"kernel-obs-build", "", false, "build service helper"},
		{"kernel-obs-qa", "", false, "build service helper"},
		{"kernel-default-devel", "", false, "per-flavor headers"},
		{"kernel-default-extra", "", false, "extra modules, not a kernel"},
		{"kernel-default-optional", "", false, "optional modules, not a kernel"},
		{"kernel-azure-vdso", "", false, "vdso build"},
		{"kernel-livepatch-6_12_0-160000_37-default", "", false, "livepatch"},

		// Not a kernel package at all.
		{"kernel", "", false, "no flavor suffix, not used by SUSE"},
		{"kernel-", "", false, "empty flavor"},
		{"kernel-base", "", false, "-base with no flavor in front"},
		{"linux-image-6.12.0-default", "", false, "debian naming"},
		{"bash", "", false, "unrelated package"},
	}

	for _, test := range tests {
		t.Run(test.pkg, func(t *testing.T) {
			name, ok := suseKernelName(test.pkg)
			assert.Equal(t, test.wantOK, ok, test.why)
			assert.Equal(t, test.wantName, name, test.why)
		})
	}
}

// The live openSUSE Leap 16.0 host this came from ran 6.12.0-160000.35-default
// with kernel-default 6.12.0-160000.35.1 installed, plus kernel-macros at the
// higher 6.12.0-160000.37.1 and kernel-firmware-network at 20250717-160000.1.2.
// Only the first is a kernel, and only it is running.
func TestSuseKernelNameWithRunningMatch(t *testing.T) {
	running := "6.12.0-160000.35-default"

	tests := []struct {
		pkg         string
		version     string
		wantKernel  bool
		wantRunning bool
	}{
		{"kernel-default", "6.12.0-160000.35.1", true, true},
		{"kernel-macros", "6.12.0-160000.37.1", false, false},
		{"kernel-firmware-network", "20250717-160000.1.2", false, false},
		{"kernel-default", "6.12.0-160000.37.1", true, false},
	}

	for _, test := range tests {
		t.Run(test.pkg+"@"+test.version, func(t *testing.T) {
			name, ok := suseKernelName(test.pkg)
			assert.Equal(t, test.wantKernel, ok)
			if !ok {
				return
			}
			assert.Equal(t, test.wantRunning, suseKernelMatchesRunning(test.version, name, running))
		})
	}
}
