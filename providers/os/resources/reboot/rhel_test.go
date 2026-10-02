// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestRhelKernelLatest(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/redhat_kernel_reboot.toml")
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "redhat",
			Family: []string{"linux", "redhat"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb := RpmNewestKernel{conn: mock}
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.Equal(t, true, required)
}

func TestAmznContainerWithoutKernel(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/amzn_kernel_container.toml")
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "amazonlinux",
			Version: "2018.03",
			Family:  []string{"linux"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb := RpmNewestKernel{conn: mock}
	required, err := lb.RebootPending()
	require.NoError(t, err)

	assert.Equal(t, false, required)
}

func TestAmznEc2Kernel(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/amzn_kernel_ec2.toml")
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "amazonlinux",
			Version: "2018.03",
			Family:  []string{"linux"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb := RpmNewestKernel{conn: mock}
	required, err := lb.RebootPending()
	require.NoError(t, err)

	assert.Equal(t, false, required)
}

// needs-restarting -r output captured on the sweep hosts.
func TestParseNeedsRestarting(t *testing.T) {
	// RHEL 7, yum-utils 1.1.31: gnutls updated since boot, no newer kernel
	required, ok := parseNeedsRestarting(1, "Core libraries or services have been updated:\n  gnutls -> 3.3.29-9.el7_6\n\nReboot is required to ensure that your system benefits from these updates.\n\nMore information:\nhttps://access.redhat.com/solutions/27943\n")
	assert.True(t, ok)
	assert.True(t, required)

	// Alma 8, dnf-utils: linux-firmware updated since boot
	required, ok = parseNeedsRestarting(1, "Core libraries or services have been updated since boot-up:\n  * linux-firmware\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943\n")
	assert.True(t, ok)
	assert.True(t, required)

	// RHEL 8 as root: subscription-manager chatter precedes the verdict
	required, ok = parseNeedsRestarting(0, "Updating Subscription Management repositories.\nUnable to read consumer identity\n\nThis system is not registered with an entitlement server. You can use subscription-manager to register.\n\nNo core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n")
	assert.True(t, ok)
	assert.False(t, required)

	// not installed, or a dnf error that also exits 1: no verdict
	_, ok = parseNeedsRestarting(127, "")
	assert.False(t, ok)
	_, ok = parseNeedsRestarting(1, "Error: This command has to be run with superuser privileges (under the root user on most systems).\n")
	assert.False(t, ok)
}

func rhelRebootMock(t *testing.T, commands map[string]*mock.Command) *RpmNewestKernel {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "fedora",
			Version: "44",
			Family:  []string{"redhat", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &RpmNewestKernel{conn: conn}
}

// Fedora Cloud 44 installs kernel-core without the kernel metapackage. With a
// newer kernel-core installed, `rpm -q kernel` found nothing and the reboot
// went unreported.
func TestRhelRebootKernelCoreOnly(t *testing.T) {
	lb := rhelRebootMock(t, map[string]*mock.Command{
		rpmQueryKernelCmd: {Stdout: "kernel-core 0:7.2.8-200.fc44 x86_64__Fedora Project__The Linux kernel__GPL-2.0-only__1790837000\n" +
			"kernel-core 0:7.2.8-999.200.fc44 x86_64__g01-sweep__g01-core sweep dummy kernel (no files)__MIT__1790930000\n"},
		"uname -r": {Stdout: "7.2.8-200.fc44.x86_64\n"},
	})
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.True(t, required)
}

// RHEL 7 with gnutls updated since boot and no newer kernel: needs-restarting
// asks for a reboot the kernel comparison can't see.
func TestRhelRebootNeedsRestartingCoreLibrary(t *testing.T) {
	commands := map[string]*mock.Command{
		rpmQueryKernelCmd: {Stdout: "kernel 0:3.10.0-1160.119.1.el7 x86_64__Red Hat, Inc.__The Linux kernel__GPLv2__1790837000\n"},
		"uname -r":        {Stdout: "3.10.0-1160.119.1.el7.x86_64\n"},
	}

	required, err := rhelRebootMock(t, commands).RebootPending()
	require.NoError(t, err)
	assert.False(t, required, "without needs-restarting only the kernel counts")

	commands[rpmNeedsRestartingCmd] = &mock.Command{
		Stdout:     "Core libraries or services have been updated:\n  gnutls -> 3.3.29-9.el7_6\n\nReboot is required to ensure that your system benefits from these updates.\n",
		ExitStatus: 1,
	}
	required, err = rhelRebootMock(t, commands).RebootPending()
	require.NoError(t, err)
	assert.True(t, required)
}

// needs-restarting only looks at packages updated after boot, so its "no"
// doesn't hide a newer kernel installed before it.
func TestRhelRebootNewerKernelOverridesNeedsRestarting(t *testing.T) {
	lb := rhelRebootMock(t, map[string]*mock.Command{
		rpmNeedsRestartingCmd: {Stdout: "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"},
		rpmQueryKernelCmd: {Stdout: "kernel 0:4.18.0-553.158.1.el8_10 x86_64__Red Hat, Inc.__The Linux kernel__GPLv2__1790837000\n" +
			"kernel 0:4.18.0-553.170.1.el8_10 x86_64__Red Hat, Inc.__The Linux kernel__GPLv2__1790930000\n"},
		"uname -r": {Stdout: "4.18.0-553.158.1.el8_10.x86_64\n"},
	})
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.True(t, required)
}
