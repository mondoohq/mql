// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor_test

import (
	"testing"

	subject "go.mondoo.com/mql/providers/os/id/hypervisor"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestHypervisorDarwinMachdepCpuFeatures(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/macos_machdep_cpu_features.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "VMware", hypervisor)
}

func TestHypervisorDarwinKernHvVMMPresent(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/macos_apple_virtualization_like_tart.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "Apple Virtualization", hypervisor)
}

func TestHypervisorDarwinSystemProfiler(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/macos_system_profiler.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "VirtualBox", hypervisor)
}

func TestHypervisorWindowsVMware(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows_vmware.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "VMware", hypervisor)
}

func TestHypervisorWindowsVirtualBox(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows_virtualbox.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "VirtualBox", hypervisor)
}

func TestHypervisorWindowsServer2022SMBIOSBIOSVersion(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows_hyper_v_smbios.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "Hyper-V", hypervisor)
}

func TestHypervisorLinuxDmidecode(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_dmidecode.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "RHEV Hypervisor", hypervisor)
}

func TestHypervisorLinuxSystemdDetectVirt(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_systemd_detect_virt.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "KVM", hypervisor)
}

func TestHypervisorLinuxDMIProductName(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_dmi_product_name.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "VMware", hypervisor)
}

func TestHypervisorLinuxOpenShiftVirtualization(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_openshift_virtualization.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "OpenShift Virtualization", hypervisor)
}

// An arm64 guest under Apple Virtualization.framework. arm64 has no CPUID
// "hypervisor" flag, so the gate asks systemd-detect-virt --vm instead.
func TestHypervisorLinuxArm64AppleVirtualization(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_apple_virtualization.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "Apple Virtualization", hypervisor)
}

// On arm64 the DMI vendor is consulted only once systemd confirms a VM, so a
// physical host whose firmware names a cloud or hardware vendor is not
// reported as virtualized.
func TestHypervisorLinuxArm64PhysicalHost(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_arm64_systemd_none.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	assert.False(t, ok)
	assert.Empty(t, hypervisor)
}

// On x86 the CPUID "hypervisor" flag alone decides whether the system is a
// guest; its absence is not second-guessed with systemd-detect-virt.
func TestHypervisorLinuxX86WithoutHypervisorFlag(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux_x86_no_hypervisor_flag.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hypervisor, ok := subject.Hypervisor(conn, platform)
	assert.False(t, ok)
	assert.Empty(t, hypervisor)
}
