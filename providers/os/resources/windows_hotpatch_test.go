// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/utils/syncx"
)

func newWindowsHotpatch(t *testing.T, pf *inventory.Platform, stdout string) *mqlWindowsHotpatch {
	t.Helper()
	data := &mock.TomlData{Commands: map[string]*mock.Command{}}
	if stdout != "" {
		data.Commands[detwin.HotpatchStateCommand(pf.Arch)] = &mock.Command{Stdout: stdout}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(data))
	require.NoError(t, err)
	return &mqlWindowsHotpatch{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
}

func hotpatchTestPlatform(title, version, build, arch, productType string) *inventory.Platform {
	return &inventory.Platform{
		Name:    "windows",
		Title:   title,
		Version: version,
		Build:   build,
		Arch:    arch,
		Family:  []string{"windows", "os"},
		Labels:  map[string]string{"windows.mondoo.com/product-type": productType},
	}
}

func TestWindowsHotpatchServer(t *testing.T) {
	pf := hotpatchTestPlatform("Windows Server 2025 Datacenter", "26100", "4652", "AMD64", "3")

	t.Run("enrolled", func(t *testing.T) {
		r := newWindowsHotpatch(t, pf, `{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":"4096","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"2","AllowRebootlessUpdates":"1"}`)
		assert.True(t, r.GetEligible().Data)
		assert.True(t, r.GetEnrolled().Data)
		assert.Equal(t, detwin.HotpatchPackage, r.GetEnrollmentPackage().Data)
		assert.Equal(t, int64(4096), r.GetHotPatchTableSize().Data)
		assert.True(t, r.GetVbsConfigured().Data)
		assert.True(t, r.GetVbsRunning().Data)
		// the client policy is null on servers even when the value exists
		require.NoError(t, r.GetRebootlessUpdatesPolicy().Error)
		assert.True(t, r.GetRebootlessUpdatesPolicy().IsNull())
	})

	t.Run("not enrolled, values absent", func(t *testing.T) {
		r := newWindowsHotpatch(t, pf, `{}`)
		assert.True(t, r.GetEligible().Data)
		assert.False(t, r.GetEnrolled().Data)
		assert.False(t, r.GetEnrolled().IsNull())
		assert.True(t, r.GetEnrollmentPackage().IsNull(), "an absent package is null, like the other absent values")
		assert.True(t, r.GetHotPatchTableSize().IsNull())
		assert.True(t, r.GetVbsConfigured().IsNull())
		assert.True(t, r.GetVbsRunning().IsNull(), "without a WMI answer the running state is null, not false")
	})

	t.Run("enrollment needs a non-zero table size", func(t *testing.T) {
		r := newWindowsHotpatch(t, pf, `{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":"0","EnableVirtualizationBasedSecurity":"1"}`)
		assert.False(t, r.GetEnrolled().Data)
		assert.Equal(t, int64(0), r.GetHotPatchTableSize().Data)
		assert.False(t, r.GetHotPatchTableSize().IsNull())
	})

	t.Run("Server 2019 is not eligible and never enrolled", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows Server 2019 Datacenter", "17763", "1", "AMD64", "3"),
			`{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":"4096","EnableVirtualizationBasedSecurity":"1"}`)
		assert.False(t, r.GetEligible().Data)
		assert.False(t, r.GetEnrolled().Data)
		assert.Equal(t, detwin.HotpatchPackage, r.GetEnrollmentPackage().Data, "raw values are reported regardless")
	})
}

func TestWindowsHotpatchClient(t *testing.T) {
	configured := `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"2"}`

	t.Run("configured x64 Enterprise", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows 11 Enterprise", "26100", "3000", "AMD64", "1"), configured)
		assert.True(t, r.GetEligible().Data)
		assert.True(t, r.GetEnrolled().Data)
		assert.True(t, r.GetRebootlessUpdatesPolicy().Data)
		assert.True(t, r.GetVbsRunning().Data)
		assert.True(t, r.GetEnrollmentPackage().IsNull())
		assert.True(t, r.GetHotPatchTableSize().IsNull())
	})

	t.Run("VBS configured but not running", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows 11 Pro", "26100", "3000", "AMD64", "1"),
			`{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"1"}`)
		assert.True(t, r.GetEligible().Data)
		assert.False(t, r.GetEnrolled().Data)
		assert.True(t, r.GetVbsConfigured().Data)
		assert.False(t, r.GetVbsRunning().Data)
		assert.False(t, r.GetVbsRunning().IsNull())
	})

	t.Run("policy absent", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows 11 Enterprise", "26100", "3000", "AMD64", "1"), `{"VirtualizationBasedSecurityStatus":"2"}`)
		assert.False(t, r.GetEnrolled().Data)
		assert.True(t, r.GetRebootlessUpdatesPolicy().IsNull())
	})

	t.Run("arm64 below the arm64 minimum UBR", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows 11 Enterprise", "26100", "3000", "ARM64", "1"), configured)
		assert.False(t, r.GetEligible().Data)
		assert.False(t, r.GetEnrolled().Data)
		assert.True(t, r.GetRebootlessUpdatesPolicy().Data, "the raw policy is still reported")
	})

	t.Run("arm64 at the arm64 minimum UBR", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows 11 Enterprise", "26100", "4929", "ARM64", "1"), configured)
		assert.True(t, r.GetEligible().Data)
		assert.True(t, r.GetEnrolled().Data)
	})

	t.Run("Home edition", func(t *testing.T) {
		r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows 11 Home", "26200", "6000", "AMD64", "1"), configured)
		assert.False(t, r.GetEligible().Data)
		assert.False(t, r.GetEnrolled().Data)
	})
}

func TestWindowsHotpatchUnknownPlatform(t *testing.T) {
	r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows", "", "", "AMD64", ""), `{}`)
	assert.True(t, r.GetEligible().IsNull())
	assert.True(t, r.GetEnrolled().IsNull())
}

func TestWindowsHotpatchReadFailure(t *testing.T) {
	r := newWindowsHotpatch(t, hotpatchTestPlatform("Windows Server 2022 Datacenter", "20348", "2762", "AMD64", "3"), "")
	// eligibility needs only the platform
	assert.True(t, r.GetEligible().Data)
	assert.Error(t, r.GetEnrolled().Error)
	assert.Error(t, r.GetVbsRunning().Error)
}

func TestWindowsHotpatchNotWindows(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}})
	require.NoError(t, err)
	r := &mqlWindowsHotpatch{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
	assert.Error(t, r.GetEligible().Error)
	assert.Error(t, r.GetEnrolled().Error)
}
