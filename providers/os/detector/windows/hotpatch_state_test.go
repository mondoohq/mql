// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/registry"
)

func i64(v int64) *int64   { return &v }
func str(v string) *string { return &v }

func TestHotpatchStateRules(t *testing.T) {
	pkg := str(HotpatchPackage)
	cases := []struct {
		name   string
		state  HotpatchState
		client bool
		want   bool
	}{
		{"server enrolled", HotpatchState{EnrollmentPackage: pkg, EnableVirtualizationBasedSecurity: i64(1), HotPatchTableSize: i64(4096)}, false, true},
		{"server without package", HotpatchState{EnableVirtualizationBasedSecurity: i64(1), HotPatchTableSize: i64(4096)}, false, false},
		{"server with another package name", HotpatchState{EnrollmentPackage: str("Other"), EnableVirtualizationBasedSecurity: i64(1), HotPatchTableSize: i64(4096)}, false, false},
		{"server VBS not configured", HotpatchState{EnrollmentPackage: pkg, EnableVirtualizationBasedSecurity: i64(0), HotPatchTableSize: i64(4096)}, false, false},
		{"server VBS value absent", HotpatchState{EnrollmentPackage: pkg, HotPatchTableSize: i64(4096)}, false, false},
		{"server table size zero", HotpatchState{EnrollmentPackage: pkg, EnableVirtualizationBasedSecurity: i64(1), HotPatchTableSize: i64(0)}, false, false},
		{"server table size absent", HotpatchState{EnrollmentPackage: pkg, EnableVirtualizationBasedSecurity: i64(1)}, false, false},
		// the server rule uses the configured VBS value, as before
		{"server VBS running is not enough", HotpatchState{EnrollmentPackage: pkg, VirtualizationBasedSecurityStatus: i64(2), HotPatchTableSize: i64(4096)}, false, false},
		{"client configured, VBS running", HotpatchState{AllowRebootlessUpdates: i64(1), VirtualizationBasedSecurityStatus: i64(2)}, true, true},
		{"client VBS configured but not running", HotpatchState{AllowRebootlessUpdates: i64(1), EnableVirtualizationBasedSecurity: i64(1), VirtualizationBasedSecurityStatus: i64(1)}, true, false},
		{"client WMI unknown falls back to configured VBS", HotpatchState{AllowRebootlessUpdates: i64(1), EnableVirtualizationBasedSecurity: i64(1)}, true, true},
		{"client policy off", HotpatchState{AllowRebootlessUpdates: i64(0), VirtualizationBasedSecurityStatus: i64(2)}, true, false},
		{"client policy absent", HotpatchState{VirtualizationBasedSecurityStatus: i64(2)}, true, false},
		{"client ignores the server package", HotpatchState{EnrollmentPackage: pkg, EnableVirtualizationBasedSecurity: i64(1), HotPatchTableSize: i64(4096)}, true, false},
		{"empty state", HotpatchState{}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.state.Enrolled(tc.client))
		})
	}
}

func TestHotpatchStateNullSemantics(t *testing.T) {
	empty := HotpatchState{}
	assert.Nil(t, empty.VBSRunning(), "unknown WMI state is null, not false")
	assert.Nil(t, empty.VBSConfigured())
	assert.Nil(t, empty.RebootlessUpdatesPolicy())

	st := HotpatchState{
		AllowRebootlessUpdates:            i64(0),
		EnableVirtualizationBasedSecurity: i64(1),
		VirtualizationBasedSecurityStatus: i64(1),
	}
	require.NotNil(t, st.VBSRunning())
	assert.False(t, *st.VBSRunning())
	require.NotNil(t, st.VBSConfigured())
	assert.True(t, *st.VBSConfigured())
	require.NotNil(t, st.RebootlessUpdatesPolicy())
	assert.False(t, *st.RebootlessUpdatesPolicy())
}

func TestParseHotpatchState(t *testing.T) {
	t.Run("string values", func(t *testing.T) {
		st, err := ParseHotpatchState(strings.NewReader(`{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":"4096","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"2","AllowRebootlessUpdates":"0"}`))
		require.NoError(t, err)
		assert.Equal(t, HotpatchPackage, *st.EnrollmentPackage)
		assert.Equal(t, int64(4096), *st.HotPatchTableSize)
		assert.Equal(t, int64(1), *st.EnableVirtualizationBasedSecurity)
		assert.Equal(t, int64(2), *st.VirtualizationBasedSecurityStatus)
		assert.Equal(t, int64(0), *st.AllowRebootlessUpdates)
	})

	t.Run("numeric values", func(t *testing.T) {
		st, err := ParseHotpatchState(strings.NewReader(`{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":4096,"EnableVirtualizationBasedSecurity":1}`))
		require.NoError(t, err)
		assert.True(t, st.ServerEnrolled())
	})

	t.Run("absent, null and empty values stay nil", func(t *testing.T) {
		st, err := ParseHotpatchState(strings.NewReader(`{"Name":"","HotPatchTableSize":null,"EnableVirtualizationBasedSecurity":""}`))
		require.NoError(t, err)
		assert.Equal(t, &HotpatchState{}, st)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParseHotpatchState(strings.NewReader(``))
		assert.Error(t, err)
	})
}

// fakeHotpatchHive serves values of SOFTWARE and SYSTEM hives loaded from
// files, keyed by "<hive>|<path>".
type fakeHotpatchHive struct {
	controlSet int64
	items      map[string][]registry.RegistryKeyItem
}

func (h fakeHotpatchHive) GetRegistryItemValue(id, path, key string) (registry.RegistryKeyItem, error) {
	if id == registry.System && path == "Select" && key == "Current" && h.controlSet > 0 {
		return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: h.controlSet}}, nil
	}
	return registry.RegistryKeyItem{}, errors.New("not found")
}

func (h fakeHotpatchHive) GetNativeRegistryKeyItems(id, path string) ([]registry.RegistryKeyItem, error) {
	if items, ok := h.items[id+"|"+path]; ok {
		return items, nil
	}
	return nil, errors.New("key not found")
}

func dword(name string, v int64) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: name, Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: v, String: strconv.FormatInt(v, 10)}}
}

func sz(name, v string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: name, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: v}}
}

func TestReadStaticHotpatchState(t *testing.T) {
	sw := registry.Software + "|"
	sys := registry.System + "|"

	t.Run("enrolled server, active control set from Select", func(t *testing.T) {
		hive := fakeHotpatchHive{controlSet: 2, items: map[string][]registry.RegistryKeyItem{
			sw + hotpatchPackageKeyPrefix + "amd64":                         {sz("Name", HotpatchPackage)},
			sys + `ControlSet002\Control\DeviceGuard`:                       {dword("EnableVirtualizationBasedSecurity", 1)},
			sys + `ControlSet002\Control\Session Manager\Memory Management`: {dword("HotPatchTableSize", 4096)},
			// a stale control set that must not be read
			sys + `ControlSet001\Control\DeviceGuard`: {dword("EnableVirtualizationBasedSecurity", 0)},
		}}
		st := ReadStaticHotpatchState(hive, "AMD64")
		assert.Equal(t, HotpatchPackage, *st.EnrollmentPackage)
		assert.Equal(t, int64(4096), *st.HotPatchTableSize)
		assert.Equal(t, int64(1), *st.EnableVirtualizationBasedSecurity)
		assert.Nil(t, st.VirtualizationBasedSecurityStatus, "an offline scan cannot read the VBS running state")
		assert.Nil(t, st.AllowRebootlessUpdates)
		assert.True(t, st.ServerEnrolled())
	})

	t.Run("arm64 reads the arm64 enrollment package key", func(t *testing.T) {
		hive := fakeHotpatchHive{items: map[string][]registry.RegistryKeyItem{
			sw + hotpatchPackageKeyPrefix + "arm64": {sz("name", HotpatchPackage)},
			sw + hotpatchPackageKeyPrefix + "amd64": {sz("Name", "wrong key")},
		}}
		st := ReadStaticHotpatchState(hive, "ARM64")
		assert.Equal(t, HotpatchPackage, *st.EnrollmentPackage, "value names are case-insensitive")
	})

	t.Run("unknown arch reads amd64", func(t *testing.T) {
		hive := fakeHotpatchHive{items: map[string][]registry.RegistryKeyItem{
			sw + hotpatchPackageKeyPrefix + "amd64": {sz("Name", HotpatchPackage)},
		}}
		st := ReadStaticHotpatchState(hive, "")
		require.NotNil(t, st.EnrollmentPackage)
	})

	t.Run("configured client", func(t *testing.T) {
		hive := fakeHotpatchHive{items: map[string][]registry.RegistryKeyItem{
			sw + rebootlessUpdatesKey:                 {dword("AllowRebootlessUpdates", 1)},
			sys + `ControlSet001\Control\DeviceGuard`: {dword("EnableVirtualizationBasedSecurity", 1)},
		}}
		st := ReadStaticHotpatchState(hive, "AMD64")
		assert.Nil(t, st.EnrollmentPackage)
		assert.Nil(t, st.HotPatchTableSize)
		assert.True(t, st.ClientEnrolled())
		assert.False(t, st.ServerEnrolled())
	})

	t.Run("nothing in the hives", func(t *testing.T) {
		assert.Equal(t, &HotpatchState{}, ReadStaticHotpatchState(fakeHotpatchHive{}, "AMD64"))
	})
}

func hotpatchMock(t *testing.T, arch, stdout string) *mock.Connection {
	t.Helper()
	data := &mock.TomlData{Commands: map[string]*mock.Command{}}
	if stdout != "" {
		data.Commands[HotpatchStateCommand(arch)] = &mock.Command{Stdout: stdout}
	}
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(data))
	require.NoError(t, err)
	return conn
}

func TestGetHotpatchStateOverPowerShell(t *testing.T) {
	t.Run("all values", func(t *testing.T) {
		conn := hotpatchMock(t, "AMD64", `{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":"4096","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"2"}`)
		st, err := GetHotpatchState(conn, "AMD64")
		require.NoError(t, err)
		assert.True(t, st.ServerEnrolled())
		assert.True(t, *st.VBSRunning())
	})

	t.Run("WMI without an answer leaves the running state null", func(t *testing.T) {
		conn := hotpatchMock(t, "AMD64", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1"}`)
		st, err := GetHotpatchState(conn, "AMD64")
		require.NoError(t, err)
		assert.Nil(t, st.VBSRunning())
	})

	t.Run("a failed command is an error", func(t *testing.T) {
		conn := hotpatchMock(t, "AMD64", "")
		_, err := GetHotpatchState(conn, "AMD64")
		assert.Error(t, err)
	})
}

func TestGetWindowsHotpatch(t *testing.T) {
	serverEnrolled := `{"Name":"Hotpatch Enrollment Package","HotPatchTableSize":"4096","EnableVirtualizationBasedSecurity":"1"}`
	clientConfigured := `{"AllowRebootlessUpdates":"1","VirtualizationBasedSecurityStatus":"2"}`

	cases := []struct {
		name   string
		pf     *inventory.Platform
		stdout string
		want   bool
	}{
		{"Server 2022 enrolled", &inventory.Platform{Title: "Windows Server 2022 Datacenter: Azure Edition", Version: "20348", Build: "2762", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "3"}}, serverEnrolled, true},
		{"Server 2025 enrolled", &inventory.Platform{Title: "Windows Server 2025 Datacenter", Version: "26100", Build: "4000", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "3"}}, serverEnrolled, true},
		{"domain controller enrolled", &inventory.Platform{Title: "Windows Server 2022 Datacenter", Version: "20348", Build: "2762", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "2"}}, serverEnrolled, true},
		{"Server 2019 is never enrolled", &inventory.Platform{Title: "Windows Server 2019 Datacenter", Version: "17763", Build: "1", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "3"}}, serverEnrolled, false},
		{"server with client values", &inventory.Platform{Title: "Windows Server 2022 Datacenter", Version: "20348", Build: "2762", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "3"}}, clientConfigured, false},
		{"client x64 configured", &inventory.Platform{Title: "Windows 11 Enterprise", Version: "26100", Build: "2033", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, clientConfigured, true},
		{"client x64 below the UBR", &inventory.Platform{Title: "Windows 11 Enterprise", Version: "26100", Build: "2032", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, clientConfigured, false},
		{"client arm64 configured", &inventory.Platform{Title: "Windows 11 Pro", Version: "26100", Build: "4929", Arch: "ARM64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, clientConfigured, true},
		{"client arm64 below the arm64 UBR", &inventory.Platform{Title: "Windows 11 Pro", Version: "26100", Build: "4000", Arch: "ARM64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, clientConfigured, false},
		{"client Home", &inventory.Platform{Title: "Windows 11 Home", Version: "26200", Build: "6000", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, clientConfigured, false},
		{"client 23H2", &inventory.Platform{Title: "Windows 11 Enterprise", Version: "22631", Build: "4000", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, clientConfigured, false},
		{"client with server values", &inventory.Platform{Title: "Windows 11 Enterprise", Version: "26100", Build: "4000", Arch: "AMD64", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}, serverEnrolled, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := hotpatchMock(t, tc.pf.Arch, tc.stdout)
			got, err := GetWindowsHotpatch(conn, tc.pf)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
