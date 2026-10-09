// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestSplitPathList(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		isWindows bool
		expected  []any
	}{
		{
			// splitting this on ':' cut every entry apart at its drive letter
			name:      "windows splits on semicolon",
			path:      `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem`,
			isWindows: true,
			expected:  []any{`C:\Windows\system32`, `C:\Windows`, `C:\Windows\System32\Wbem`},
		},
		{
			name:      "unix splits on colon",
			path:      "/usr/local/bin:/usr/bin:/bin",
			isWindows: false,
			expected:  []any{"/usr/local/bin", "/usr/bin", "/bin"},
		},
		{
			// an empty unix entry means the working directory, which is worth
			// keeping so it can be audited for
			name:      "unix keeps the empty working-directory entry",
			path:      "/usr/bin::/bin",
			isWindows: false,
			expected:  []any{"/usr/bin", "", "/bin"},
		},
		{
			name:      "windows trailing separator",
			path:      `C:\Windows;`,
			isWindows: true,
			expected:  []any{`C:\Windows`, ""},
		},
		{
			name:      "single entry",
			path:      "/bin",
			isWindows: false,
			expected:  []any{"/bin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, splitPathList(tt.path, tt.isWindows))
		})
	}
}

// kernelsInstalled builds the value kernel.installed hands to os.rebootpending
// from the JSON mql prints for `kernel { installed }`.
func kernelsInstalled(t *testing.T, raw string) *plugin.TValue[[]any] {
	t.Helper()
	var data []any
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	return &plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
}

func TestKernelPackagesRebootPending(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		expected  bool
	}{
		{
			// photon:4.0 and photon:5.0 container images: no kernel package.
			name:      "photon container without a kernel package",
			installed: `[]`,
			expected:  false,
		},
		{
			// photon:5.0 container after `tdnf install linux-esx`; the
			// container runs the host's kernel, so the package is not running.
			name:      "photon 5 kernel installed but not running",
			installed: `[{"name":"linux-esx","running":false,"version":"6.12.111-1.ph5-esx"}]`,
			expected:  true,
		},
		{
			// photon:4.0 container after `tdnf install linux-esx`.
			name:      "photon 4 kernel installed but not running",
			installed: `[{"name":"linux-esx","running":false,"version":"5.10.260-3.ph4-esx"}]`,
			expected:  true,
		},
		{
			// photon:5.0 container after `tdnf install linux-esx
			// linux-esx-devel linux-api-headers`.
			name: "photon 5 kernel with devel and header packages, none running",
			installed: `[{"name":"linux-esx","running":false,"version":"6.12.111-1.ph5-esx"},` +
				`{"name":"linux-esx-devel","running":false,"version":"6.12.111-1.ph5-esx-devel"},` +
				`{"name":"linux-api-headers","running":false,"version":"6.1.79-6.ph5-api-headers"}]`,
			expected: true,
		},
		{
			// the photon 5 fixture above as a booted host reports it
			name: "running kernel alongside header packages",
			installed: `[{"name":"linux-esx","running":true,"version":"6.12.111-1.ph5-esx"},` +
				`{"name":"linux-esx-devel","running":false,"version":"6.12.111-1.ph5-esx-devel"},` +
				`{"name":"linux-api-headers","running":false,"version":"6.1.79-6.ph5-api-headers"}]`,
			expected: false,
		},
		{
			name: "newer kernel of the running flavor installed side by side",
			installed: `[{"name":"linux-esx","running":true,"version":"6.12.109-1.ph5-esx"},` +
				`{"name":"linux-esx","running":false,"version":"6.12.111-1.ph5-esx"}]`,
			expected: true,
		},
		{
			name: "older kernel of the running flavor installed side by side",
			installed: `[{"name":"linux-esx","running":false,"version":"6.12.109-1.ph5-esx"},` +
				`{"name":"linux-esx","running":true,"version":"6.12.111-1.ph5-esx"}]`,
			expected: false,
		},
		{
			// Arch: pacman upgrades linux in place, so the booted release no
			// longer matches any package.
			name: "arch kernel upgraded in place",
			installed: `[{"name":"linux","running":false,"version":"7.2.9.arch1-1"},` +
				`{"name":"linux-lts","running":false,"version":"6.18.55-1"}]`,
			expected: true,
		},
		{
			name: "arch running linux-lts while linux was upgraded",
			installed: `[{"name":"linux","running":false,"version":"7.2.9.arch1-1"},` +
				`{"name":"linux-lts","running":true,"version":"6.18.55-1"}]`,
			expected: false,
		},
		{
			// Void: xbps upgrades a series package in place.
			name:      "void series package upgraded past the running kernel",
			installed: `[{"name":"linux6.12","running":false,"version":"6.12.113_1"}]`,
			expected:  true,
		},
		{
			name: "void running series current, newer series installed",
			installed: `[{"name":"linux6.12","running":true,"version":"6.12.112_1"},` +
				`{"name":"linux6.18","running":false,"version":"6.18.55_1"}]`,
			expected: false,
		},
		{
			// Mageia installs kernel-<flavor> side by side.
			name: "mageia newer kernel of the running flavor",
			installed: `[{"name":"kernel-desktop","running":true,"version":"6.6.141-1.mga9"},` +
				`{"name":"kernel-desktop","running":false,"version":"6.6.150-1.mga9"}]`,
			expected: true,
		},
		{
			name: "mageia other flavor at the same version",
			installed: `[{"name":"kernel-desktop","running":true,"version":"6.6.141-1.mga9"},` +
				`{"name":"kernel-server","running":false,"version":"6.6.141-1.mga9"}]`,
			expected: false,
		},
		{
			name: "azurelinux newer kernel of the running line",
			installed: `[{"name":"kernel","running":true,"version":"6.6.150.1-1.azl3"},` +
				`{"name":"kernel","running":false,"version":"6.6.157.1-1.azl3"}]`,
			expected: true,
		},
		{
			name: "azurelinux kernel-hwe beside the running kernel",
			installed: `[{"name":"kernel","running":true,"version":"6.6.157.1-1.azl3"},` +
				`{"name":"kernel-hwe","running":false,"version":"6.18.48.1-1.azl3"}]`,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kernelPackagesRebootPending(kernelsInstalled(t, tc.installed))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}

	t.Run("kernel.installed error is returned", func(t *testing.T) {
		installed := &plugin.TValue[[]any]{Error: errors.New("boom"), State: plugin.StateIsSet}
		_, err := kernelPackagesRebootPending(installed)
		assert.EqualError(t, err, "boom")
	})
}

func TestRebootPendingFromKernelPackages(t *testing.T) {
	for _, name := range []string{"photon", "azurelinux", "mariner", "mageia", "arch", "endeavouros", "void"} {
		assert.True(t, rebootPendingFromKernelPackages(&inventory.Platform{Name: name}), name)
	}
	// Manjaro, SteamOS and CachyOS are in the arch family but name their
	// kernels differently; ALT has no kernel filter.
	for _, name := range []string{"manjaro", "steamos", "cachyos", "altlinux", "redhat", "ubuntu"} {
		assert.False(t, rebootPendingFromKernelPackages(&inventory.Platform{Name: name}), name)
	}
}
