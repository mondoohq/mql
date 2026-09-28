// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// photonInstalled builds the value kernel.installed hands to os.rebootpending
// from the JSON mql prints for `kernel { installed }`.
func photonInstalled(t *testing.T, raw string) *plugin.TValue[[]any] {
	t.Helper()
	var data []any
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	return &plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
}

func TestPhotonRebootPending(t *testing.T) {
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := photonRebootPending(photonInstalled(t, tc.installed))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}

	t.Run("kernel.installed error is returned", func(t *testing.T) {
		installed := &plugin.TValue[[]any]{Error: errors.New("boom"), State: plugin.StateIsSet}
		_, err := photonRebootPending(installed)
		assert.EqualError(t, err, "boom")
	})
}
