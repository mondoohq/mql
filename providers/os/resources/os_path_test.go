// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
