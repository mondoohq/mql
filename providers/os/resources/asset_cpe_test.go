// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// The fixtures are /etc/os-release as shipped on SLES 15 SP7, SLES 16.0,
// openSUSE Leap 15.6 and Leap 16.0.
func TestOsReleaseCPEName(t *testing.T) {
	tests := map[string]string{
		"sles15": "cpe:2.3:o:suse:sles:15:sp7:*:*:*:*:*:*",
		"sles16": "cpe:2.3:o:suse:sles:16:16.0:*:*:*:*:*:*",
		"leap15": "cpe:2.3:o:opensuse:leap:15.6:*:*:*:*:*:*:*",
		"leap16": "cpe:2.3:o:opensuse:leap:16.0:*:*:*:*:*:*:*",
		// ALT ships no /etc/system-release-cpe and has no platform table entry
		"altp11":      "cpe:2.3:o:alt:container:11:*:*:*:*:*:*:*",
		"altsisyphus": "cpe:2.3:o:alt:sisyphus:20260316:*:*:*:*:*:*:*",
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile("testdata/os-release/" + name)
			require.NoError(t, err)
			assert.Equal(t, want, osReleaseCPEName(string(content)))
		})
	}

	t.Run("no CPE_NAME", func(t *testing.T) {
		assert.Equal(t, "", osReleaseCPEName("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n"))
	})
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", osReleaseCPEName(""))
	})
}

func TestUsesOsReleaseCPE(t *testing.T) {
	tests := []struct {
		name   string
		family []string
		want   bool
	}{
		{"sles", []string{"suse", "linux", "unix", "os"}, true},
		{"opensuse-leap", []string{"suse", "linux", "unix", "os"}, true},
		{"redhat", []string{"redhat", "linux", "unix", "os"}, false},
		{"ubuntu", []string{"debian", "linux", "unix", "os"}, false},
		{"debian", []string{"debian", "linux", "unix", "os"}, false},
		{"altlinux", []string{"linux", "unix", "os"}, true},
	}
	for _, tc := range tests {
		pf := &inventory.Platform{Name: tc.name, Family: tc.family}
		assert.Equal(t, tc.want, usesOsReleaseCPE(pf), tc.name)
	}
	assert.False(t, usesOsReleaseCPE(nil))
}
