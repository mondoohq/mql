// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sentinelone

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		// Measured: Linux agent 26.3, 2026-11-21 (mgmt_uuid is dashed lower case).
		{"dashed lower case", "4f6b2c1e-8a3d-4e5f-9b7a-1c2d3e4f5a6b", "4f6b2c1e-8a3d-4e5f-9b7a-1c2d3e4f5a6b"},
		// Measured: macOS agent 26.2, 2026-11-21 (IOPlatformUUID is dashed upper case).
		{"dashed upper case", "7D2E9C4A-1B3F-5A6E-8C0D-2F4A6B8C0E1D", "7d2e9c4a-1b3f-5a6e-8c0d-2f4a6b8c0e1d"},
		// Measured: Windows agent 26.2, 2026-11-21 (AgentUID is 32 hex digits, no dashes).
		{"32 hex digits", "9C8B7A6F5E4D43C2B1A0F9E8D7C6B5A4", "9c8b7a6f5e4d43c2b1a0f9e8d7c6b5a4"},
		// Synthetic: PowerShell output ends with CRLF.
		{"surrounding whitespace", " 9c8b7a6f5e4d43c2b1a0f9e8d7c6b5a4\r\n", "9c8b7a6f5e4d43c2b1a0f9e8d7c6b5a4"},
		// Synthetic: an all-zero UUID is no identity; hosts reporting it would merge.
		{"all-zero dashed", "00000000-0000-0000-0000-000000000000", ""},
		// Synthetic: the same for the 32-digit form.
		{"all-zero 32 digits", "00000000000000000000000000000000", ""},
		// Synthetic: not hexadecimal.
		{"non-hex", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", ""},
		// Synthetic: dashes in the wrong places.
		{"misplaced dashes", "4f6b2c1e8a3d-4e5f-9b7a-1c2d3e4f5a6b", ""},
		// Synthetic: too short.
		{"truncated", "4f6b2c1e-8a3d-4e5f-9b7a", ""},
		// Synthetic: nothing read.
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, normalize(c.raw))
		})
	}
}

func TestPlatformID(t *testing.T) {
	// Synthetic: no agent UUID yields no platform ID.
	assert.Empty(t, PlatformID(""))
	// Synthetic: the ID is unscoped; agent UUIDs are unique across consoles.
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/sentinelone/agents/9c8b7a6f5e4d43c2b1a0f9e8d7c6b5a4",
		PlatformID("9c8b7a6f5e4d43c2b1a0f9e8d7c6b5a4"))
}
