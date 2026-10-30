// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceAssuranceConstraints(t *testing.T) {
	policy := map[string]any{
		"id":            "dae1a2b3",
		"name":          "macOS baseline",
		"platform":      "MACOS",
		"createdBy":     "00u1",
		"createdDate":   "2024-01-01T00:00:00.000Z",
		"lastUpdate":    "2024-02-01T00:00:00.000Z",
		"lastUpdatedBy": "00u2",
		"_links":        map[string]any{"self": "x"},
		// constraints that must survive:
		"diskEncryptionType":    map[string]any{"include": []any{"ALL_INTERNAL_VOLUMES"}},
		"screenLockType":        map[string]any{"include": []any{"BIOMETRIC"}},
		"osVersion":             map[string]any{"minimum": "14.0.0"},
		"secureHardwarePresent": true,
		"jailbreak":             false,
	}

	got := deviceAssuranceConstraints(policy)

	// Metadata removed.
	for _, k := range deviceAssuranceMetadataKeys {
		_, present := got[k]
		assert.Falsef(t, present, "metadata key %q should be stripped", k)
	}
	// Constraints retained.
	assert.Len(t, got, 5)
	assert.Equal(t, "14.0.0", got["osVersion"].(map[string]any)["minimum"])
	assert.Equal(t, true, got["secureHardwarePresent"])
	assert.Equal(t, false, got["jailbreak"])

	// Input map is not mutated.
	assert.Contains(t, policy, "id")
	assert.Len(t, policy, 13)
}

func TestParseOktaRFC3339(t *testing.T) {
	assert.Nil(t, parseOktaRFC3339(""))
	assert.Nil(t, parseOktaRFC3339("not-a-time"))

	got := parseOktaRFC3339("2024-03-01T12:34:56Z")
	if assert.NotNil(t, got) {
		assert.Equal(t, 2024, got.Year())
		assert.Equal(t, 56, got.Second())
	}
}
