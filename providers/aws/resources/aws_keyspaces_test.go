// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSystemKeyspace(t *testing.T) {
	tests := []struct {
		name   string
		system bool
	}{
		// the real, closed set of Amazon Keyspaces system keyspaces
		{"system", true},
		{"system_schema", true},
		{"system_schema_mcs", true},
		{"system_multiregion_info", true},

		// user keyspaces that a strings.HasPrefix(name, "system") test would
		// silently swallow -- they would never be listed and their tables would
		// never be audited
		{"systems_of_record", false},
		{"system_test", false},
		{"systemsdata", false},
		{"systemd", false},

		// ordinary user keyspaces
		{"my_keyspace", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.system, isSystemKeyspace(tt.name))
		})
	}
}
