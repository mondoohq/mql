// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDefaultProtectedBranch(t *testing.T) {
	tests := []struct {
		name          string
		rule          string
		defaultBranch string
		want          bool
	}{
		{"exact match", "main", "main", true},
		{"different branch", "develop", "main", false},
		{"catch-all wildcard", "*", "main", true},
		{"prefix wildcard", "ma*", "main", true},
		{"suffix wildcard", "*ain", "main", true},
		{"middle wildcard", "m*n", "main", true},
		{"single-character wildcard", "?ain", "main", true},
		{"path wildcard", "release/*", "release/1.0", true},
		{"path wildcard misses default", "release/*", "main", false},
		{"wildcard does not match a longer name", "ma*", "develop", false},
		{"empty rule", "", "main", false},
		{"wildcard before literal", "*-stable", "1.0-stable", true},
		{"literal before wildcard", "1.0-*", "1.0-stable", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDefaultProtectedBranch(tt.rule, tt.defaultBranch))
		})
	}
}
