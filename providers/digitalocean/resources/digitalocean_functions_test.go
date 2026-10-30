// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOwTruthy(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"bool true", true, true},
		{"bool false", false, false},
		{"string true", "true", true},
		{"string false", "false", false},
		{"string no", "no", false},
		{"string raw (web action)", "raw", true},
		{"string auth token", "some-token", true},
		{"empty string", "", false},
		{"nil", nil, false},
		{"other type defaults true", 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, owTruthy(tt.value))
		})
	}
}

func TestOwAnnotation(t *testing.T) {
	anns := []owKeyValue{
		{Key: "exec", Value: "nodejs:18"},
		{Key: "web-export", Value: true},
	}

	t.Run("found returns value and true", func(t *testing.T) {
		v, ok := owAnnotation(anns, "exec")
		assert.True(t, ok)
		assert.Equal(t, "nodejs:18", v)
	})

	t.Run("missing returns false", func(t *testing.T) {
		_, ok := owAnnotation(anns, "require-whisk-auth")
		assert.False(t, ok)
	})

	t.Run("empty annotations", func(t *testing.T) {
		_, ok := owAnnotation(nil, "exec")
		assert.False(t, ok)
	})
}

func TestOwString(t *testing.T) {
	assert.Equal(t, "nodejs:18", owString("nodejs:18"))
	assert.Equal(t, "", owString(42))
	assert.Equal(t, "", owString(nil))
	assert.Equal(t, "", owString(true))
}
