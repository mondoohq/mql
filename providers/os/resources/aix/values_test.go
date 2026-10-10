// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBool(t *testing.T) {
	for in, want := range map[string]bool{"true": true, "yes": true, " ON ": true, "false": false, "no": false, "off": false} {
		b, ok := ParseBool(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, b, in)
	}
	_, ok := ParseBool("maybe")
	assert.False(t, ok)
}
