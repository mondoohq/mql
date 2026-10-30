// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apk_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/core/resources/versions/apk"
	"go.mondoo.com/mql/providers/core/resources/versions/generic"
)

const (
	LESS    = -1
	EQUAL   = 0
	GREATER = 1
)

func TestParseAndCompare(t *testing.T) {
	cases := []struct {
		v1       string
		expected int
		v2       string
	}{
		// Alpine Linux corner cases.
		{"1.2.2-r7", GREATER, "1.2.2_pre2-r0"},
		// Test version with epoch
		{generic.VersionWithoutEpoch("1632431095:1.2.2-r7"), GREATER, "1.2.2_pre2-r0"},
	}

	var (
		p   apk.Parser
		cmp int
		err error
	)
	for _, c := range cases {
		cmp, err = p.Compare(c.v1, c.v2)
		assert.Nil(t, err)
		assert.Equal(t, c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v1, c.v2, cmp, c.expected)

		cmp, err = p.Compare(c.v2, c.v1)
		assert.Nil(t, err)
		assert.Equal(t, -c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v2, c.v1, cmp, -c.expected)
	}
}
