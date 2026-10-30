// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package semver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParserCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
		why  string
	}{
		{"1.2.3", "1.2.3", 0, "identical"},
		{"1.2", "1.2.0", 0, "missing components are zeros"},
		{"1.9.0", "1.10.0", -1, "minor is numeric, not lexical"},
		{"v2.0.0", "1.9.9", 1, "a leading v is decoration"},
		{"1.0.0-rc1", "1.0.0", -1, "a prerelease leads its release"},
		// Differs from the Masterminds parser this used to wrap, which read every
		// dash-suffix as a prerelease. See the Parser doc.
		{"1.0.0-1", "1.0.0", 1, "a bare numeric suffix is a later build"},
	}

	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			got, err := Parser{}.Compare(tt.a, tt.b)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, tt.why)

			got, err = Parser{}.Compare(tt.b, tt.a)
			require.NoError(t, err)
			assert.Equal(t, -tt.want, got, "compare must be antisymmetric")
		})
	}
}

func TestParserCompareRejectsNonSemver(t *testing.T) {
	// The strict half of versionx: these all compare fine there, and must not here.
	for _, v := range []string{"1:2.4.52-1ubuntu4.6", "126.0.6478.126", "1.1.1k", "latest", ""} {
		t.Run(v, func(t *testing.T) {
			_, err := Parser{}.Compare(v, "1.0.0")
			assert.Error(t, err, "left side")

			_, err = Parser{}.Compare("1.0.0", v)
			assert.Error(t, err, "right side")
		})
	}
}
