// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versionx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConstraintCheck(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		want       bool
	}{
		// plain operators
		{"1.2.3", ">= 1.0.0", true},
		{"1.2.3", ">= 1.2.3", true},
		{"1.2.3", "> 1.2.3", false},
		{"1.2.3", "< 2.0.0", true},
		{"1.2.3", "< 1.2.3", false},
		{"1.2.3", "<= 1.2.3", true},
		{"1.2.3", "= 1.2.3", true},
		{"1.2.3", "== 1.2.3", true},
		{"1.2.3", "!= 1.2.3", false},
		{"1.2.3", "!= 1.2.4", true},
		{"1.2.3", ">=1.0.0", true /* no space */},
		{"1.2", "= 1.2.0", true /* semantic equality */},

		// caret: the major line, with npm's 0.x carve-outs
		{"1.9.0", "^1.2.3", true},
		{"2.0.0", "^1.2.3", false},
		{"1.2.2", "^1.2.3", false},
		{"0.2.9", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false},
		{"0.0.3", "^0.0.3", true},
		{"0.0.4", "^0.0.3", false},

		// tilde: the minor line
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.9.9", "~1", true},
		{"2.0.0", "~1", false},
		{"1.2.9", "~>1.2.3", true},

		// wildcards
		{"1.2.9", "1.2.x", true},
		{"1.3.0", "1.2.x", false},
		{"1.9.9", "1.x", true},
		{"2.0.0", "1.*", false},
		{"42.0.0", "x", true},

		// the shapes a semver-only implementation had to refuse
		{"1.2.3.4.5", ">= 1.0.0", true},
		{"1.2.3.4.5", "< 2.0.0", true},
		{"126.0.6478.126", ">= 100.0.0.0", true},
		{"1:1.2.3", ">= 1.0.0", true /* epoch outranks */},
		{"1:1.2.3", "< 2.0.0", false /* epoch outranks */},
		{"1.1.1k", ">= 1.1.1f", true},
		{"4.18.0-425.13.1.el8_7", "> 4.18.0-425.3.1.el8_7", true},
	}

	for _, tt := range tests {
		t.Run(tt.version+" "+tt.constraint, func(t *testing.T) {
			c, err := ParseConstraint(tt.constraint)
			require.NoError(t, err)
			assert.Equal(t, tt.want, c.Check(Parse(tt.version)))
		})
	}
}

func TestSatisfies(t *testing.T) {
	ok, err := Satisfies(Parse("1.2.3"), ">= 1.0.0", "< 2.0.0")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = Satisfies(Parse("1.2.3"), ">= 1.0.0", "< 1.2.0")
	require.NoError(t, err)
	assert.False(t, ok)

	// An unparseable bound is an error, never a quiet false: a typo that matched
	// nothing would read as "no version qualifies".
	_, err = Satisfies(Parse("1.2.3"), ">= ")
	assert.Error(t, err)
}

func TestParseConstraintErrors(t *testing.T) {
	for _, s := range []string{"", "   ", ">=", "^", "^abc", "~"} {
		t.Run(s, func(t *testing.T) {
			_, err := ParseConstraint(s)
			assert.Error(t, err)
		})
	}
}

func TestNeedsOperator(t *testing.T) {
	// Bare versions: a caller may default these to ">=" / "<=".
	for _, s := range []string{"1.2.3", "1.2", "1:1.2.3", "1.1.1k", " 1.2.3 "} {
		assert.True(t, NeedsOperator(s), s)
	}
	// Already-bounded: prefixing an operator onto these would stack two of them.
	for _, s := range []string{">= 1.2.3", "< 2.0.0", "^1.2.3", "~1.2.3", "~>1.2.3", "1.2.x", "1.*", "= 1.2.3", "!= 1.2.3"} {
		assert.False(t, NeedsOperator(s), s)
	}
}

// Stacking is what a caller produces when it defaults a bare bound to ">=" without
// asking NeedsOperator first. Left unchecked it compares against the junk version
// "^1.2.3" and answers true for everything above it.
func TestStackedOperatorsRejected(t *testing.T) {
	for _, s := range []string{">= ^1.2.3", "<= ~1.2.3", ">= >= 1.2.3", "< != 1.0"} {
		t.Run(s, func(t *testing.T) {
			_, err := ParseConstraint(s)
			assert.Error(t, err)
		})
	}
}
