// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// All cases are synthetic edge cases of the segment matcher.

func TestSegmentMatch(t *testing.T) {
	cases := []struct {
		pattern string
		gitlab  bool
		name    string
		want    bool
	}{
		{"*", false, "", true},
		{"*", false, ".env", true},
		{"a*b*c", false, "aXbYc", true},
		{"a*b*c", false, "aXbY", false},
		{"a**b", false, "aXb", true},
		{"*.go", false, "x.go.bak", false},
		{"?", false, "é", true},
		{"??", false, "é", false},
		{"[a-c]x", true, "bx", true},
		{"[a-c]x", true, "dx", false},
		{"[^a-c]x", true, "dx", true},
		{"[]]", true, "]", true},
		{"[a-]", true, "-", true},
		{"[abc", true, "[abc", true},
		{`\[a]`, true, "[a]", true},
		{"[ab]", false, "[ab]", true}, // no classes in the GitHub dialect
	}
	for _, tc := range cases {
		seg := compileSegment(tc.pattern, tc.gitlab)
		assert.Equal(t, tc.want, seg.match(tc.name), "%q against %q", tc.pattern, tc.name)
	}
}

func TestNormalizeGitLab(t *testing.T) {
	cases := map[string]string{
		"*":         "/**/*",
		"README.md": "/**/README.md",
		"/docs/":    "/docs/**/*",
		"docs/":     "/**/docs/**/*",
		`\#a`:       "/**/#a",
		`a\ b\  c`:  "/**/a b c",
		"/a/**":     "/a/**",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeGitLab(in), in)
	}
}
