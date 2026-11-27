// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"strings"
	"testing"
	"time"

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

// TestDoubleStarBacktracking matches patterns with many `**` segments against
// a deep path. Without memoization each `**` multiplies the work by the path
// depth: 12 of them against 40 segments did not finish in minutes, so a
// single CODEOWNERS line from a scanned repository could hang the scan.
// Synthetic; no real CODEOWNERS file showed this.
func TestDoubleStarBacktracking(t *testing.T) {
	deep := strings.Repeat("a/", 40)
	for _, d := range []Dialect{GitHub, GitLab} {
		rules := mustParse(t, "/"+strings.Repeat("**/a/", 12)+"b @o\n", d)
		start := time.Now()
		assert.Empty(t, MatchRules(rules, deep+"c", d), d.String())
		assert.Len(t, MatchRules(rules, deep+"b", d), 1, d.String())
		assert.Less(t, time.Since(start), 2*time.Second, d.String())
	}
}
