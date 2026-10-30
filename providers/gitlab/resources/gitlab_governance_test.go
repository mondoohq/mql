// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGIDInt(t *testing.T) {
	tests := []struct {
		name string
		gid  string
		want int64
	}{
		{"user gid", "gid://gitlab/User/123", 123},
		{"vulnerability gid", "gid://gitlab/Vulnerability/9876543210", 9876543210},
		{"bare number without slash", "42", 0},
		{"empty", "", 0},
		{"no trailing number", "gid://gitlab/User/", 0},
		{"non-numeric tail", "gid://gitlab/User/abc", 0},
		{"trailing slash only", "/", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseGIDInt(tt.gid))
		})
	}
}

func TestIsVulnerabilitiesUnavailable(t *testing.T) {
	tests := []struct {
		name string
		errs []gqlGraphQLError
		want bool
	}{
		{
			name: "no errors is available",
			errs: nil,
			want: false,
		},
		{
			name: "permission error is unavailable",
			errs: []gqlGraphQLError{{Message: "You don't have permission to access this resource"}},
			want: true,
		},
		{
			name: "feature not available is unavailable",
			errs: []gqlGraphQLError{{Message: "Vulnerabilities are not available on this plan"}},
			want: true,
		},
		{
			name: "schema field missing is unavailable",
			errs: []gqlGraphQLError{{Message: "Field 'vulnerabilities' doesn't exist on type 'Project'"}},
			want: true,
		},
		{
			name: "license error is unavailable",
			errs: []gqlGraphQLError{{Message: "This feature requires an Ultimate license"}},
			want: true,
		},
		{
			name: "case-insensitive match",
			errs: []gqlGraphQLError{{Message: "PERMISSION DENIED"}},
			want: true,
		},
		{
			name: "genuine error is available (should surface)",
			errs: []gqlGraphQLError{{Message: "internal server error"}},
			want: false,
		},
		{
			name: "mixed: any genuine error makes it available",
			errs: []gqlGraphQLError{
				{Message: "permission denied"},
				{Message: "unexpected token in query"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isVulnerabilitiesUnavailable(tt.errs))
		})
	}
}

func TestParseCodeowners(t *testing.T) {
	t.Run("empty content returns nil", func(t *testing.T) {
		assert.Nil(t, parseCodeowners(""))
	})

	t.Run("comments and blank lines are skipped", func(t *testing.T) {
		rules := parseCodeowners("# this is a comment\n\n   \n# another\n")
		assert.Empty(t, rules)
	})

	t.Run("simple pattern with multiple owners", func(t *testing.T) {
		rules := parseCodeowners("*.go @go-team @ci-bot\n")
		require.Len(t, rules, 1)
		r := rules[0]
		assert.Equal(t, 1, r.LineNumber)
		assert.Equal(t, "", r.Section)
		assert.True(t, r.Required)
		assert.False(t, r.Optional)
		assert.Equal(t, 0, r.ApprovalsRequired)
		assert.Equal(t, "*.go", r.Pattern)
		assert.Equal(t, []string{"@go-team", "@ci-bot"}, r.Owners)
	})

	t.Run("sections, optional sections, approvals, and line numbers", func(t *testing.T) {
		content := "# Comment line\n" + // 1
			"*.go @go-team @ci\n" + //          2
			"\n" + //                           3
			"[Backend]\n" + //                  4
			"src/ @backend\n" + //              5
			"\n" + //                           6
			"^[Optional][2]\n" + //             7
			"docs/ @docs-team user@example.com" // 8 (no trailing newline)

		rules := parseCodeowners(content)
		require.Len(t, rules, 3)

		// Line 2: top-level rule, no section.
		assert.Equal(t, 2, rules[0].LineNumber)
		assert.Equal(t, "", rules[0].Section)
		assert.True(t, rules[0].Required)
		assert.False(t, rules[0].Optional)
		assert.Equal(t, "*.go", rules[0].Pattern)
		assert.Equal(t, []string{"@go-team", "@ci"}, rules[0].Owners)

		// Line 5: inside required [Backend] section.
		assert.Equal(t, 5, rules[1].LineNumber)
		assert.Equal(t, "Backend", rules[1].Section)
		assert.True(t, rules[1].Required)
		assert.False(t, rules[1].Optional)
		assert.Equal(t, 0, rules[1].ApprovalsRequired)
		assert.Equal(t, "src/", rules[1].Pattern)

		// Line 8: inside optional ^[Optional][2] section, approvals carried over.
		assert.Equal(t, 8, rules[2].LineNumber)
		assert.Equal(t, "Optional", rules[2].Section)
		assert.False(t, rules[2].Required)
		assert.True(t, rules[2].Optional)
		assert.Equal(t, 2, rules[2].ApprovalsRequired)
		assert.Equal(t, "docs/", rules[2].Pattern)
		assert.Equal(t, []string{"@docs-team", "user@example.com"}, rules[2].Owners)
	})

	t.Run("section approval count resets between sections", func(t *testing.T) {
		content := "[A][3]\n" + //   1
			"a/ @team-a\n" + //      2
			"[B]\n" + //             3
			"b/ @team-b" //          4

		rules := parseCodeowners(content)
		require.Len(t, rules, 2)
		assert.Equal(t, "A", rules[0].Section)
		assert.Equal(t, 3, rules[0].ApprovalsRequired)
		assert.Equal(t, "B", rules[1].Section)
		assert.Equal(t, 0, rules[1].ApprovalsRequired)
	})
}

func TestParseCodeownersSectionsWithDefaultOwners(t *testing.T) {
	// GitLab lets a section header carry default owners, which apply to every
	// pattern in the section that does not name its own. Rejecting that form
	// turned the header into a rule whose pattern was the literal "[Database]"
	// and, worse, left the section state pointing at the *previous* section —
	// so a required section was reported as optional for the rest of the file.
	t.Run("required section with default owners", func(t *testing.T) {
		rules := parseCodeowners("[Database] @dba-team\ndb/schema.rb\ndb/migrate/ @migrations\n")
		require.Len(t, rules, 2, "the header must not become a rule")

		assert.Equal(t, "db/schema.rb", rules[0].Pattern)
		assert.Equal(t, "Database", rules[0].Section)
		assert.True(t, rules[0].Required)
		assert.False(t, rules[0].Optional)
		assert.Equal(t, []string{"@dba-team"}, rules[0].Owners,
			"a pattern with no owners inherits the section defaults")

		assert.Equal(t, "db/migrate/", rules[1].Pattern)
		assert.Equal(t, []string{"@migrations"}, rules[1].Owners,
			"an explicit owner list wins over the section defaults")
	})

	t.Run("optional section with approvals and default owners", func(t *testing.T) {
		rules := parseCodeowners("^[Review][2] @a @b\nsrc/\n")
		require.Len(t, rules, 1)
		assert.Equal(t, "Review", rules[0].Section)
		assert.True(t, rules[0].Optional)
		assert.False(t, rules[0].Required)
		assert.Equal(t, 2, rules[0].ApprovalsRequired)
		assert.Equal(t, []string{"@a", "@b"}, rules[0].Owners)
	})

	t.Run("section state advances past a default-owner header", func(t *testing.T) {
		rules := parseCodeowners("^[Optional]\nexperiments/ @lab\n[Database] @dba\ndb/schema.rb\n")
		require.Len(t, rules, 2)

		assert.Equal(t, "Optional", rules[0].Section)
		assert.True(t, rules[0].Optional)

		assert.Equal(t, "Database", rules[1].Section)
		assert.True(t, rules[1].Required, "the required section must not inherit optional")
		assert.False(t, rules[1].Optional)
	})

	t.Run("bare headers still parse", func(t *testing.T) {
		rules := parseCodeowners("[Docs]\nREADME.md @docs\n")
		require.Len(t, rules, 1)
		assert.Equal(t, "Docs", rules[0].Section)
		assert.Equal(t, []string{"@docs"}, rules[0].Owners)
	})

	t.Run("pattern with no owners and no section defaults", func(t *testing.T) {
		rules := parseCodeowners("docs/\n")
		require.Len(t, rules, 1)
		assert.Empty(t, rules[0].Owners, "an unowned path must stay unowned")
	})
}
