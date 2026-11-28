// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case here is synthetic: no repository was scanned and no forge was
// asked. The GitHub cases reproduce the examples of GitHub's "About code
// owners" page (github/docs, content/repositories/
// managing-your-repositorys-settings-and-features/customizing-your-repository/
// about-code-owners.md, read 2026-11-26). The GitLab cases reproduce GitLab's
// "Syntax of CODEOWNERS file" and "Advanced CODEOWNERS configuration" pages
// (gitlab-org/gitlab doc/user/project/codeowners/reference.md and
// advanced.md, read 2026-11-26) and, where the pages are silent, the
// behaviour of GitLab's parser (ee/lib/gitlab/code_owners/file.rb and
// pattern_index.rb, read the same day). No case was checked against a live
// forge.

// owners returns the distinct owners of path, or nil.
func owners(t *testing.T, rules []Rule, path string, d Dialect) []string {
	t.Helper()
	return Names(Match(rules, path, d))
}

func mustParse(t *testing.T, content string, d Dialect) []Rule {
	t.Helper()
	rules, err := Parse(content, d)
	require.NoError(t, err)
	return rules
}

// githubExample is the example CODEOWNERS file of GitHub's documentation,
// without its last two blocks (they repeat /apps/ and are tested separately).
const githubExample = `# This is a comment.
# Each line is a file pattern followed by one or more owners.

*       @global-owner1 @global-owner2
*.js    @js-owner #This is an inline comment.
*.go docs@example.com
*.txt @octo-org/octocats
/build/logs/ @doctocat
docs/* docs@example.com
apps/ @octocat
/docs/ @doctocat
/scripts/ @doctocat @octocat
**/logs @octocat
`

func TestGitHubDocumentedExample(t *testing.T) {
	rules := mustParse(t, githubExample, GitHub)
	require.Len(t, rules, 10)
	assert.Equal(t, []string{"@js-owner"}, rules[1].Owners, "an inline comment ends the owners")

	cases := []struct {
		path string
		want []string
	}{
		// "*": the default owners for everything.
		{"README.md", []string{"@global-owner1", "@global-owner2"}},
		{"src/deep/file.rb", []string{"@global-owner1", "@global-owner2"}},
		// "the last matching pattern takes the most precedence": *.js.
		{"src/app.js", []string{"@js-owner"}},
		{"app.js", []string{"@js-owner"}},
		{"main.go", []string{"docs@example.com"}},
		{"notes.txt", []string{"@octo-org/octocats"}},
		// "/build/logs/": the directory at the root and its subdirectories.
		{"build/logs/out.log", []string{"@octocat"}}, // **/logs is later and also matches
		{"build/logs/2026/out.bin", []string{"@octocat"}},
		// "docs/*" matches docs/getting-started.md but not further nested
		// files; /docs/ is later and owns both.
		{"docs/getting-started.md", []string{"@doctocat"}},
		{"docs/build-app/troubleshooting.md", []string{"@doctocat"}},
		// "apps/": an apps directory anywhere.
		{"apps/main.c", []string{"@octocat"}},
		{"services/apps/web/main.c", []string{"@octocat"}},
		// "/scripts/".
		{"scripts/deploy.sh", []string{"@doctocat", "@octocat"}},
		// "**/logs": a logs directory such as /build/logs, /scripts/logs and
		// /deeply/nested/logs.
		{"scripts/logs/run.bin", []string{"@octocat"}},
		{"deeply/nested/logs/run.bin", []string{"@octocat"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, owners(t, rules, tc.path, GitHub))
		})
	}
}

// TestGitHubPatterns checks each documented pattern alone, so a later rule
// cannot hide a wrong match.
func TestGitHubPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{"*", []string{"a", "x/y/z.go", ".github/CODEOWNERS"}, nil},
		{"*.js", []string{"a.js", "x/y/a.js", ".eslintrc.js"}, []string{"a.ts", "a.jsx", "a.js.map"}},
		{"/build/logs/", []string{"build/logs/a", "build/logs/x/y"}, []string{"build/logs", "x/build/logs/a", "build/logsx/a"}},
		{"docs/*", []string{"docs/getting-started.md", "docs/.hidden"}, []string{"docs/build-app/troubleshooting.md", "x/docs/a.md", "docs"}},
		{"apps/", []string{"apps/a", "x/apps/y/z"}, []string{"apps", "myapps/a"}},
		{"/docs/", []string{"docs/a", "docs/a/b"}, []string{"x/docs/a", "docs"}},
		{"**/logs", []string{"logs/a", "build/logs/a", "deeply/nested/logs/a", "logs"}, []string{"logsx/a", "build/logs.txt"}},
		// gitignore semantics GitHub's page relies on: a name without a slash
		// matches a file or directory at any depth; a slash in the middle
		// anchors to the root; a final ** matches everything below.
		{"Makefile", []string{"Makefile", "sub/Makefile", "Makefile/x"}, []string{"Makefile.in", "makefile"}},
		{"cmd/server", []string{"cmd/server", "cmd/server/main.go"}, []string{"x/cmd/server/main.go"}},
		{"/apps/github", []string{"apps/github", "apps/github/x.go"}, []string{"apps/githubx", "x/apps/github"}},
		{"docs/**", []string{"docs/a", "docs/a/b/c"}, []string{"docs", "x/docs/a"}},
		{"a/**/b", []string{"a/b", "a/x/b", "a/x/y/b", "a/x/b/c"}, []string{"a/xb", "x/a/b"}},
		{"*.y?ml", []string{"ci.yaml", "x/ci.yxml"}, []string{"ci.yml", "ci.yaaml", "x.y/ml"}},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			rules := mustParse(t, tc.pattern+" @o", GitHub)
			for _, p := range tc.match {
				assert.Equal(t, []string{"@o"}, owners(t, rules, p, GitHub), "%s should match %s", tc.pattern, p)
			}
			for _, p := range tc.noMatch {
				assert.Nil(t, owners(t, rules, p, GitHub), "%s should not match %s", tc.pattern, p)
			}
		})
	}
}

func TestGitHubCaseSensitive(t *testing.T) {
	// "CODEOWNERS paths are case sensitive".
	rules := mustParse(t, "/Docs/ @o", GitHub)
	assert.Nil(t, owners(t, rules, "docs/a.md", GitHub))
	assert.Equal(t, []string{"@o"}, owners(t, rules, "Docs/a.md", GitHub))
}

func TestGitHubEmptyOwnersOverride(t *testing.T) {
	// "/apps/github" with no owners: changes there need no code owner.
	rules := mustParse(t, "/apps/ @octocat\n/apps/github\n", GitHub)
	assert.Equal(t, []string{"@octocat"}, owners(t, rules, "apps/web/a.go", GitHub))
	assert.Nil(t, owners(t, rules, "apps/github/a.go", GitHub))

	matched := MatchRules(rules, "apps/github/a.go", GitHub)
	require.Len(t, matched, 1, "the ownerless rule still decides the path")
	assert.Equal(t, 2, matched[0].Line)

	// "this subdirectory has its own owner @doctocat".
	rules = mustParse(t, "/apps/ @octocat\n/apps/github @doctocat\n", GitHub)
	assert.Equal(t, []string{"@doctocat"}, owners(t, rules, "apps/github/a.go", GitHub))
}

func TestGitHubOwnerCarriesRule(t *testing.T) {
	rules := mustParse(t, "# header\n\n*.go @a @b\n", GitHub)
	got := Match(rules, "x.go", GitHub)
	require.Len(t, got, 2)
	assert.Equal(t, "@a", got[0].Name)
	assert.Equal(t, "*.go", got[0].Rule.Pattern)
	assert.Equal(t, 3, got[0].Rule.Line)
	assert.Equal(t, "", got[0].Rule.Section)
}

func TestGitHubSkipsUnsupportedLines(t *testing.T) {
	// GitHub: "If any line in your CODEOWNERS file contains invalid syntax,
	// that line will be skipped", and `\#`, `!` and `[ ]` do not work.
	content := "* @default\n" +
		"!*.md @nobody\n" +
		"*.[ch] @c-team\n" +
		"\\#notes @hash\n" +
		"*.py not-an-owner\n" +
		"*.rb @ruby\r\n"
	rules, err := Parse(content, GitHub)
	require.Error(t, err)

	var lines []int
	for _, e := range unwrap(err) {
		var le *LineError
		require.True(t, errors.As(e, &le))
		lines = append(lines, le.Line)
	}
	assert.Equal(t, []int{2, 3, 4, 5}, lines)

	require.Len(t, rules, 2)
	assert.Equal(t, []string{"@default"}, owners(t, rules, "a.md", GitHub))
	assert.Equal(t, []string{"@default"}, owners(t, rules, "a.c", GitHub))
	assert.Equal(t, []string{"@default"}, owners(t, rules, "a.py", GitHub))
	assert.Equal(t, []string{"@ruby"}, owners(t, rules, "a.rb", GitHub), "CRLF line endings are accepted")
}

// gitlabReadme is the README example of GitLab's "Sections" documentation.
const gitlabReadme = `* @admin

[README Owners]
README.md @user1 @user2
internal/README.md @user4

[README other owners]
README.md @user3
`

func TestGitLabSections(t *testing.T) {
	rules := mustParse(t, gitlabReadme, GitLab)

	// "The Code Owners for the README.md in the root directory are: @admin,
	// @user1 and @user2, @user3."
	assert.Equal(t, []string{"@admin", "@user1", "@user2", "@user3"}, owners(t, rules, "README.md", GitLab))
	// "The Code Owners for internal/README.md are: @admin, @user4, @user3."
	assert.Equal(t, []string{"@admin", "@user4", "@user3"}, owners(t, rules, "internal/README.md", GitLab))

	matched := MatchRules(rules, "internal/README.md", GitLab)
	require.Len(t, matched, 3)
	assert.Equal(t, []string{"", "README Owners", "README other owners"},
		[]string{matched[0].Section, matched[1].Section, matched[2].Section})
	assert.Equal(t, []int{1, 5, 8}, []int{matched[0].Line, matched[1].Line, matched[2].Line})
	assert.Equal(t, []string{"@admin"}, owners(t, rules, "src/main.go", GitLab))
}

func TestGitLabDefaultOwners(t *testing.T) {
	// "Set default Code Owner for a section".
	content := `[Documentation] @docs-team
docs/
README.md

[Database] @database-team @agarcia
model/db/
model/db/database-setup.md @docs-team
`
	rules := mustParse(t, content, GitLab)
	assert.Equal(t, []string{"@docs-team"}, owners(t, rules, "docs/guide/intro.md", GitLab))
	assert.Equal(t, []string{"@docs-team"}, owners(t, rules, "README.md", GitLab))
	assert.Equal(t, []string{"@database-team", "@agarcia"}, owners(t, rules, "model/db/schema.rb", GitLab))
	assert.Equal(t, []string{"@docs-team"}, owners(t, rules, "model/db/database-setup.md", GitLab))
}

func TestGitLabRegularEntriesAndSections(t *testing.T) {
	// "A merge request that modifies model/db/CHANGELOG.txt would require
	// three approvals: one from each of the @general-approvers, @docs-team,
	// and @database-team groups."
	content := `* @general-approvers

[Documentation] @docs-team
docs/
README.md
*.txt

[Database] @database-team
model/db/
model/db/database-setup.md @docs-team
`
	rules := mustParse(t, content, GitLab)
	assert.Equal(t, []string{"@general-approvers", "@docs-team", "@database-team"},
		owners(t, rules, "model/db/CHANGELOG.txt", GitLab))
}

func TestGitLabDuplicateSections(t *testing.T) {
	// "This code results in three entries under the Documentation section
	// header, and two entries under Database ... using the case of the first
	// section."
	content := `[Documentation]
ee/docs/    @docs
docs/       @docs

[Database]
README.md  @database
model/db/   @database

[DOCUMENTATION]
README.md  @docs
`
	rules := mustParse(t, content, GitLab)
	count := map[string]int{}
	for _, r := range rules {
		count[r.Section]++
	}
	assert.Equal(t, map[string]int{"Documentation": 3, "Database": 2}, count)
	matched := MatchRules(rules, "README.md", GitLab)
	require.Len(t, matched, 2)
	assert.Equal(t, "Documentation", matched[0].Section, "sections keep the order of their first header")
	assert.Equal(t, []string{"@docs", "@database"}, owners(t, rules, "README.md", GitLab))
}

func TestGitLabOptionalAndApprovals(t *testing.T) {
	content := `[Documentation][2] @docs-team
docs/
README.md

^[Database] @database-team
model/db/

^[Go]
*.go @root

[Go]
*.mod @root
`
	rules := mustParse(t, content, GitLab)
	byLine := map[int]Rule{}
	for _, r := range rules {
		byLine[r.Line] = r
	}
	assert.Equal(t, 2, byLine[2].ApprovalsRequired)
	assert.False(t, byLine[2].Optional)
	assert.True(t, byLine[6].Optional, "^[Database] is optional")
	assert.Equal(t, []string{"@database-team"}, byLine[6].Owners)
	// "If a section is duplicated in the file, and one of them is marked as
	// optional and the other isn't, the section is required."
	assert.False(t, byLine[9].Optional)
	assert.False(t, byLine[12].Optional)
}

func TestGitLabPaths(t *testing.T) {
	// "Path matching" in GitLab's syntax reference.
	cases := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{"/README.md", []string{"README.md"}, []string{"docs/README.md"}},
		{"/docs/README.md", []string{"docs/README.md"}, []string{"README.md", "x/docs/README.md"}},
		{"README.md", []string{"README.md", "internal/README.md", "app/lib/README.md"}, []string{"README.mdx"}},
		{"internal/README.md", []string{"internal/README.md", "docs/internal/README.md", "docs/api/internal/README.md"}, []string{"README.md"}},
		{"/docs/", []string{"docs/a.md", "docs/a/b/c.md"}, []string{"x/docs/a.md"}},
		{"/docs/*.md", []string{"docs/a.md"}, []string{"docs/a/b.md", "docs/a.rb"}},
		{"/docs/index.*", []string{"docs/index.md", "docs/index.html", "docs/index.xml"}, []string{"docs/indexes.md"}},
		{"/docs/*spec*", []string{"docs/qa_specs.rb", "docs/spec_helpers.rb", "docs/runtime.spec"}, []string{"docs/a/spec.rb"}},
		{"/docs/*/README.md", []string{"docs/api/README.md"}, []string{"docs/README.md", "docs/a/b/README.md"}},
		{"/docs/**/index.md", []string{"docs/index.md", "docs/api/index.md", "docs/api/graphql/index.md"}, []string{"docs/api/index.mdx"}},
		// "A trailing /** behaves like * and matches files one level deep."
		{"/docs/**", []string{"docs/index.md"}, []string{"docs/api/index.md"}},
		{"/docs/**/*", []string{"docs/index.md", "docs/api/index.md"}, nil},
		// "**/*.rb matches config/database.rb and
		// app/controllers/users/stars_controller.rb".
		{"**/*.rb", []string{"config/database.rb", "app/controllers/users/stars_controller.rb"}, []string{"a.rbx"}},
		// FNM_DOTMATCH: "* matches dotfiles like .gitignore".
		{"*", []string{".gitignore", "a/.env"}, nil},
		// A pattern without a trailing slash names a file: GitLab's parser
		// adds `**/*` only for a trailing `/`.
		{"/ee/docs", []string{"ee/docs"}, []string{"ee/docs/a.md"}},
		// fnmatch character classes and escapes.
		{"*.[ch]", []string{"a.c", "x/a.h"}, []string{"a.o"}},
		{"*.[!o]", []string{"a.c"}, []string{"a.o"}},
		{`/a\*b`, []string{"a*b"}, []string{"axb"}},
		// "Escape whitespace in paths with backslashes".
		{`path\ with\ spaces/*.md`, []string{"path with spaces/a.md", "x/path with spaces/b.md"}, []string{"path/a.md"}},
		// "Remove `\` when escaping `\#`".
		{`\#notes.md`, []string{"#notes.md"}, []string{"notes.md"}},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			rules := mustParse(t, tc.pattern+" @o", GitLab)
			require.Len(t, rules, 1)
			for _, p := range tc.match {
				assert.Equal(t, []string{"@o"}, owners(t, rules, p, GitLab), "%s should match %s", tc.pattern, p)
			}
			for _, p := range tc.noMatch {
				assert.Nil(t, owners(t, rules, p, GitLab), "%s should not match %s", tc.pattern, p)
			}
		})
	}
}

func TestGitLabExclusions(t *testing.T) {
	// "Exclusion patterns" in GitLab's syntax reference.
	content := `* @username
!pom.xml

[Ruby]
*.rb @ruby-team
!/config/**/*.rb

[Config]
/config/ @ops-team
`
	rules := mustParse(t, content, GitLab)
	assert.Nil(t, owners(t, rules, "pom.xml", GitLab))
	assert.Equal(t, []string{"@username", "@ruby-team"}, owners(t, rules, "app/a.rb", GitLab))
	// "Config files still require ops-team approval."
	assert.Equal(t, []string{"@username", "@ops-team"}, owners(t, rules, "config/routes.rb", GitLab))

	// "After a pattern is excluded, it cannot be included again in the same
	// section."
	rules = mustParse(t, "* @default-owner\n!*.rb\n/special/*.rb @ruby-owner\n", GitLab)
	assert.Nil(t, owners(t, rules, "special/a.rb", GitLab))
	assert.Equal(t, []string{"@default-owner"}, owners(t, rules, "special/a.go", GitLab))
}

func TestGitLabSamePatternReplaced(t *testing.T) {
	// GitLab's parser keys a section's rules by normalized pattern, so a
	// later rule with the same pattern replaces the earlier one, even when
	// one of them is an exclusion.
	rules := mustParse(t, "!*.md\n*.md @docs\n", GitLab)
	require.Len(t, rules, 1)
	assert.Equal(t, []string{"@docs"}, owners(t, rules, "a.md", GitLab))

	rules = mustParse(t, "docs/ @a\n/**/docs/ @b\n", GitLab)
	require.Len(t, rules, 1, "docs/ and /**/docs/ normalize to one pattern")
	assert.Equal(t, 2, rules[0].Line)
}

func TestGitLabMalformedLines(t *testing.T) {
	content := `* @group
[Section name
docs/ @docs_group
/path/* @group user_without_at_symbol @user_with_at_symbol
/docs/**/*.md @markdown-docs  # Match specific file types in any subdirectory
/orphan/
[]
`
	rules, err := Parse(content, GitLab)
	require.Error(t, err)
	var lines []int
	for _, e := range unwrap(err) {
		var le *LineError
		require.True(t, errors.As(e, &le))
		lines = append(lines, le.Line)
	}
	// 2: unparsable header; 4 and 5: tokens that are not owners; 6: no owners;
	// 7: a header without a name.
	assert.Equal(t, []int{2, 4, 5, 6, 7}, lines)

	// "GitLab ignores the heading [Section name. The default section includes
	// two rules."
	assert.Equal(t, []string{"@docs_group"}, owners(t, rules, "docs/a", GitLab))
	// "This entry is owned by @group and @user_with_at_symbol."
	assert.Equal(t, []string{"@group", "@user_with_at_symbol"}, owners(t, rules, "path/a", GitLab))
	// Inline comments are unsupported; only the owner-shaped words count.
	assert.Equal(t, []string{"@markdown-docs"}, owners(t, rules, "docs/a/b.md", GitLab))
	// A rule without owners still decides the path.
	assert.Nil(t, owners(t, rules, "orphan/a", GitLab))
}

func TestGitLabRoleAndEmailOwners(t *testing.T) {
	rules := mustParse(t, "/config/ @@maintainer\nLICENSE @legal janedoe@gitlab.com\nREADME @group @group/with-nested/subgroup\n", GitLab)
	assert.Equal(t, []string{"@@maintainer"}, owners(t, rules, "config/a.yml", GitLab))
	assert.Equal(t, []string{"@legal", "janedoe@gitlab.com"}, owners(t, rules, "LICENSE", GitLab))
	assert.Equal(t, []string{"@group", "@group/with-nested/subgroup"}, owners(t, rules, "README", GitLab))
}

func TestNoMatchNoOwner(t *testing.T) {
	for _, d := range []Dialect{GitHub, GitLab} {
		t.Run(d.String(), func(t *testing.T) {
			rules := mustParse(t, "/docs/ @docs\n", d)
			assert.Nil(t, Match(rules, "src/main.go", d), "never a fallback owner")
			assert.Nil(t, MatchRules(rules, "src/main.go", d))
			assert.Nil(t, Match(rules, "", d))
			assert.Nil(t, Match(nil, "docs/a", d))
		})
	}
}

func TestEmptyFile(t *testing.T) {
	for _, d := range []Dialect{GitHub, GitLab} {
		for _, content := range []string{"", "\n\n", "# only a comment\n"} {
			rules, err := Parse(content, d)
			assert.NoError(t, err)
			assert.Empty(t, rules)
		}
	}
	_, err := Parse("* @a", Dialect(0))
	assert.ErrorIs(t, err, ErrDialect)
}

func TestPathForms(t *testing.T) {
	rules := mustParse(t, "/docs/ @o\n", GitHub)
	for _, p := range []string{"docs/a.md", "/docs/a.md", "./docs/a.md", "docs//a.md"} {
		assert.Equal(t, []string{"@o"}, owners(t, rules, p, GitHub), p)
	}
}

func TestHandBuiltRules(t *testing.T) {
	// Rules not from Parse are compiled on use.
	rules := []Rule{{Pattern: "*.go", Owners: []string{"@go"}, Line: 1}}
	assert.Equal(t, []string{"@go"}, owners(t, rules, "a/b.go", GitHub))
	assert.Equal(t, []string{"@go"}, owners(t, rules, "a/b.go", GitLab))
}

func TestNames(t *testing.T) {
	rules := mustParse(t, "* @a @b\n[S]\n*.go @b @c\n", GitLab)
	assert.Equal(t, []string{"@a", "@b", "@c"}, Names(Match(rules, "x.go", GitLab)))
}

func unwrap(err error) []error {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		return u.Unwrap()
	}
	return []error{err}
}

// BenchmarkMatch is BenchmarkIndexMatch without the index, on fewer paths.
func BenchmarkMatch(b *testing.B) {
	for _, d := range []Dialect{GitHub, GitLab} {
		b.Run(d.String(), func(b *testing.B) {
			rules, paths := benchFile(b, d)
			paths = paths[:1000]
			for b.Loop() {
				for _, p := range paths {
					_ = Match(rules, p, d)
				}
			}
		})
	}
}
