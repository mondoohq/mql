// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"reflect"
	"strings"
	"testing"
)

// The documentation examples the tests run against, copied verbatim from the
// forges' own documentation sources:
//
//   - GitHub: github/docs e0b0c90 (2026-11-23),
//     content/repositories/.../about-code-owners.md, "Example of a CODEOWNERS file".
//   - GitLab: gitlabhq/gitlabhq d7b9a61 (2026-10-23),
//     doc/user/project/codeowners/reference.md and advanced.md.
//
// Do not edit them to make a test pass: they are the ground truth.

const gitHubDocExample = `# This is a comment.
# Each line is a file pattern followed by one or more owners.

# These owners will be the default owners for everything in
# the repo. Unless a later match takes precedence,
# @global-owner1 and @global-owner2 will be requested for
# review when someone opens a pull request.
*       @global-owner1 @global-owner2

# Order is important; the last matching pattern takes the most
# precedence. When someone opens a pull request that only
# modifies JS files, only @js-owner and not the global
# owner(s) will be requested for a review.
*.js    @js-owner #This is an inline comment.

# You can also use email addresses if you prefer. They'll be
# used to look up users just like we do for commit author
# emails.
*.go docs@example.com

# Teams can be specified as code owners as well. Teams should
# be identified in the format @org/team-name. Teams must have
# explicit write access to the repository. In this example,
# the octocats team in the octo-org organization owns all .txt files.
*.txt @octo-org/octocats

# In this example, @doctocat owns any files in the build/logs
# directory at the root of the repository and any of its
# subdirectories.
/build/logs/ @doctocat

# The ` + "`" + `docs/*` + "`" + ` pattern will match files like
# ` + "`" + `docs/getting-started.md` + "`" + ` but not further nested files like
# ` + "`" + `docs/build-app/troubleshooting.md` + "`" + `.
docs/* docs@example.com

# In this example, @octocat owns any file in an apps directory
# anywhere in your repository.
apps/ @octocat

# In this example, @doctocat owns any file in the ` + "`" + `/docs` + "`" + `
# directory in the root of your repository and any of its
# subdirectories.
/docs/ @doctocat

# In this example, any change inside the ` + "`" + `/scripts` + "`" + ` directory
# will require approval from @doctocat or @octocat.
/scripts/ @doctocat @octocat

# In this example, @octocat owns any file in a ` + "`" + `/logs` + "`" + ` directory such as
# ` + "`" + `/build/logs` + "`" + `, ` + "`" + `/scripts/logs` + "`" + `, and ` + "`" + `/deeply/nested/logs` + "`" + `. Any changes
# in a ` + "`" + `/logs` + "`" + ` directory will require approval from @octocat.
**/logs @octocat

# In this example, @octocat owns any file in the ` + "`" + `/apps` + "`" + `
# directory in the root of your repository except for the ` + "`" + `/apps/github` + "`" + `
# subdirectory, as its owners are left empty. Without an owner, changes
# to ` + "`" + `apps/github` + "`" + ` can be made with the approval of any user who has
# write access to the repository.
/apps/ @octocat
/apps/github

# In this example, @octocat owns any file in the ` + "`" + `/apps` + "`" + `
# directory in the root of your repository except for the ` + "`" + `/apps/github` + "`" + `
# subdirectory, as this subdirectory has its own owner @doctocat
/apps/ @octocat
/apps/github @doctocat
`

// reference.md, the opening examples.
const gitLabDocOverview = `# Specify a default Code Owner for all files with a wildcard:
* @default-owner

# Specify multiple Code Owners to a specific file:
README.md @doc-team @tech-lead

# Specify a Code Owner to all files with a specific extension:
*.rb @ruby-owner

# Specify Code Owners with usernames or email addresses:
LICENSE @legal janedoe@gitlab.com

# Use group names to match groups and nested groups:
README @group @group/with-nested/subgroup

# Specify a Code Owner to a directory and all its contents:
/docs/ @all-docs
/docs/* @root-docs
/docs/**/*.md @markdown-docs  # Match specific file types in any subdirectory
/db/**/index.md @index-docs   # Match a specific file name in any subdirectory

# Use a section to group related rules:
[Documentation]
ee/docs    @docs
docs       @docs

# Assign a role as a Code Owner:
/config/ @@maintainer
`

// reference.md, "Sections".
const gitLabDocReadmeSections = `* @admin

[README Owners]
README.md @user1 @user2
internal/README.md @user4

[README other owners]
README.md @user3
`

// reference.md, "Set default Code Owner for a section".
const gitLabDocSectionDefaults = `[Documentation] @docs-team
docs/
README.md

[Database] @database-team @agarcia
model/db/
model/db/database-setup.md @docs-team
`

// reference.md, "Optional sections".
const gitLabDocOptional = `[Documentation]
*.md @root

[Ruby]
*.rb @root

^[Go]
*.go @root
`

// reference.md, "Exclusion patterns".
const gitLabDocExclusions = `# All files require approval from @username
* @username

# Except pom.xml which needs no approval
!pom.xml

[Ruby]
# All ruby files require approval from @ruby-team
*.rb @ruby-team

# Except Ruby files in the config directory
!/config/**/*.rb
`

// advanced.md, "Regular entries and sections".
const gitLabDocRegularAndSections = `# Required for all files
* @general-approvers

[Documentation] @docs-team
docs/
README.md
*.txt

[Database] @database-team
model/db/
model/db/database-setup.md @docs-team
`

// advanced.md, "Sections with duplicate names".
const gitLabDocDuplicateSections = `[Documentation]
ee/docs/    @docs
docs/       @docs

[Database]
README.md  @database
model/db/   @database

[DOCUMENTATION]
README.md  @docs
`

// Each case is a statement the GitHub documentation makes about its own
// example, checked on a one-entry file so that no later entry decides it.
func TestGitHubPatternsAsDocumented(t *testing.T) {
	tests := []struct {
		entry, path string
		want        bool
	}{
		// "@js-owner ... when someone opens a pull request that only modifies JS files"
		{"*.js @o", "app.js", true},
		{"*.js @o", "src/deep/app.js", true},
		{"*.js @o", "app.jsx", false},
		// "owns any files in the build/logs directory at the root of the
		// repository and any of its subdirectories"
		{"/build/logs/ @o", "build/logs/a.log", true},
		{"/build/logs/ @o", "build/logs/2026/a.log", true},
		{"/build/logs/ @o", "sub/build/logs/a.log", false},
		// "will match files like docs/getting-started.md but not further
		// nested files like docs/build-app/troubleshooting.md"
		{"docs/* @o", "docs/getting-started.md", true},
		{"docs/* @o", "docs/build-app/troubleshooting.md", false},
		// "owns any file in an apps directory anywhere in your repository"
		{"apps/ @o", "apps/a.rb", true},
		{"apps/ @o", "services/web/apps/a.rb", true},
		{"apps/ @o", "apps.rb", false},
		// "any file in the /docs directory in the root of your repository and
		// any of its subdirectories"
		{"/docs/ @o", "docs/a/b.md", true},
		{"/docs/ @o", "x/docs/b.md", false},
		// "any file in a /logs directory such as /build/logs, /scripts/logs,
		// and /deeply/nested/logs"
		{"**/logs @o", "build/logs/a", true},
		{"**/logs @o", "scripts/logs/a", true},
		{"**/logs @o", "deeply/nested/logs/a", true},
		{"**/logs @o", "logs/a", true},
		{"**/logs @o", "build/logstash/a", false},
		// "/apps/github subdirectory"
		{"/apps/github @o", "apps/github/x.go", true},
		{"/apps/github @o", "apps/gitlab/x.go", false},
		// "CODEOWNERS paths are case sensitive"
		{"/Docs/ @o", "docs/a.md", false},
	}
	for _, tt := range tests {
		f := Parse(GitHub, tt.entry+"\n")
		if len(f.Rules) != 1 {
			t.Fatalf("%q: parsed %d rules, want 1", tt.entry, len(f.Rules))
		}
		if got := len(f.Match(tt.path)) == 1; got != tt.want {
			t.Errorf("%q matches %q = %v, want %v", tt.entry, tt.path, got, tt.want)
		}
	}
}

// The whole documentation example, where the last matching entry wins.
func TestGitHubDocumentationExample(t *testing.T) {
	f := Parse(GitHub, gitHubDocExample)
	tests := []struct {
		path string
		want []string
	}{
		{"README.md", []string{"@global-owner1", "@global-owner2"}},
		// The inline comment after @js-owner is not an owner.
		{"src/app.js", []string{"@js-owner"}},
		{"cmd/main.go", []string{"docs@example.com"}},
		{"notes/a.txt", []string{"@octo-org/octocats"}},
		// /build/logs/ names @doctocat, and the later **/logs entry wins.
		{"build/logs/x.log", []string{"@octocat"}},
		// docs/* names docs@example.com, and the later /docs/ entry wins.
		{"docs/getting-started.md", []string{"@doctocat"}},
		{"docs/build-app/troubleshooting.md", []string{"@doctocat"}},
		{"services/apps/y.rb", []string{"@octocat"}},
		{"scripts/run.sh", []string{"@doctocat", "@octocat"}},
		{"deeply/nested/logs/a.log", []string{"@octocat"}},
		// The file's last two entries: /apps/ and then /apps/github.
		{"apps/other/x.py", []string{"@octocat"}},
		{"apps/github/x.py", []string{"@doctocat"}},
	}
	for _, tt := range tests {
		if got := f.Owners(tt.path); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("owners(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
	// A leading slash on the queried path is ignored.
	if got := f.Owners("/src/app.js"); !reflect.DeepEqual(got, []string{"@js-owner"}) {
		t.Errorf("owners(/src/app.js) = %v", got)
	}
	// Line numbers are those of the file: the *.js entry is on line 14.
	m := f.Match("src/app.js")
	if len(m) != 1 || m[0].Pattern != "*.js" || m[0].Line != 14 {
		t.Errorf("match(src/app.js) = %+v, want the *.js entry on line 14", m)
	}
}

// "@octocat owns any file in the /apps directory ... except for the
// /apps/github subdirectory, as its owners are left empty." The documentation
// example ends with a second pair that gives /apps/github an owner, so this
// reads the example up to that pair. Synthetic only in where it is cut.
func TestGitHubEntryWithoutOwnersLeavesPathUnowned(t *testing.T) {
	cut := strings.LastIndex(gitHubDocExample, "# In this example, @octocat owns any file in the `/apps`")
	if cut < 0 {
		t.Fatal("the documentation example changed shape")
	}
	f := Parse(GitHub, gitHubDocExample[:cut])
	m := f.Match("apps/github/x.py")
	if len(m) != 1 || m[0].Pattern != "/apps/github" || len(m[0].Owners) != 0 {
		t.Fatalf("match = %+v, want the /apps/github entry with no owners", m)
	}
	if got := f.Owners("apps/github/x.py"); got != nil {
		t.Errorf("owners = %v, want none", got)
	}
	if got := f.Owners("apps/other/x.py"); !reflect.DeepEqual(got, []string{"@octocat"}) {
		t.Errorf("owners(apps/other/x.py) = %v", got)
	}
}

// Synthetic: lines GitHub documents as not working are skipped, and the rest
// of the file still applies.
func TestGitHubSkipsInvalidLines(t *testing.T) {
	f := Parse(GitHub, strings.Join([]string{
		"* @all",
		"!*.md @negation",          // `!` does not negate
		"src/[a-c]*.go @range",     // `[ ]` ranges do not work
		`\#notes.txt @escaped`,     // `\#` does not escape
		"*.rb not-an-owner",        // an owner must be @name or an email
		"*.py @py-team # trailing", // inline comment with a space
		"",
		"   # indented comment @nobody",
	}, "\n"))
	var patterns []string
	for _, r := range f.Rules {
		patterns = append(patterns, r.Pattern)
	}
	if want := []string{"*", "*.py"}; !reflect.DeepEqual(patterns, want) {
		t.Fatalf("rules = %v, want %v", patterns, want)
	}
	if got := f.Owners("a.md"); !reflect.DeepEqual(got, []string{"@all"}) {
		t.Errorf("owners(a.md) = %v, want the * entry's", got)
	}
	if got := f.Owners("x.py"); !reflect.DeepEqual(got, []string{"@py-team"}) {
		t.Errorf("owners(x.py) = %v", got)
	}
}

func TestGitLabDocumentationExamples(t *testing.T) {
	tests := []struct {
		name, content, path string
		want                []string
	}{
		// Opening examples. Everything before [Documentation] is the unnamed
		// section; /config/ comes after the heading, so it belongs to it.
		{"overview: file at any depth", gitLabDocOverview, "README.md", []string{"@doc-team", "@tech-lead"}},
		{"overview: extension", gitLabDocOverview, "lib/x.rb", []string{"@ruby-owner"}},
		{"overview: username and email", gitLabDocOverview, "LICENSE", []string{"@legal", "janedoe@gitlab.com"}},
		{"overview: nested group", gitLabDocOverview, "README", []string{"@group", "@group/with-nested/subgroup"}},
		{"overview: /docs/* is one level", gitLabDocOverview, "docs/logo.png", []string{"@root-docs"}},
		{"overview: /docs/ is every level", gitLabDocOverview, "docs/api/logo.png", []string{"@all-docs"}},
		{"overview: /docs/**/*.md, text after # names no owner", gitLabDocOverview, "docs/api/guide.md", []string{"@markdown-docs"}},
		{"overview: /db/**/index.md", gitLabDocOverview, "db/a/b/index.md", []string{"@index-docs"}},
		{"overview: a role in a section", gitLabDocOverview, "config/app.yml", []string{"@default-owner", "@@maintainer"}},
		// `docs` without a trailing slash matches a path named docs, not the
		// files in a directory of that name.
		{"overview: section entry without a slash", gitLabDocOverview, "ee/docs", []string{"@default-owner", "@docs"}},
		{"overview: it does not match inside the directory", gitLabDocOverview, "ee/docs/x.txt", []string{"@default-owner"}},

		// "The Code Owners for the README.md in the root directory are: @admin
		// ... @user1 and @user2 ... @user3."
		{"sections: root README", gitLabDocReadmeSections, "README.md", []string{"@admin", "@user1", "@user2", "@user3"}},
		// "The Code Owners for internal/README.md are: @admin ... @user4 ...
		// only the last matching entry in the section is used ... @user3."
		{"sections: internal README", gitLabDocReadmeSections, "internal/README.md", []string{"@admin", "@user4", "@user3"}},

		// "@docs-team owns all items in the Documentation section."
		{"defaults: directory entry", gitLabDocSectionDefaults, "docs/guide/a.md", []string{"@docs-team"}},
		{"defaults: file entry", gitLabDocSectionDefaults, "README.md", []string{"@docs-team"}},
		// "@database-team and @agarcia own all items in the Database section
		// except model/db/database-setup.md, which has an override."
		{"defaults: second section", gitLabDocSectionDefaults, "model/db/schema.rb", []string{"@database-team", "@agarcia"}},
		{"defaults: override beside the path", gitLabDocSectionDefaults, "model/db/database-setup.md", []string{"@docs-team"}},
		{"defaults: no entry matches", gitLabDocSectionDefaults, "src/main.go", nil},

		// "A merge request that modifies model/db/CHANGELOG.txt would require
		// three approvals: one from each of the @general-approvers, @docs-team,
		// and @database-team groups."
		{"regular entries are not overridden", gitLabDocRegularAndSections, "model/db/CHANGELOG.txt", []string{"@general-approvers", "@docs-team", "@database-team"}},

		// "The pom.xml exclusion applies to the default section."
		{"exclusions: excluded in the default section", gitLabDocExclusions, "pom.xml", nil},
		{"exclusions: ruby file", gitLabDocExclusions, "app/models/a.rb", []string{"@username", "@ruby-team"}},
		// "The /config/**/*.rb exclusion only affects Ruby files in the Ruby section."
		{"exclusions: excluded in the Ruby section only", gitLabDocExclusions, "config/initializers/a.rb", []string{"@username"}},
		{"exclusions: other config file", gitLabDocExclusions, "config/app.yml", []string{"@username"}},

		// "The entries defined under the sections Documentation and
		// DOCUMENTATION are combined."
		{"duplicate section names combine", gitLabDocDuplicateSections, "README.md", []string{"@docs", "@database"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse(GitLab, tt.content).Owners(tt.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("owners(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// "In this example, the [Go] section is optional."
func TestGitLabOptionalSection(t *testing.T) {
	f := Parse(GitLab, gitLabDocOptional)
	goRule := f.Match("cmd/main.go")
	if len(goRule) != 1 || goRule[0].Section != "Go" || !goRule[0].Optional {
		t.Fatalf("match(cmd/main.go) = %+v, want one optional entry of section Go", goRule)
	}
	rb := f.Match("lib/a.rb")
	if len(rb) != 1 || rb[0].Section != "Ruby" || rb[0].Optional {
		t.Fatalf("match(lib/a.rb) = %+v, want one required entry of section Ruby", rb)
	}
}

// "using the case of the first section": an entry under [DOCUMENTATION]
// reports the section as it was first written.
func TestGitLabDuplicateSectionKeepsFirstSpelling(t *testing.T) {
	m := Parse(GitLab, gitLabDocDuplicateSections).Match("README.md")
	if len(m) != 2 || m[0].Section != "Documentation" || m[0].Line != 10 || m[1].Section != "Database" {
		t.Fatalf("match = %+v, want Documentation (line 10) then Database", m)
	}
}

// Synthetic: the behaviours GitLab documents in prose or with one-line
// examples, which no full example file exercises.
func TestGitLabSyntax(t *testing.T) {
	t.Run("heading forms", func(t *testing.T) {
		f := Parse(GitLab, "[Section name][2] @group @subgroup\ndocs/\n")
		m := f.Match("docs/a.md")
		if len(m) != 1 || m[0].Approvals != 2 || m[0].Optional || !reflect.DeepEqual(m[0].Owners, []string{"@group", "@subgroup"}) {
			t.Fatalf("match = %+v", m)
		}
	})
	// "If a section is duplicated in the file, and one of them is marked as
	// optional and the other isn't, the section is required."
	t.Run("optional and required duplicate is required", func(t *testing.T) {
		m := Parse(GitLab, "^[Go]\n*.go @a\n[go]\n*.mod @b\n").Match("main.go")
		if len(m) != 1 || m[0].Optional {
			t.Fatalf("match = %+v, want a required entry", m)
		}
	})
	// "GitLab ignores the heading `[Section name`. The [Docs] section
	// includes two rules."
	t.Run("unparsable heading is ignored", func(t *testing.T) {
		f := Parse(GitLab, "[Docs]\ndocs/**/* @group\n[Section name\ndocs/ @docs_group\n")
		m := f.Match("docs/a.md")
		if len(m) != 1 || m[0].Section != "Docs" || !reflect.DeepEqual(m[0].Owners, []string{"@docs_group"}) {
			t.Fatalf("match = %+v, want the last entry of [Docs]", m)
		}
	})
	// "This entry is owned by @group and @user_with_at_symbol."
	t.Run("malformed owners are ignored", func(t *testing.T) {
		got := Parse(GitLab, "/path/* @group user_without_at_symbol @user_with_at_symbol\n").Owners("path/x")
		if !reflect.DeepEqual(got, []string{"@group", "@user_with_at_symbol"}) {
			t.Fatalf("owners = %v", got)
		}
	})
	// "Escape whitespace in paths with backslashes."
	t.Run("escaped spaces", func(t *testing.T) {
		f := Parse(GitLab, `path\ with\ spaces/*.md @owner`+"\n")
		if got := f.Owners("path with spaces/a.md"); !reflect.DeepEqual(got, []string{"@owner"}) {
			t.Fatalf("owners = %v", got)
		}
	})
	// "After a pattern is excluded, it cannot be included again in the same
	// section."
	t.Run("exclusion is not undone by a later entry", func(t *testing.T) {
		f := Parse(GitLab, "[Ruby]\n*.rb @ruby-team\n!/config/**/*.rb\n/config/routes.rb @ops\n")
		if got := f.Owners("config/routes.rb"); got != nil {
			t.Fatalf("owners = %v, want none", got)
		}
		if got := f.Owners("lib/a.rb"); !reflect.DeepEqual(got, []string{"@ruby-team"}) {
			t.Fatalf("owners(lib/a.rb) = %v", got)
		}
	})
	// "The FNM_DOTMATCH flag allows * to match dotfiles"; "FNM_PATHNAME
	// prevents * from matching the / path separator".
	t.Run("star matches dotfiles and stops at a slash", func(t *testing.T) {
		f := Parse(GitLab, "/docs/* @d\n")
		if got := f.Owners("docs/.gitignore"); !reflect.DeepEqual(got, []string{"@d"}) {
			t.Errorf("owners(docs/.gitignore) = %v", got)
		}
		if got := f.Owners("docs/projects/index.md"); got != nil {
			t.Errorf("owners(docs/projects/index.md) = %v, want none", got)
		}
	})
	// "/docs/*/README.md: README.md files one level deep within the docs
	// directory"; "/docs/**/index.md: /docs/index.md, /docs/api/index.md,
	// and /docs/api/graphql/index.md".
	t.Run("one level and any level", func(t *testing.T) {
		f := Parse(GitLab, "/docs/*/README.md @one\n/docs/**/index.md @any\n")
		for path, want := range map[string][]string{
			"docs/api/README.md":        {"@one"},
			"docs/README.md":            nil,
			"docs/api/v2/README.md":     nil,
			"docs/index.md":             {"@any"},
			"docs/api/index.md":         {"@any"},
			"docs/api/graphql/index.md": {"@any"},
			"other/docs/api/index.md":   nil,
		} {
			if got := f.Owners(path); !reflect.DeepEqual(got, want) {
				t.Errorf("owners(%q) = %v, want %v", path, got, want)
			}
		}
	})
}

// Synthetic: the same text read by each forge gives different owners, which is
// why a file is parsed for one dialect.
func TestDialectsDisagree(t *testing.T) {
	const content = "docs @team\n"
	if got := Parse(GitHub, content).Owners("docs/a.md"); !reflect.DeepEqual(got, []string{"@team"}) {
		t.Errorf("GitHub owners = %v, want the directory's contents owned", got)
	}
	if got := Parse(GitLab, content).Owners("docs/a.md"); got != nil {
		t.Errorf("GitLab owners = %v, want none: the entry names a path, not a directory", got)
	}
}

func TestMatchWithoutAFileOrAPath(t *testing.T) {
	var f *File
	if f.Match("a") != nil || f.Owners("a") != nil {
		t.Error("a nil file owns nothing")
	}
	if Parse(GitHub, "* @a\n").Match("") != nil || Parse(GitLab, "* @a\n").Match("/") != nil {
		t.Error("an empty path matches nothing")
	}
}
