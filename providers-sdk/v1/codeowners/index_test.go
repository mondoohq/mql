// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIndexAgreesWithMatch checks that the index gives the answer of the
// linear scan for every file and path the dialect tests use, plus synthetic
// paths that hit literal segments, suffixes and neither.
func TestIndexAgreesWithMatch(t *testing.T) {
	files := []struct {
		content string
		d       Dialect
	}{
		{githubExample, GitHub},
		{"/apps/ @octocat\n/apps/github\n*.proto @api\nMakefile @build\n**/logs @ops\ndocs/** @docs\n", GitHub},
		{gitlabReadme, GitLab},
		{"* @username\n!pom.xml\n[Ruby]\n*.rb @ruby-team\n!/config/**/*.rb\n[Config]\n/config/ @ops-team\n[ruby]\n/special/*.rb @x\n", GitLab},
		{"[Documentation][2] @docs-team\ndocs/\nREADME.md\n^[Database] @database-team\nmodel/db/\nmodel/db/database-setup.md @docs-team\n*.[ch] @c\n", GitLab},
		// Synthetic: suffix keys with multi-byte runes, and a pattern holding
		// a byte that is not UTF-8 (the matcher reads it as U+FFFD).
		{"*é.go @e\n*中 @zh\n*.m\xff @bad\n", GitHub},
		{"*é.go @e\n*中 @zh\n*.m\xff @bad\n", GitLab},
	}
	paths := []string{
		"README.md", "internal/README.md", "docs/a.md", "docs/build-app/troubleshooting.md",
		"apps/github/x.go", "apps/web/x.go", "api/v1/svc.proto", "Makefile", "sub/Makefile",
		"build/logs/a", "x/logs/y/z", "pom.xml", "app/a.rb", "config/routes.rb", "special/a.rb",
		"model/db/schema.rb", "model/db/database-setup.md", "src/a.c", "src/a.o", "main.go",
		"scripts/deploy.sh", "notes.txt", ".github/CODEOWNERS", "",
		"src/café.go", "src/é.go", "docs/文件中", "a/x.m\xff", "a/x.m\xfe",
	}
	for i, f := range files {
		rules, _ := Parse(f.content, f.d)
		x := NewIndex(rules, f.d)
		for _, p := range paths {
			assert.Equal(t, MatchRules(rules, p, f.d), x.MatchRules(p), "file %d, path %q", i, p)
			assert.Equal(t, Match(rules, p, f.d), x.Match(p), "file %d, path %q", i, p)
		}
	}
}

func TestIndexKeys(t *testing.T) {
	rules := mustParse(t, "/services/api/ @a\n*.proto @b\n* @c\n**/x?y @d\n", GitHub)
	x := NewIndex(rules, GitHub)
	assert.Equal(t, []int{0}, x.bySeg["api"])
	assert.Equal(t, []int{1}, x.bySuffix[".proto"])
	assert.Equal(t, []int{2}, x.always)
	assert.Equal(t, []int{3}, x.bySuffix["y"])
	// The literal-keyed rule is not a candidate for a path without "api".
	assert.Equal(t, []int{2}, x.candidates([]string{"web", "main.go"}))
}

// BenchmarkIndexMatch matches 20,000 paths against 5,000 rules, the size a
// code scanner caps a CODEOWNERS file at. Synthetic rules and paths.
func BenchmarkIndexMatch(b *testing.B) {
	for _, d := range []Dialect{GitHub, GitLab} {
		b.Run(d.String(), func(b *testing.B) {
			rules, paths := benchFile(b, d)
			x := NewIndex(rules, d)
			for b.Loop() {
				for _, p := range paths {
					_ = x.Match(p)
				}
			}
		})
	}
}

func benchFile(b *testing.B, d Dialect) ([]Rule, []string) {
	b.Helper()
	var content []byte
	for i := range 5000 {
		switch i % 4 {
		case 0:
			content = fmt.Appendf(content, "/services/svc%d/ @team%d\n", i, i)
		case 1:
			content = fmt.Appendf(content, "*.gen%d.go @gen\n", i)
		case 2:
			content = fmt.Appendf(content, "docs/area%d/*.md @docs%d\n", i, i)
		default:
			content = fmt.Appendf(content, "**/logs%d @ops\n", i)
		}
	}
	content = append(content, "* @default\n"...)
	rules, err := Parse(string(content), d)
	if err != nil {
		b.Fatal(err)
	}
	paths := make([]string, 20000)
	for i := range paths {
		paths[i] = fmt.Sprintf("services/svc%d/pkg/sub/file%d.go", (i*4)%5000, i)
	}
	return rules, paths
}
