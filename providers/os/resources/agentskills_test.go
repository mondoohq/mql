// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestParseAgentSkillFullFrontmatter(t *testing.T) {
	s := parseAgentSkill(`---
name: pdf-processing
description: Extract text and tables from PDF files.
license: Apache-2.0
compatibility: Requires poppler-utils
metadata:
  author: example-org
  version: "1.0"
allowed-tools: Bash(git add:*) Bash(jq:*) Read
argument-hint: <file>
---
# PDF processing

Step one.
`)
	assert.Empty(t, s.errors)
	assert.Equal(t, "pdf-processing", s.name)
	assert.Equal(t, "Extract text and tables from PDF files.", s.description)
	assert.Equal(t, "Apache-2.0", s.license)
	assert.Equal(t, "Requires poppler-utils", s.compatibility)
	assert.Equal(t, map[string]any{"author": "example-org", "version": "1.0"}, s.metadata)
	assert.Equal(t, []string{"Bash(git add:*)", "Bash(jq:*)", "Read"}, s.allowedTools)
	assert.Equal(t, "<file>", s.frontmatter["argument-hint"], "fields outside the spec stay readable")
	assert.Equal(t, "# PDF processing\n\nStep one.\n", s.body)
}

func TestParseAgentSkillHasNoFallbacks(t *testing.T) {
	s := parseAgentSkill("---\ndescription: d\n---\nbody\n")
	assert.Empty(t, s.errors)
	assert.Equal(t, "", s.name, "a missing name is empty, not the directory name")
	assert.Nil(t, s.metadata, "absent metadata is null, not an empty map")
	assert.Nil(t, s.allowedTools)
}

func TestParseAgentSkillEmptyFrontmatter(t *testing.T) {
	s := parseAgentSkill("---\n---\nbody\n")
	assert.Empty(t, s.errors)
	assert.Equal(t, map[string]any{}, s.frontmatter)
	assert.Equal(t, "body\n", s.body)
}

func TestParseAgentSkillWindowsLineEndingsAndBOM(t *testing.T) {
	s := parseAgentSkill("\uFEFF---\r\nname: win\r\ndescription: d\r\n---\r\nbody\r\n")
	assert.Empty(t, s.errors)
	assert.Equal(t, "win", s.name)
	assert.Equal(t, "body\n", s.body)
}

func TestParseAgentSkillFrontmatterErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"no frontmatter", "# Just markdown\n", "does not start with a --- frontmatter block"},
		{"frontmatter not first", "\n---\nname: x\n---\n", "does not start with a --- frontmatter block"},
		{"not closed", "---\nname: x\ndescription: y\n", "not closed by a --- line"},
		{"only opening line", "---", "not closed by a --- line"},
		{"invalid yaml", "---\nname: [unclosed\n---\n", "frontmatter is not valid YAML"},
		{"not a map", "---\n- a\n- b\n---\n", "frontmatter is not valid YAML"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := parseAgentSkill(tt.content)
			require.Len(t, s.errors, 1)
			assert.Contains(t, s.errors[0], tt.want)
			assert.Nil(t, s.frontmatter)
			assert.Equal(t, "", s.name)
		})
	}
}

func TestParseAgentSkillNoFrontmatterKeepsBody(t *testing.T) {
	s := parseAgentSkill("# Just markdown\n")
	assert.Equal(t, "# Just markdown\n", s.body)
}

func TestParseAgentSkillWrongFieldTypes(t *testing.T) {
	s := parseAgentSkill("---\nname: 123\ndescription: ok\nlicense: true\nmetadata: [a]\nallowed-tools: 7\n---\n")
	assert.ElementsMatch(t, []string{
		"name must be a string, not a number",
		"license must be a string, not a boolean",
		"metadata must be a map, not a list",
		"allowed-tools must be a string, not a number",
	}, s.errors)
	assert.Equal(t, "", s.name)
	assert.Equal(t, "ok", s.description, "a bad field does not hide the good ones")
}

func TestParseAgentSkillAllowedToolsAsList(t *testing.T) {
	s := parseAgentSkill("---\nname: x\nallowed-tools:\n  - Read\n  - Bash(git add:*)\n  - 3\n---\n")
	assert.Equal(t, []string{"Read", "Bash(git add:*)"}, s.allowedTools)
	assert.Equal(t, []string{"allowed-tools entries must be strings, not a number"}, s.errors)
}

func TestSplitAllowedTools(t *testing.T) {
	assert.Equal(t, []string{"Bash(git add:*)", "Read"}, splitAllowedTools("Bash(git add:*) Read"))
	assert.Equal(t, []string{"Read", "Write", "Edit"}, splitAllowedTools("Read, Write,Edit"))
	assert.Equal(t, []string{"Bash(a, b)", "Read"}, splitAllowedTools("  Bash(a, b)\tRead  "))
	assert.Nil(t, splitAllowedTools(""))
	assert.Nil(t, splitAllowedTools(" , "))
}

func writeAgentSkillFile(t *testing.T, fs afero.Fs, path string) {
	t.Helper()
	require.NoError(t, afero.WriteFile(fs, path, []byte("---\nname: x\n---\n"), 0o644))
}

func TestFindAgentSkills(t *testing.T) {
	mem := afero.NewMemMapFs()
	for _, p := range []string{
		"/repo/skills/alpha/SKILL.md",
		"/repo/skills/alpha/scripts/nested/SKILL.md", // inside a skill: a bundled file, not a skill
		"/repo/plugins/p/skills/beta/SKILL.md",
		"/repo/.claude/skills/gamma/SKILL.md", // hidden directories are searched
		"/repo/node_modules/dep/SKILL.md",
		"/repo/.git/SKILL.md",
	} {
		writeAgentSkillFile(t, mem, p)
	}
	require.NoError(t, afero.WriteFile(mem, "/repo/README.md", []byte("x"), 0o644))

	got, err := findAgentSkills(&afero.Afero{Fs: mem}, "/repo")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/repo/.claude/skills/gamma/SKILL.md",
		"/repo/plugins/p/skills/beta/SKILL.md",
		"/repo/skills/alpha/SKILL.md",
	}, got)
}

func TestFindAgentSkillsRootIsASkill(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/skill/SKILL.md")
	writeAgentSkillFile(t, mem, "/skill/sub/SKILL.md")

	got, err := findAgentSkills(&afero.Afero{Fs: mem}, "/skill")
	require.NoError(t, err)
	assert.Equal(t, []string{"/skill/SKILL.md"}, got)
}

func TestFindAgentSkillsDepthLimit(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/r/1/2/3/4/5/6/7/8/9/10/SKILL.md")
	writeAgentSkillFile(t, mem, "/r/1/2/3/4/5/6/7/8/9/10/11/SKILL.md")

	got, err := findAgentSkills(&afero.Afero{Fs: mem}, "/r")
	require.NoError(t, err)
	assert.Equal(t, []string{"/r/1/2/3/4/5/6/7/8/9/10/SKILL.md"}, got)
}

func TestFindAgentSkillsSkipsUnreadableSubdir(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/repo/ok/SKILL.md")
	writeAgentSkillFile(t, mem, "/repo/locked/SKILL.md")

	got, err := findAgentSkills(&afero.Afero{Fs: &denyFs{Fs: mem, deny: "/repo/locked"}}, "/repo")
	require.NoError(t, err)
	assert.Equal(t, []string{"/repo/ok/SKILL.md"}, got)
}

func TestFindAgentSkillsMissingRoot(t *testing.T) {
	_, err := findAgentSkills(&afero.Afero{Fs: afero.NewMemMapFs()}, "/nope")
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrNotFound), "a missing path is NotFound, got %v", err)
}

func TestFindAgentSkillsRootIsAFile(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/repo/SKILL.md")
	_, err := findAgentSkills(&afero.Afero{Fs: mem}, "/repo/SKILL.md")
	assert.ErrorContains(t, err, "is not a directory")
}

func TestAgentSkillBundledFiles(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/s/SKILL.md")
	writeAgentSkillFile(t, mem, "/s/references/SKILL.md") // only the top-level SKILL.md is excluded
	for _, p := range []string{"/s/scripts/run.sh", "/s/assets/logo.png", "/s/LICENSE"} {
		require.NoError(t, afero.WriteFile(mem, p, []byte("x"), 0o644))
	}

	got, err := agentSkillBundledFiles(&afero.Afero{Fs: mem}, "/s/SKILL.md")
	require.NoError(t, err)
	assert.Equal(t, []string{"/s/LICENSE", "/s/assets/logo.png", "/s/references/SKILL.md", "/s/scripts/run.sh"}, got)
}
