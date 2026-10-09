// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"errors"
	"path/filepath"
	"strings"
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

	got, _, err := findAgentSkills(&afero.Afero{Fs: mem}, "/repo")
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

	got, _, err := findAgentSkills(&afero.Afero{Fs: mem}, "/skill")
	require.NoError(t, err)
	assert.Equal(t, []string{"/skill/SKILL.md"}, got)
}

func TestFindAgentSkillsDepthLimit(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/r/1/2/3/4/5/6/7/8/9/10/SKILL.md")
	writeAgentSkillFile(t, mem, "/r/1/2/3/4/5/6/7/8/9/10/11/SKILL.md")

	got, _, err := findAgentSkills(&afero.Afero{Fs: mem}, "/r")
	require.NoError(t, err)
	assert.Equal(t, []string{"/r/1/2/3/4/5/6/7/8/9/10/SKILL.md"}, got)
}

func TestFindAgentSkillsSkipsUnreadableSubdir(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/repo/ok/SKILL.md")
	writeAgentSkillFile(t, mem, "/repo/locked/SKILL.md")

	got, _, err := findAgentSkills(&afero.Afero{Fs: &denyFs{Fs: mem, deny: "/repo/locked"}}, "/repo")
	require.NoError(t, err)
	assert.Equal(t, []string{"/repo/ok/SKILL.md"}, got)
}

func TestFindAgentSkillsMissingRoot(t *testing.T) {
	_, _, err := findAgentSkills(&afero.Afero{Fs: afero.NewMemMapFs()}, "/nope")
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrNotFound), "a missing path is NotFound, got %v", err)
}

func TestFindAgentSkillsRootIsAFile(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/repo/SKILL.md")
	_, _, err := findAgentSkills(&afero.Afero{Fs: mem}, "/repo/SKILL.md")
	assert.ErrorContains(t, err, "is not a directory or a .skill package")
}

func TestFindAgentSkillsRootIsAPackage(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/dl/x.skill", []byte("x"), 0o644))
	skills, packages, err := findAgentSkills(&afero.Afero{Fs: mem}, "/dl/x.skill")
	require.NoError(t, err)
	assert.Empty(t, skills)
	assert.Equal(t, []string{"/dl/x.skill"}, packages)
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

func TestAgentSkillReferences(t *testing.T) {
	body := strings.Join([]string{
		"See [the guide](references/GUIDE.md) and ![logo](./assets/logo.png \"Logo\").",
		"Again: [guide](references/GUIDE.md#setup), [spaced](<references/my%20notes.md>).",
		"A sibling skill: [use](../figma-use/SKILL.md). Base dir: [wf]({baseDir}/references/workflow.md).",
		"Not files: [site](https://example.com/x.md), [mail](mailto:a@b.c), [top](#usage),",
		"[abs](/etc/passwd), [home](~/x.md), [data](data:text/plain,hi), [env](${CLAUDE_PLUGIN_ROOT}/x.md).",
		"Prose only: Read references/DESIGN.md and run `python scripts/extract.py`.",
		"```markdown",
		"[Example](url) and [edit](edit_url)",
		"```",
		"~~~",
		"[tilde](fenced.md)",
		"~~~",
		"After the fence: [last](assets/last.png)",
	}, "\n")
	assert.Equal(t, []string{
		"references/GUIDE.md",
		"assets/logo.png",
		"references/my notes.md",
		"../figma-use/SKILL.md",
		"references/workflow.md",
		"assets/last.png",
	}, agentSkillReferences(body))
	assert.Empty(t, agentSkillReferences("# No references\nJust prose.\n"))
}

func TestCountLines(t *testing.T) {
	assert.Equal(t, 0, countLines(""))
	assert.Equal(t, 1, countLines("one"))
	assert.Equal(t, 1, countLines("one\n"))
	assert.Equal(t, 3, countLines("one\n\nthree\n"))
}

func TestFindAgentSkillsPackages(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeAgentSkillFile(t, mem, "/repo/skills/alpha/SKILL.md")
	for _, p := range []string{
		"/repo/dist/beta.skill",
		"/repo/skills/alpha/bundled.skill", // inside a skill: a bundled file
		"/repo/node_modules/dep/x.skill",
		"/repo/notes.skills",
	} {
		require.NoError(t, afero.WriteFile(mem, p, []byte("x"), 0o644))
	}
	require.NoError(t, mem.MkdirAll("/repo/dir.skill/gamma", 0o755)) // a directory, searched as one
	writeAgentSkillFile(t, mem, "/repo/dir.skill/gamma/SKILL.md")

	skills, packages, err := findAgentSkills(&afero.Afero{Fs: mem}, "/repo")
	require.NoError(t, err)
	assert.Equal(t, []string{"/repo/dir.skill/gamma/SKILL.md", "/repo/skills/alpha/SKILL.md"}, skills)
	assert.Equal(t, []string{"/repo/dist/beta.skill"}, packages)
}

// zipBytes builds a zip archive from name -> content. A name ending in "/" is
// a directory entry.
func zipBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func readPackage(t *testing.T, data []byte) []agentSkillSource {
	t.Helper()
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/dl/pkg.skill", data, 0o644))
	return readAgentSkillPackage(&afero.Afero{Fs: mem}, "/dl/pkg.skill")
}

func TestReadAgentSkillPackage(t *testing.T) {
	srcs := readPackage(t, zipBytes(t, map[string]string{
		"design/SKILL.md":             "---\nname: design\n---\n",
		"design/references/DESIGN.md": "x",
		"design/references/SKILL.md":  "nested, so a bundled file",
		"other/sub/SKILL.md":          "---\nname: sub\n---\n",
		"node_modules/dep/SKILL.md":   "skipped",
		"README.md":                   "x",
	}))
	require.Len(t, srcs, 2)

	assert.Equal(t, "/dl/pkg.skill/design/SKILL.md", srcs[0].path)
	assert.Equal(t, "design", srcs[0].directory)
	assert.Equal(t, "/dl/pkg.skill", srcs[0].archive)
	assert.Equal(t, "---\nname: design\n---\n", string(srcs[0].content))
	assert.Empty(t, srcs[0].errors)
	assert.True(t, srcs[0].exists("references/DESIGN.md"))
	assert.True(t, srcs[0].exists("references"), "directories without an entry of their own exist")
	assert.False(t, srcs[0].exists("references/MISSING.md"))
	assert.False(t, srcs[0].exists("README.md"), "references resolve inside the skill directory")

	assert.Equal(t, "/dl/pkg.skill/other/sub/SKILL.md", srcs[1].path)
	assert.Equal(t, "sub", srcs[1].directory)
}

func TestReadAgentSkillPackageRootSkill(t *testing.T) {
	srcs := readPackage(t, zipBytes(t, map[string]string{
		"SKILL.md":           "---\nname: pkg\n---\n",
		"scripts/run.sh":     "x",
		"scripts/x/SKILL.md": "nested",
	}))
	require.Len(t, srcs, 1)
	assert.Equal(t, "pkg", srcs[0].directory, "a skill at the archive root is named after the archive")
	assert.True(t, srcs[0].exists("scripts/run.sh"))
}

func TestReadAgentSkillPackageProblems(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"not a zip", []byte("not a zip"), "not a valid zip archive"},
		{"no SKILL.md", zipBytes(t, map[string]string{"README.md": "x"}), "contains no SKILL.md"},
		{"SKILL.md too large", zipBytes(t, map[string]string{
			"big/SKILL.md": strings.Repeat("a", agentSkillFileMaxBytes+1),
		}), "over the 5242880 byte limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcs := readPackage(t, tt.data)
			require.Len(t, srcs, 1)
			require.Len(t, srcs[0].errors, 1)
			assert.Contains(t, srcs[0].errors[0], tt.want)
			assert.Nil(t, srcs[0].content)
		})
	}

	t.Run("too many entries", func(t *testing.T) {
		entries := map[string]string{"s/SKILL.md": "---\nname: s\n---\n"}
		for i := 0; i < agentSkillPackageMaxEntries; i++ {
			entries["s/f"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)] = ""
		}
		srcs := readPackage(t, zipBytes(t, entries))
		require.Len(t, srcs, 1)
		assert.Contains(t, srcs[0].errors[0], "entry limit")
	})
}

func TestAgentSkillMissingReferences(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/p/skills/s/references/GUIDE.md", []byte("x"), 0o644))
	require.NoError(t, afero.WriteFile(mem, "/p/skills/sibling/SKILL.md", []byte("x"), 0o644))
	exists := func(rel string) bool {
		_, err := mem.Stat(filepath.Join("/p/skills/s", rel))
		return err == nil
	}

	assert.Equal(t, []string{"references/DESIGN.md", "../gone/SKILL.md"}, agentSkillMissingReferences(
		[]string{"references/GUIDE.md", "references/DESIGN.md", "../sibling/SKILL.md", "../gone/SKILL.md"}, exists))
}
