// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The SKILL.md bodies below are the files found under ~/.claude/skills on the
// Ubuntu hosts used to verify this parser.

func TestParseSkillMdSpecSpaceDelimitedTools(t *testing.T) {
	content := "---\nname: cc-spec-u\ndescription: Spec-style allowed tools\nallowed-tools: Bash(git:*) Bash(jq:*) Read\n---\nbody\n"
	skill := parseSkillMd("cc-spec-u", "/s/SKILL.md", content)
	assert.Equal(t, []string{"Bash(git:*)", "Bash(jq:*)", "Read"}, skill.allowedTools)
}

func TestParseSkillMdCommaDelimitedTools(t *testing.T) {
	content := "---\nname: cc-full-u\ndescription: Deploys the cc-full-u service. Use when shipping.\nallowed-tools: Bash, Read, Edit\nargument-hint: <environment>\n---\n# cc-full-u\nRun the deploy.\n"
	skill := parseSkillMd("cc-full-u", "/s/SKILL.md", content)
	assert.Equal(t, []string{"Bash", "Read", "Edit"}, skill.allowedTools)
	assert.Equal(t, "<environment>", skill.argumentHint)
}

func TestParseSkillMdYAMLListTools(t *testing.T) {
	content := "---\nname: cc-list-u\ndescription: YAML list allowed tools\nallowed-tools:\n  - Bash\n  - Read\n---\nbody\n"
	skill := parseSkillMd("dir-name", "/s/SKILL.md", content)
	// The rest of the frontmatter must survive the list form too.
	assert.Equal(t, "cc-list-u", skill.name)
	assert.Equal(t, "YAML list allowed tools", skill.description)
	assert.Equal(t, []string{"Bash", "Read"}, skill.allowedTools)
}

func TestParseSkillMdYAMLListKeepsRuleWithSpaces(t *testing.T) {
	content := "---\nname: x\nallowed-tools:\n  - Bash(git status:*)\n  - Read\n---\n"
	skill := parseSkillMd("x", "/s/SKILL.md", content)
	assert.Equal(t, []string{"Bash(git status:*)", "Read"}, skill.allowedTools)
}

func TestParseSkillMdCRLF(t *testing.T) {
	content := "---\r\nname: cc-crlf-u\r\ndescription: CRLF skill\r\n---\r\nbody\r\n"
	skill := parseSkillMd("dir-name", "/s/SKILL.md", content)
	assert.Equal(t, "cc-crlf-u", skill.name)
	assert.Equal(t, "CRLF skill", skill.description)
	assert.Equal(t, content, skill.content)
}

func TestParseSkillMdByteOrderMark(t *testing.T) {
	content := "\xef\xbb\xbf---\nname: bom-skill\ndescription: Saved with a BOM\n---\nbody\n"
	skill := parseSkillMd("dir-name", "/s/SKILL.md", content)
	assert.Equal(t, "bom-skill", skill.name)
}

func TestParseSkillMdUnterminatedFrontmatter(t *testing.T) {
	content := "---\nname: never-closed\ndescription: no closing line\n"
	skill := parseSkillMd("dir-name", "/s/SKILL.md", content)
	assert.Equal(t, "dir-name", skill.name)
	assert.Empty(t, skill.description)
}

func TestSplitSkillTools(t *testing.T) {
	assert.Equal(t, []string{"Bash(gh *)", "Bash(git *)", "Read"}, splitSkillTools("Bash(gh *), Bash(git *), Read"))
	assert.Equal(t, []string{"Read", "Grep"}, splitSkillTools("  Read\tGrep  "))
	assert.Nil(t, splitSkillTools("   "))
}
