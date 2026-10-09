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

func TestClassifyAgentInstruction(t *testing.T) {
	tests := []struct {
		rel   string
		agent string
		ok    bool
	}{
		{"AGENTS.md", "", true},
		{"services/api/AGENTS.md", "", true},
		{"CLAUDE.md", "claude.code", true},
		{".claude/CLAUDE.md", "claude.code", true},
		{"CLAUDE.local.md", "claude.code", true},
		{"GEMINI.md", "gemini", true},
		{"WARP.md", "warp", true},
		{".cursorrules", "cursor", true},
		{".cursor/rules/style.mdc", "cursor", true},
		{".cursor/rules/team/review.md", "cursor", true}, // cursor reads nested rule directories
		{"web/.cursor/rules/ui.mdc", "cursor", true},
		{".cursor/rules/notes.txt", "", false},
		{".windsurfrules", "windsurf", true},
		{".windsurf/rules/a.md", "windsurf", true},
		{".windsurf/rules/sub/a.md", "", false},
		{".clinerules", "cline", true},
		{".clinerules/testing.md", "cline", true},
		{".kiro/steering/product.md", "kiro", true},
		{".roo/rules/any-file", "roo", true},
		{".roo/rules-code/style.md", "roo", true},
		{".trae/rules/project_rules.md", "trae", true},
		{".kilocode/rules/a.md", "kilocode", true},
		{".augment/rules/a.md", "augment", true},
		{".github/copilot-instructions.md", "github.copilot", true},
		{".github/instructions/go.instructions.md", "github.copilot", true},
		{".github/instructions/README.md", "", false},
		{".junie/guidelines.md", "junie", true},
		{"README.md", "", false},
		{"docs/agents.md", "", false}, // names are case-sensitive, as agents read them
		{"rules/a.md", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.rel, func(t *testing.T) {
			agent, ok := classifyAgentInstruction(tt.rel)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.agent, agent)
		})
	}
}

func TestFindAgentInstructions(t *testing.T) {
	mem := afero.NewMemMapFs()
	for _, p := range []string{
		"/repo/AGENTS.md",
		"/repo/README.md",
		"/repo/.cursor/rules/style.mdc",
		"/repo/services/api/CLAUDE.md",
		"/repo/node_modules/dep/AGENTS.md",
		"/repo/.git/CLAUDE.md",
		"/repo/locked/AGENTS.md",
	} {
		require.NoError(t, afero.WriteFile(mem, p, []byte("x"), 0o644))
	}

	got, err := findAgentInstructions(&afero.Afero{Fs: &denyFs{Fs: mem, deny: "/repo/locked"}}, "/repo")
	require.NoError(t, err)
	assert.Equal(t, []agentInstructionFile{
		{path: "/repo/.cursor/rules/style.mdc", agent: "cursor"},
		{path: "/repo/AGENTS.md", agent: ""},
		{path: "/repo/services/api/CLAUDE.md", agent: "claude.code"},
	}, got)
}

func TestFindAgentInstructionsDepthLimit(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/r/1/2/3/4/5/6/7/8/9/10/AGENTS.md", []byte("x"), 0o644))
	require.NoError(t, afero.WriteFile(mem, "/r/1/2/3/4/5/6/7/8/9/10/11/AGENTS.md", []byte("x"), 0o644))

	got, err := findAgentInstructions(&afero.Afero{Fs: mem}, "/r")
	require.NoError(t, err)
	assert.Equal(t, []agentInstructionFile{{path: "/r/1/2/3/4/5/6/7/8/9/10/AGENTS.md"}}, got)
}

func TestFindAgentInstructionsRoot(t *testing.T) {
	_, err := findAgentInstructions(&afero.Afero{Fs: afero.NewMemMapFs()}, "/nope")
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrNotFound), "a missing path is NotFound, got %v", err)

	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/repo/AGENTS.md", []byte("x"), 0o644))
	_, err = findAgentInstructions(&afero.Afero{Fs: mem}, "/repo/AGENTS.md")
	assert.ErrorContains(t, err, "is not a directory")
}
