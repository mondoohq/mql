// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAgentHookEvents(t *testing.T) {
	// Synthetic: two events written out of order, one group without a
	// matcher, two handlers under one matcher, an exec-form command with args,
	// an http handler, and timeouts set and unset; no target showed all of
	// these in one file.
	raw := json.RawMessage(`{
	  "PreToolUse": [
	    {"matcher": "Bash", "hooks": [
	      {"type": "command", "command": "/opt/guard/check.sh", "timeout": 30},
	      {"type": "command", "command": "/usr/bin/logger", "args": ["-t", "claude"]}
	    ]},
	    {"matcher": "Edit|Write", "hooks": [{"type": "http", "url": "https://hooks.example.com/edit"}]}
	  ],
	  "Notification": [
	    {"hooks": [{"type": "command", "command": "notify-send done"}]}
	  ]
	}`)
	hooks, err := parseAgentHookEvents(raw)
	require.NoError(t, err)
	require.Len(t, hooks, 4)

	// Events sorted by name, groups and handlers in file order.
	assert.Equal(t, "Notification", hooks[0].event)
	assert.Equal(t, "", hooks[0].matcher, "an omitted matcher reads as empty")
	assert.Equal(t, "notify-send done", hooks[0].handler.Command)
	assert.Nil(t, hooks[0].timeout(), "an unset timeout is null, not 0")

	assert.Equal(t, "PreToolUse", hooks[1].event)
	assert.Equal(t, "Bash", hooks[1].matcher)
	assert.Equal(t, "/opt/guard/check.sh", hooks[1].handler.Command)
	require.NotNil(t, hooks[1].timeout())
	assert.Equal(t, int64(30), *hooks[1].timeout())

	assert.Equal(t, "Bash", hooks[2].matcher, "both handlers of one matcher keep it")
	assert.Equal(t, []string{"-t", "claude"}, hooks[2].handler.Args)
	assert.Equal(t, 0, hooks[2].group)
	assert.Equal(t, 1, hooks[2].index)

	assert.Equal(t, "Edit|Write", hooks[3].matcher)
	assert.Equal(t, "http", hooks[3].handler.Type)
	assert.Equal(t, "https://hooks.example.com/edit", hooks[3].handler.URL)
	assert.Equal(t, 1, hooks[3].group)

	ids := map[string]struct{}{}
	for _, h := range hooks {
		ids[h.id("claude.code.hook", "/home/u/.claude/settings.json")] = struct{}{}
	}
	assert.Len(t, ids, 4, "every hook of one file has its own id")
}

func TestParseAgentHookEventsEmpty(t *testing.T) {
	// Synthetic: no hooks key, an explicit null, and an empty map.
	for _, raw := range []string{"", "null", "{}"} {
		hooks, err := parseAgentHookEvents(json.RawMessage(raw))
		require.NoError(t, err, raw)
		assert.Empty(t, hooks, raw)
	}
}

func TestParseAgentHookEventsMalformed(t *testing.T) {
	// Synthetic: shapes the hooks schema does not allow.
	for name, raw := range map[string]string{
		"hooks is a list":           `[{"matcher": "Bash"}]`,
		"event is an object":        `{"PreToolUse": {"matcher": "Bash", "hooks": []}}`,
		"handlers is not a list":    `{"PreToolUse": [{"hooks": {"type": "command"}}]}`,
		"handler is a string":       `{"PreToolUse": [{"hooks": ["echo hi"]}]}`,
		"command is not a string":   `{"PreToolUse": [{"hooks": [{"type": "command", "command": 1}]}]}`,
		"timeout is not a number":   `{"PreToolUse": [{"hooks": [{"type": "command", "timeout": "30"}]}]}`,
		"matcher is not a string":   `{"PreToolUse": [{"matcher": ["Bash"], "hooks": []}]}`,
		"top level is not a object": `"PreToolUse"`,
	} {
		_, err := parseAgentHookEvents(json.RawMessage(raw))
		assert.Error(t, err, name)
	}
}

func TestReadAgentHooksFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	writeTestFiles(t, fs, map[string]string{
		"/cfg/no-hooks.json":  `{"model": "opus"}`,
		"/cfg/broken.json":    `{"hooks": `,
		"/cfg/malformed.json": `{"hooks": {"Stop": "echo bye"}}`,
		"/cfg/ok.json":        `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}]}}`,
	})

	// Synthetic: a missing file and a file without hooks have none.
	hooks, err := readAgentHooksFile(afs, "/cfg/missing.json", unmarshalJSONConfig)
	require.NoError(t, err)
	assert.Empty(t, hooks)
	hooks, err = readAgentHooksFile(afs, "/cfg/no-hooks.json", unmarshalJSONConfig)
	require.NoError(t, err)
	assert.Empty(t, hooks)

	// Synthetic: invalid JSON and a malformed hooks block are errors naming the file.
	_, err = readAgentHooksFile(afs, "/cfg/broken.json", unmarshalJSONConfig)
	assert.Error(t, err)
	_, err = readAgentHooksFile(afs, "/cfg/malformed.json", unmarshalJSONConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/cfg/malformed.json")

	hooks, err = readAgentHooksFile(afs, "/cfg/ok.json", unmarshalJSONConfig)
	require.NoError(t, err)
	require.Len(t, hooks, 1)
	assert.Equal(t, "echo bye", hooks[0].handler.Command)
}
