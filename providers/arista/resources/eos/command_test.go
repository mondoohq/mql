// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// data decodes a JSON-RPC error's data the way the eAPI client does.
func data(t *testing.T, s string) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(s), &v))
	return v
}

func TestCommandMessages_JSON(t *testing.T) {
	// The `enable` that precedes the command succeeds; the command fails.
	d := data(t, `[{}, {"errors": ["There seem to be no power supplies connected."]}]`)
	assert.Equal(t, []string{"There seem to be no power supplies connected."}, commandMessages(d))
}

func TestCommandMessages_Text(t *testing.T) {
	d := data(t, `[{"output": ""}, {"output": "% Error displaying flash:/startup-config (No such file or directory)\n"}]`)
	assert.Equal(t, []string{"% Error displaying flash:/startup-config (No such file or directory)"}, commandMessages(d))
}

func TestCommandMessages_NoData(t *testing.T) {
	assert.Empty(t, commandMessages(nil))
	assert.Empty(t, commandMessages("not a list"))
}

func TestCommandError(t *testing.T) {
	base := errors.New("JSON Error(1000): CLI command 2 of 2 'show vrrp all' failed: invalid command")
	e := &CommandError{
		Command:  "show vrrp all",
		Messages: []string{"% Unavailable command (not supported on this hardware platform)"},
		Err:      base,
	}
	assert.True(t, e.HasMessage("Unavailable command"))
	assert.False(t, e.HasMessage("BGP inactive"))
	assert.ErrorIs(t, e, base)
	assert.Contains(t, e.Error(), "not supported on this hardware platform")

	var target *CommandError
	assert.True(t, errors.As(error(e), &target))
}
