// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJsonParamsRepairsMalformedApparmorOutput(t *testing.T) {
	content := `{"version": "1", "profiles": {, "/usr/bin/man": "complain"}, "processes": {], "/usr/sbin/chronyd": [{"profile": "/usr/sbin/chronyd", "pid": "339", "status": "unconfined"}]}}`

	res, err := (&mqlParseJson{}).params(content)
	require.NoError(t, err)

	params := res.(map[string]any)
	assert.Equal(t, "1", params["version"])

	profiles := params["profiles"].(map[string]any)
	assert.Equal(t, "complain", profiles["/usr/bin/man"])

	processes := params["processes"].(map[string]any)
	chronyd := processes["/usr/sbin/chronyd"].([]any)
	require.Len(t, chronyd, 1)

	proc := chronyd[0].(map[string]any)
	assert.Equal(t, "/usr/sbin/chronyd", proc["profile"])
	assert.Equal(t, "339", proc["pid"])
	assert.Equal(t, "unconfined", proc["status"])
}

func TestParseJsonParamsRejectsUnrepairableJSON(t *testing.T) {
	_, err := (&mqlParseJson{}).params(`{"version": nope}`)
	require.Error(t, err)
}
