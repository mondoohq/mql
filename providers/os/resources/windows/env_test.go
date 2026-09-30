// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnv(t *testing.T) {
	r, err := os.Open("./testdata/env.json")
	require.NoError(t, err)

	items, err := ParseEnv(r)
	assert.Nil(t, err)
	assert.Equal(t, 9, len(items))

	assert.Equal(t, "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;C:\\Windows\\System32\\OpenSSH\\;C:\\Program Files\\Amazon\\cfn-bootstrap\\;C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\WindowsApps;C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\WindowsApps;", items["Path"])
}

// ConvertTo-Json emits a bare object for a single variable.
func TestParseEnvSingleObject(t *testing.T) {
	items, err := ParseEnv(strings.NewReader(`{"Key":"Path","Value":"C:\\Windows"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"Path": `C:\Windows`}, items)

	items, err = ParseEnv(strings.NewReader(`[{"Key":"A","Value":"1"},{"Key":"B","Value":"2"}]`))
	require.NoError(t, err)
	assert.Len(t, items, 2)
}
