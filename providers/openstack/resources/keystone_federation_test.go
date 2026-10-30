// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/federation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A mapping's rules are the point where an external assertion becomes local
// authorization, so they have to survive the trip to a dict intact and in a
// JSON-native shape.
func TestMappingRulesToDict(t *testing.T) {
	const body = `[
      {
        "local": [
          {"user": {"name": "{0}"}},
          {"group": {"id": "3d5f4c1b1a2e4a9f8c7b6a5d4e3f2a1b"}}
        ],
        "remote": [
          {"type": "OIDC-preferred_username"},
          {"type": "OIDC-groups", "any_one_of": ["platform-admins"], "regex": true}
        ]
      }
    ]`
	var rules []federation.MappingRule
	require.NoError(t, json.Unmarshal([]byte(body), &rules))

	out, err := mappingRulesToDict(rules)
	require.NoError(t, err)
	require.Len(t, out, 1)

	rule, ok := out[0].(map[string]any)
	require.True(t, ok, "rule must decode to a plain map, not a struct")

	local, ok := rule["local"].([]any)
	require.True(t, ok)
	require.Len(t, local, 2)
	group, ok := local[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"id": "3d5f4c1b1a2e4a9f8c7b6a5d4e3f2a1b"}, group["group"])

	remote, ok := rule["remote"].([]any)
	require.True(t, ok)
	require.Len(t, remote, 2)
	condition, ok := remote[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "OIDC-groups", condition["type"])
	assert.Equal(t, []any{"platform-admins"}, condition["any_one_of"])
	assert.Equal(t, true, condition["regex"])
}

func TestMappingRulesToDictEmpty(t *testing.T) {
	out, err := mappingRulesToDict(nil)
	require.NoError(t, err)
	assert.Equal(t, []any{}, out)
}

func TestRequiredByNames(t *testing.T) {
	assert.Nil(t, requiredByNames(nil))
	assert.Nil(t, requiredByNames([]any{}))
	assert.Equal(t, []string{"web_server", "db"}, requiredByNames([]any{"web_server", "db"}))
	// The API types the entries as free-form, so a non-string must still render
	// rather than drop out of the list.
	assert.Equal(t, []string{"web_server", "7"}, requiredByNames([]any{"web_server", 7}))
}
