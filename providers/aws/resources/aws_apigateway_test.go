// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApigatewayPolicyJSON(t *testing.T) {
	// Synthetic: the backslash-escaped shape GetRestApis returns for a resource policy.
	escaped := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"execute-api:Invoke\",\"Resource\":\"arn:aws:execute-api:us-east-1:123456789012:abc123/*\"}]}`
	got := apigatewayPolicyJSON(escaped)
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(got), &doc))
	assert.Equal(t, "2012-10-17", doc["Version"])
	assert.Len(t, doc["Statement"], 1)

	// Measured: GetRestApis on a PRIVATE REST API, us-west-2, 2026-11-23 (account
	// and ids replaced). Slashes arrive escaped as well as quotes.
	measured := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"execute-api:Invoke\",\"Resource\":\"arn:aws:execute-api:us-west-2:123456789012:abcde12345\/*\",\"Condition\":{\"StringEquals\":{\"aws:SourceVpce\":\"vpce-0123456789abcdef0\"}}}]}`
	got = apigatewayPolicyJSON(measured)
	doc = map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(got), &doc))
	stmt := doc["Statement"].([]any)[0].(map[string]any)
	assert.Equal(t, "arn:aws:execute-api:us-west-2:123456789012:abcde12345/*", stmt["Resource"])

	// Synthetic: a document that already parses passes through unchanged.
	plain := `{"Version":"2012-10-17","Statement":[]}`
	assert.Equal(t, plain, apigatewayPolicyJSON(plain))
	assert.Equal(t, "", apigatewayPolicyJSON(""))
	// Synthetic: garbage stays garbage rather than turning into something else.
	assert.Equal(t, `not json \x`, apigatewayPolicyJSON(`not json \x`))
}

func TestRestApiIsPublic(t *testing.T) {
	regional := []any{"REGIONAL"}
	edge := []any{"EDGE"}
	private := []any{"PRIVATE"}
	// Synthetic: no resource policy on an internet-facing endpoint.
	assert.True(t, restApiIsPublic(regional, false, false, false))
	assert.True(t, restApiIsPublic(edge, false, false, false))
	// Synthetic: a policy that grants a wildcard principal without scoping.
	assert.True(t, restApiIsPublic(regional, false, true, true))
	// Synthetic: a policy that scopes callers.
	assert.False(t, restApiIsPublic(regional, false, true, false))
	// Synthetic: PRIVATE endpoints and a disabled default endpoint are never reachable this way.
	assert.False(t, restApiIsPublic(private, false, false, false))
	assert.False(t, restApiIsPublic(private, false, true, true))
	assert.False(t, restApiIsPublic(regional, true, false, false))
	assert.False(t, restApiIsPublic([]any{}, false, false, false))
}
