// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The document IAM hands back for a policy scoped by a condition. This is the
// shape that used to lose its Condition block on the way through
// awspolicy.IamPolicyDocument, which has no Condition field.
const conditionPolicyJSON = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CondScoped",
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::example-bucket/*",
    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}
  }]
}`

func TestParseIamPolicyDocumentKeepsConditions(t *testing.T) {
	for _, tc := range []struct {
		title string
		input string
	}{
		{"raw json", conditionPolicyJSON},
		{"url-encoded, as IAM returns it", url.QueryEscape(conditionPolicyJSON)},
	} {
		t.Run(tc.title, func(t *testing.T) {
			doc, err := parseIamPolicyDocument(tc.input)
			require.NoError(t, err)

			stmts, ok := doc["Statement"].([]any)
			require.True(t, ok, "Statement should decode to a list")
			require.Len(t, stmts, 1)
			stmt, ok := stmts[0].(map[string]any)
			require.True(t, ok)

			// The regression: a policy that only grants access within an
			// organization read as an unconditional grant.
			cond, ok := stmt["Condition"].(map[string]any)
			require.True(t, ok, "Condition must survive decoding")
			eq, ok := cond["StringEquals"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "o-exampleorgid", eq["aws:PrincipalOrgID"])
		})
	}
}

func TestParseIamPolicyDocumentKeepsPrincipalShape(t *testing.T) {
	// statementSection flattened a principal map to a list of quoted values,
	// so {"AWS": "*"} came back as ["\"*\""] with the key gone.
	doc, err := parseIamPolicyDocument(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"*"}]}`)
	require.NoError(t, err)

	stmt := doc["Statement"].([]any)[0].(map[string]any)
	principal, ok := stmt["Principal"].(map[string]any)
	require.True(t, ok, "Principal must stay a map, not become a list of quoted strings")
	assert.Equal(t, "*", principal["AWS"])
}

func TestParseIamPolicyDocumentPreservesScalarAndArrayActions(t *testing.T) {
	// Action is legally either a string or an array; the raw document keeps
	// whichever IAM sent rather than normalizing both to a list.
	scalar, err := parseIamPolicyDocument(`{"Statement":[{"Action":"s3:GetObject"}]}`)
	require.NoError(t, err)
	assert.Equal(t, "s3:GetObject", scalar["Statement"].([]any)[0].(map[string]any)["Action"])

	array, err := parseIamPolicyDocument(`{"Statement":[{"Action":["s3:GetObject","s3:PutObject"]}]}`)
	require.NoError(t, err)
	assert.Equal(t, []any{"s3:GetObject", "s3:PutObject"},
		array["Statement"].([]any)[0].(map[string]any)["Action"])
}

func TestParseIamPolicyDocumentReportsUnreadableDocuments(t *testing.T) {
	_, err := parseIamPolicyDocument("not json and not url-encoded json {{{")
	assert.Error(t, err, "an unreadable document must not decode to an empty policy")
}

func TestDecodeIamPolicyDocumentTreatsUnreadableAsMissing(t *testing.T) {
	// The nil-returning wrapper keeps its existing contract for callers that
	// treat an unreadable document the way the API treats a missing one.
	assert.Nil(t, decodeIamPolicyDocument(nil))
	bad := "not json {{{"
	assert.Nil(t, decodeIamPolicyDocument(&bad))

	good := conditionPolicyJSON
	require.NotNil(t, decodeIamPolicyDocument(&good))
}
