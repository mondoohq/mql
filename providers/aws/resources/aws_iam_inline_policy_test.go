// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const inlinePolicyDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

func TestDecodeIamPolicyDocument(t *testing.T) {
	tests := []struct {
		name     string
		document *string
		wantNil  bool
	}{
		{"nil document", nil, true},
		{"plain json", aws.String(inlinePolicyDoc), false},
		{"url-encoded json", aws.String(url.QueryEscape(inlinePolicyDoc)), false},
		{"empty string", aws.String(""), true},
		{"not a policy", aws.String("this is not json"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeIamPolicyDocument(tt.document)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, "2012-10-17", got["Version"])
			assert.NotEmpty(t, got["Statement"])
		})
	}
}

// A plain-JSON document that contains a `+` must not be URL-decoded, since
// QueryUnescape turns `+` into a space and would corrupt the value.
func TestDecodeIamPolicyDocumentPreservesPlus(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/a+b"}]}`
	got := decodeIamPolicyDocument(&doc)
	require.NotNil(t, got)

	statements, ok := got["Statement"].([]any)
	require.True(t, ok)
	statement, ok := statements[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "arn:aws:s3:::bucket/a+b", statement["Resource"])
}

func TestStatementsAllowWildcard(t *testing.T) {
	statement := func(effect string, actions, resources []any) *mqlAwsIamPolicyStatement {
		return &mqlAwsIamPolicyStatement{
			Effect:    setString(effect),
			Actions:   plugin.TValue[[]any]{Data: actions, State: plugin.StateIsSet},
			Resources: plugin.TValue[[]any]{Data: resources, State: plugin.StateIsSet},
		}
	}
	scoped := []any{"s3:GetObject"}
	scopedRes := []any{"arn:aws:s3:::bucket/*"}

	tests := []struct {
		name       string
		statements []any
		want       bool
	}{
		{"no statements", []any{}, false},
		{"scoped allow", []any{statement("Allow", scoped, scopedRes)}, false},
		{"wildcard action", []any{statement("Allow", []any{"s3:*"}, scopedRes)}, true},
		{"global action", []any{statement("Allow", []any{"*"}, scopedRes)}, true},
		{"wildcard resource", []any{statement("Allow", scoped, []any{"*"})}, true},
		{"lowercase effect", []any{statement("allow", []any{"*"}, scopedRes)}, true},
		{"wildcard deny is not a grant", []any{statement("Deny", []any{"*"}, []any{"*"})}, false},
		{
			"wildcard in a later statement",
			[]any{statement("Allow", scoped, scopedRes), statement("Allow", []any{"iam:*"}, scopedRes)},
			true,
		},
		{"non-statement element is skipped", []any{"not a statement"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := statementsAllowWildcard(tt.statements)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInlinePolicyHasWildcardAllow(t *testing.T) {
	wildcard := &mqlAwsIamPolicyStatement{
		Effect:    setString("Allow"),
		Actions:   plugin.TValue[[]any]{Data: []any{"*"}, State: plugin.StateIsSet},
		Resources: plugin.TValue[[]any]{Data: []any{"*"}, State: plugin.StateIsSet},
	}

	policy := &mqlAwsIamInlinePolicy{
		Statements: plugin.TValue[[]any]{Data: []any{wildcard}, State: plugin.StateIsSet},
	}
	got, err := policy.hasWildcardAllow()
	require.NoError(t, err)
	assert.True(t, got)

	empty := &mqlAwsIamInlinePolicy{
		Statements: plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet},
	}
	got, err = empty.hasWildcardAllow()
	require.NoError(t, err)
	assert.False(t, got)
}
