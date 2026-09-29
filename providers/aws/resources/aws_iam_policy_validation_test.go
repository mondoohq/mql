// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyDocumentText(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	got, err := policyDocumentText(doc)
	require.NoError(t, err)
	assert.Equal(t, doc, got, "plain JSON passes through unchanged")

	got, err = policyDocumentText(url.QueryEscape(doc))
	require.NoError(t, err)
	assert.Equal(t, doc, got, "IAM's URL-encoded form is decoded")
}

func TestValidatePolicyFindingsToDicts(t *testing.T) {
	got := validatePolicyFindingsToDicts([]aatypes.ValidatePolicyFinding{{
		FindingType:    aatypes.ValidatePolicyFindingTypeSecurityWarning,
		IssueCode:      aws.String("PASS_ROLE_WITH_STAR_IN_RESOURCE"),
		FindingDetails: aws.String("Using the iam:PassRole action with wildcards (*) in the resource can be overly permissive"),
		LearnMoreLink:  aws.String("https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html"),
		Locations: []aatypes.Location{{
			Path: []aatypes.PathElement{
				&aatypes.PathElementMemberKey{Value: "Statement"},
				&aatypes.PathElementMemberIndex{Value: 0},
				&aatypes.PathElementMemberSubstring{Value: aatypes.Substring{Start: aws.Int32(3), Length: aws.Int32(5)}},
			},
			Span: &aatypes.Span{
				Start: &aatypes.Position{Line: aws.Int32(1), Column: aws.Int32(2), Offset: aws.Int32(3)},
				End:   &aatypes.Position{Line: aws.Int32(1), Column: aws.Int32(9), Offset: aws.Int32(10)},
			},
		}},
	}})
	require.Len(t, got, 1)
	f := got[0].(map[string]any)
	assert.Equal(t, "SECURITY_WARNING", f["findingType"])
	assert.Equal(t, "PASS_ROLE_WITH_STAR_IN_RESOURCE", f["issueCode"])
	locs := f["locations"].([]any)
	require.Len(t, locs, 1)
	loc := locs[0].(map[string]any)
	assert.Equal(t, []any{"Statement", int64(0), map[string]any{"start": int64(3), "length": int64(5)}}, loc["path"])
	span := loc["span"].(map[string]any)
	assert.Equal(t, map[string]any{"line": int64(1), "column": int64(9), "offset": int64(10)}, span["end"])
}

func TestUnusedAccessConfiguration(t *testing.T) {
	assert.Nil(t, unusedAccessAge(nil), "a non-unused-access analyzer has no age")
	assert.Equal(t, []any{}, unusedAccessExclusions(nil))

	internal := &aatypes.AnalyzerConfigurationMemberInternalAccess{}
	assert.Nil(t, unusedAccessAge(internal))

	cfg := &aatypes.AnalyzerConfigurationMemberUnusedAccess{Value: aatypes.UnusedAccessConfiguration{
		UnusedAccessAge: aws.Int32(90),
		AnalysisRule: &aatypes.AnalysisRule{Exclusions: []aatypes.AnalysisRuleCriteria{
			{AccountIds: []string{"123456789012"}},
			{ResourceTags: []map[string]string{{"break-glass": "true"}}},
		}},
	}}
	require.NotNil(t, unusedAccessAge(cfg))
	assert.Equal(t, int32(90), *unusedAccessAge(cfg))
	assert.Equal(t, []any{
		map[string]any{"accountIds": []any{"123456789012"}, "resourceTags": []any{}},
		map[string]any{"accountIds": []any{}, "resourceTags": []any{map[string]any{"break-glass": "true"}}},
	}, unusedAccessExclusions(cfg))
}
