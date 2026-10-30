// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awspolicy

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS3BucketPolicies(t *testing.T) {
	files := []string{
		"./testdata/s3bucket_policy1.json",
		"./testdata/s3bucket_policy2.json",
		"./testdata/s3bucket_policy3.json",
		"./testdata/s3bucket_policy_array.json",
		"./testdata/s3bucket_multistatement.json",
		"./testdata/s3bucket_multielements.json",
		"./testdata/s3bucket_multiblock.json",
		"./testdata/s3bucket_2008_public.json",
		"./testdata/s3bucket_2008_iprestriction.json",
		"./testdata/s3bucket_compliant.json",
		"./testdata/s3bucket_noncompliant.json",
		"./testdata/s3bucket_principal.json",
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		require.NoError(t, err, f)

		var policy S3BucketPolicy
		err = json.Unmarshal(data, &policy)
		require.NoError(t, err, f)
	}
}

func TestPolicyPrincipal(t *testing.T) {
	f := "./testdata/s3bucket_principal.json"
	data, err := os.ReadFile(f)
	require.NoError(t, err, f)

	var policy S3BucketPolicy
	err = json.Unmarshal(data, &policy)
	require.NoError(t, err, f)

	assert.Equal(t, map[string][]string{
		"AWS": {"*"},
	}, policy.Statements[0].Principal.Data())
}

// TestPolicyPrincipalArray guards against a regression where an array-valued
// principal (e.g. {"Service": ["a", "b"]}) was rendered as a single bracketed
// string instead of a slice of the individual values.
func TestPolicyPrincipalArray(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": ["lambda.amazonaws.com", "logs.amazonaws.com"]},
			"Action": "sts:AssumeRole"
		}]
	}`

	var policy S3BucketPolicy
	err := json.Unmarshal([]byte(doc), &policy)
	require.NoError(t, err)

	assert.Equal(t, map[string][]string{
		"Service": {"lambda.amazonaws.com", "logs.amazonaws.com"},
	}, policy.Statements[0].Principal.Data())
}

// TestS3BucketPolicySingleObjectStatement covers the single-object Statement
// shape the IAM policy grammar allows. Without the s3Statements unmarshaller it
// failed to decode, so policyStatements/isPublic/hasWildcardAllow errored on
// such documents while the sibling IamPolicyDocument parsed them fine.
func TestS3BucketPolicySingleObjectStatement(t *testing.T) {
	var p S3BucketPolicy
	err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}`), &p)
	require.NoError(t, err)
	require.Len(t, p.Statements, 1)
	assert.Equal(t, "Allow", p.Statements[0].Effect)
	assert.Equal(t, []string{"*"}, p.Statements[0].Principal["AWS"])
}

func TestS3BucketPolicyArrayStatementStillWorks(t *testing.T) {
	var p S3BucketPolicy
	err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
		{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}`), &p)
	require.NoError(t, err)
	require.Len(t, p.Statements, 2)
	assert.Equal(t, "Deny", p.Statements[1].Effect)
}
