// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestVerifiedAccessPolicyFields(t *testing.T) {
	g := &mqlAwsVerifiedaccessGroup{}
	g.policyFetched = true
	g.policy = &verifiedAccessPolicy{document: aws.String("permit(principal,action,resource);"), enabled: aws.Bool(true)}
	doc, err := g.policyDocument()
	require.NoError(t, err)
	assert.Equal(t, "permit(principal,action,resource);", doc)
	enabled, err := g.policyEnabled()
	require.NoError(t, err)
	assert.True(t, enabled)

	none := &mqlAwsVerifiedaccessEndpoint{}
	none.policyFetched = true
	none.policy = &verifiedAccessPolicy{enabled: aws.Bool(false)}
	_, err = none.policyDocument()
	require.NoError(t, err)
	assert.True(t, none.PolicyDocument.IsNull(), "no policy document reads null")
	enabled, err = none.policyEnabled()
	require.NoError(t, err)
	assert.False(t, enabled)
	assert.False(t, none.PolicyEnabled.IsNull())
}

func TestVerifiedAccessPolicyDenied(t *testing.T) {
	denied := func() (*verifiedAccessPolicy, error) {
		return nil, awsAPIErr(403, "UnauthorizedOperation", "not authorized to perform ec2:GetVerifiedAccessGroupPolicy")
	}

	c := &verifiedAccessPolicyCache{}
	policy, err := c.load("ec2:GetVerifiedAccessGroupPolicy", denied)
	require.NoError(t, err, "without structured errors a denial reads as null")
	assert.Nil(t, policy)

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	c = &verifiedAccessPolicyCache{}
	_, err = c.load("ec2:GetVerifiedAccessGroupPolicy", denied)
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrForbidden)
}
