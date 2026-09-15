// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/types"
)

// A resource accessor that returns a typed nil with no error is not the same as
// one that returns null. GetOrCompute stores the nil as set-and-not-null, and
// serializing that value calls MqlID on the nil receiver. This pins the
// mechanism the deployment accessors have to guard against.
func TestNilResourceIsNotAValidNullValue(t *testing.T) {
	var field plugin.TValue[*mqlAwsCodedeployDeployment]

	tv := plugin.GetOrCompute(&field, func() (*mqlAwsCodedeployDeployment, error) {
		return nil, nil
	})

	require.True(t, tv.IsSet(), "a typed nil still marks the field set")
	require.False(t, tv.IsNull(), "and it does not mark the field null, which is the trap")

	assert.Panics(t, func() {
		tv.ToDataRes(types.Resource("aws.codedeploy.deployment"))
	}, "serializing a set-but-nil resource dereferences the nil receiver in MqlID")
}

// The same field, marked null before the accessor returns, serializes cleanly.
func TestNullMarkedResourceSerializes(t *testing.T) {
	field := plugin.TValue[*mqlAwsCodedeployDeployment]{
		State: plugin.StateIsSet | plugin.StateIsNull,
	}

	res := field.ToDataRes(types.Resource("aws.codedeploy.deployment"))

	require.NotNil(t, res)
	assert.Empty(t, res.Error)
	require.NotNil(t, res.Data)
	assert.Equal(t, string(types.Nil), res.Data.Type)
}

func TestDeploymentGroupLastDeploymentsWithoutAReference(t *testing.T) {
	t.Run("no last successful deployment", func(t *testing.T) {
		dg := &mqlAwsCodedeployDeploymentGroup{}
		dg.sdkData = codedeploytypes.DeploymentGroupInfo{}

		dep, err := dg.lastSuccessfulDeployment()

		require.NoError(t, err)
		require.Nil(t, dep)
		assert.True(t, dg.LastSuccessfulDeployment.IsSet())
		assert.True(t, dg.LastSuccessfulDeployment.IsNull())
	})

	t.Run("last successful deployment carries no id", func(t *testing.T) {
		dg := &mqlAwsCodedeployDeploymentGroup{}
		dg.sdkData = codedeploytypes.DeploymentGroupInfo{
			LastSuccessfulDeployment: &codedeploytypes.LastDeploymentInfo{},
		}

		dep, err := dg.lastSuccessfulDeployment()

		require.NoError(t, err)
		require.Nil(t, dep)
		assert.True(t, dg.LastSuccessfulDeployment.IsSet())
		assert.True(t, dg.LastSuccessfulDeployment.IsNull())
	})

	t.Run("no last attempted deployment", func(t *testing.T) {
		dg := &mqlAwsCodedeployDeploymentGroup{}
		dg.sdkData = codedeploytypes.DeploymentGroupInfo{}

		dep, err := dg.lastAttemptedDeployment()

		require.NoError(t, err)
		require.Nil(t, dep)
		assert.True(t, dg.LastAttemptedDeployment.IsSet())
		assert.True(t, dg.LastAttemptedDeployment.IsNull())
	})

	t.Run("last attempted deployment carries no id", func(t *testing.T) {
		dg := &mqlAwsCodedeployDeploymentGroup{}
		dg.sdkData = codedeploytypes.DeploymentGroupInfo{
			LastAttemptedDeployment: &codedeploytypes.LastDeploymentInfo{},
		}

		dep, err := dg.lastAttemptedDeployment()

		require.NoError(t, err)
		require.Nil(t, dep)
		assert.True(t, dg.LastAttemptedDeployment.IsSet())
		assert.True(t, dg.LastAttemptedDeployment.IsNull())
	})
}
