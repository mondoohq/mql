// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sagemakerTypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- Endpoint sub-resource tests ----

func TestEndpointDataCaptureConfigKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		dcc := &mqlAwsSagemakerEndpointDataCaptureConfig{}
		result, err := dcc.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, dcc.KmsKey.State&plugin.StateIsNull != 0)
		assert.True(t, dcc.KmsKey.State&plugin.StateIsSet != 0)
	})

	t.Run("empty key ID sets null state", func(t *testing.T) {
		dcc := &mqlAwsSagemakerEndpointDataCaptureConfig{}
		empty := ""
		dcc.cacheKmsKeyId = &empty
		result, err := dcc.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, dcc.KmsKey.State&plugin.StateIsNull != 0)
		assert.True(t, dcc.KmsKey.State&plugin.StateIsSet != 0)
	})
}

func TestEndpointDataCaptureConfigId(t *testing.T) {
	dcc := &mqlAwsSagemakerEndpointDataCaptureConfig{}
	dcc.cacheEndpointArn = "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-endpoint"
	id, err := dcc.id()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-endpoint/dataCaptureConfig", id)
}

func TestProductionVariantId(t *testing.T) {
	pv := &mqlAwsSagemakerEndpointProductionVariant{}
	pv.cacheParentId = "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-endpoint"
	pv.VariantName = plugin.TValue[string]{Data: "variant-1", State: plugin.StateIsSet}
	id, err := pv.id()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-endpoint/variant-1", id)
}

func TestProductionVariantStatusId(t *testing.T) {
	vs := &mqlAwsSagemakerEndpointProductionVariantStatus{}
	vs.cacheParentId = "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-endpoint/variant-1"
	vs.Status = plugin.TValue[string]{Data: "ActivatingTraffic", State: plugin.StateIsSet}
	id, err := vs.id()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-endpoint/variant-1/status/ActivatingTraffic", id)
}

func TestProductionVariantNullDicts(t *testing.T) {
	t.Run("nil serverless config returns nil", func(t *testing.T) {
		pv := &mqlAwsSagemakerEndpointProductionVariant{}
		result, err := pv.currentServerlessConfig()
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("nil managed instance scaling returns nil", func(t *testing.T) {
		pv := &mqlAwsSagemakerEndpointProductionVariant{}
		result, err := pv.managedInstanceScaling()
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("nil routing config returns nil", func(t *testing.T) {
		pv := &mqlAwsSagemakerEndpointProductionVariant{}
		result, err := pv.routingConfig()
		require.NoError(t, err)
		require.Nil(t, result)
	})
}

// ---- sagemakerBuildProductionVariants tests ----

func TestSagemakerBuildProductionVariantsEmpty(t *testing.T) {
	result, err := sagemakerBuildProductionVariants(nil, "parent-arn", nil, "")
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestBuildProductionVariantsWithData(t *testing.T) {
	now := time.Now()
	variants := []sagemakerTypes.ProductionVariantSummary{
		{
			VariantName:          aws.String("AllTraffic"),
			CurrentInstanceCount: aws.Int32(2),
			DesiredInstanceCount: aws.Int32(2),
			CurrentWeight:        aws.Float32(1.0),
			DesiredWeight:        aws.Float32(1.0),
			VariantStatus: []sagemakerTypes.ProductionVariantStatus{
				{
					Status:    sagemakerTypes.VariantStatusActivatingTraffic,
					StartTime: &now,
				},
			},
		},
	}

	// Verify the helper doesn't panic on nil runtime with empty input
	emptyResult, err := sagemakerBuildProductionVariants(nil, "parent", nil, "")
	require.NoError(t, err)
	assert.Empty(t, emptyResult)

	// Verify variant data structure
	assert.Len(t, variants, 1)
	assert.Equal(t, "AllTraffic", *variants[0].VariantName)
	assert.Equal(t, int32(2), *variants[0].CurrentInstanceCount)
	assert.Len(t, variants[0].VariantStatus, 1)
}

// ---- Model sub-resource tests ----

// TestModelContainerId exercises sagemakerModelContainerID directly -- the
// helper buildContainer actually uses. The previous version of this test
// hand-primed cacheModelArn and called id(), asserting a state the production
// path can never reach (cacheModelArn is assigned after CreateResource
// returns), so it passed while every container in an account collided.
func TestModelContainerId(t *testing.T) {
	const modelArn = "arn:aws:sagemaker:us-east-1:123456789012:model/my-model"

	t.Run("uses containerHostname when set", func(t *testing.T) {
		assert.Equal(t,
			modelArn+"/container/my-container",
			sagemakerModelContainerID(modelArn, "my-container", "image-uri"))
	})

	t.Run("falls back to image when hostname is empty", func(t *testing.T) {
		image := "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-image:latest"
		assert.Equal(t,
			modelArn+"/container/"+image,
			sagemakerModelContainerID(modelArn, "", image))
	})

	// The regression: two models sharing a base inference image (the common
	// case, since ContainerHostname is nil unless a model has multiple
	// containers) must not produce the same cache key.
	t.Run("models sharing a base image get distinct keys", func(t *testing.T) {
		image := "123456789012.dkr.ecr.us-east-1.amazonaws.com/huggingface-pytorch-inference:2.1-cpu"
		a := sagemakerModelContainerID("arn:aws:sagemaker:us-east-1:123456789012:model/model-a", "", image)
		b := sagemakerModelContainerID("arn:aws:sagemaker:us-east-1:123456789012:model/model-b", "", image)
		assert.NotEqual(t, a, b)
	})

	// An inference-pipeline model has several containers; they must stay distinct.
	t.Run("pipeline containers within one model get distinct keys", func(t *testing.T) {
		a := sagemakerModelContainerID(modelArn, "preprocess", "img")
		b := sagemakerModelContainerID(modelArn, "predict", "img")
		assert.NotEqual(t, a, b)
	})
}

func TestModelContainerNullDicts(t *testing.T) {
	t.Run("nil imageConfig returns nil", func(t *testing.T) {
		c := &mqlAwsSagemakerModelContainer{}
		result, err := c.imageConfig()
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("nil multiModelConfig returns nil", func(t *testing.T) {
		c := &mqlAwsSagemakerModelContainer{}
		result, err := c.multiModelConfig()
		require.NoError(t, err)
		require.Nil(t, result)
	})
}

// ---- Training job sub-resource tests ----

func TestTrainingJobStatusTransitionId(t *testing.T) {
	startTime := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	st := &mqlAwsSagemakerTrainingjobStatusTransition{}
	st.cacheParentArn = "arn:aws:sagemaker:us-east-1:123456789012:training-job/my-job"
	st.Status = plugin.TValue[string]{Data: "Training", State: plugin.StateIsSet}
	st.StartTime = plugin.TValue[*time.Time]{Data: &startTime, State: plugin.StateIsSet}
	id, err := st.id()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:sagemaker:us-east-1:123456789012:training-job/my-job/statusTransition/Training/"+startTime.String(), id)
}

func TestTrainingJobMetricDataId(t *testing.T) {
	ts := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	md := &mqlAwsSagemakerTrainingjobMetricData{}
	md.cacheParentArn = "arn:aws:sagemaker:us-east-1:123456789012:training-job/my-job"
	md.MetricName = plugin.TValue[string]{Data: "train:loss", State: plugin.StateIsSet}
	md.Timestamp = plugin.TValue[*time.Time]{Data: &ts, State: plugin.StateIsSet}
	id, err := md.id()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:sagemaker:us-east-1:123456789012:training-job/my-job/metric/train:loss/"+ts.String(), id)
}

// ---- Cluster tests ----

func TestClusterInstanceGroupId(t *testing.T) {
	ig := &mqlAwsSagemakerClusterInstanceGroup{}
	ig.cacheClusterName = "my-cluster"
	ig.Region = plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet}
	ig.InstanceGroupName = plugin.TValue[string]{Data: "workers", State: plugin.StateIsSet}
	id, err := ig.id()
	require.NoError(t, err)
	assert.Equal(t, "us-east-1/my-cluster/workers", id)
}

func TestClusterNodeId(t *testing.T) {
	node := &mqlAwsSagemakerClusterNode{}
	node.cacheClusterName = "my-cluster"
	node.Region = plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet}
	node.InstanceGroupName = plugin.TValue[string]{Data: "workers", State: plugin.StateIsSet}
	node.InstanceId = plugin.TValue[string]{Data: "i-1234567890abcdef0", State: plugin.StateIsSet}
	id, err := node.id()
	require.NoError(t, err)
	assert.Equal(t, "us-east-1/my-cluster/workers/i-1234567890abcdef0", id)
}

func TestClusterInstanceGroupIamRole(t *testing.T) {
	t.Run("nil role sets null state", func(t *testing.T) {
		ig := &mqlAwsSagemakerClusterInstanceGroup{}
		result, err := ig.iamRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, ig.IamRole.State&plugin.StateIsNull != 0)
		assert.True(t, ig.IamRole.State&plugin.StateIsSet != 0)
	})

	t.Run("empty role sets null state", func(t *testing.T) {
		ig := &mqlAwsSagemakerClusterInstanceGroup{}
		empty := ""
		ig.cacheExecutionRole = &empty
		result, err := ig.iamRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, ig.IamRole.State&plugin.StateIsNull != 0)
		assert.True(t, ig.IamRole.State&plugin.StateIsSet != 0)
	})
}

// ---- sagemakerTagsCache tests ----

func TestSagemakerTagsCacheDoubleCheckLocking(t *testing.T) {
	cache := &sagemakerTagsCache{}
	assert.False(t, cache.tagsFetched.Load())
	assert.Nil(t, cache.cacheTags)

	// Simulate pre-fetched tags (as done during eager loading)
	cache.cacheTags = map[string]any{"env": "prod"}
	cache.tagsFetched.Store(true)

	assert.True(t, cache.tagsFetched.Load())
	assert.Equal(t, map[string]any{"env": "prod"}, cache.cacheTags)
}

// ---- Feature definition tests ----

func TestFeatureDefinitionId(t *testing.T) {
	fd := &mqlAwsSagemakerFeatureDefinition{}
	fd.cacheFeatureGroupArn = "arn:aws:sagemaker:us-east-1:123456789012:feature-group/my-fg"
	fd.FeatureName = plugin.TValue[string]{Data: "user_id", State: plugin.StateIsSet}
	fd.FeatureType = plugin.TValue[string]{Data: "String", State: plugin.StateIsSet}
	id, err := fd.id()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:sagemaker:us-east-1:123456789012:feature-group/my-fg/user_id/String", id)
}

// ---- Instance type detail tests ----

func TestClusterInstanceTypeDetailId(t *testing.T) {
	itd := &mqlAwsSagemakerClusterInstanceGroupInstanceTypeDetail{}
	itd.cacheParentGroupID = "us-east-1/my-cluster/workers"
	itd.InstanceType = plugin.TValue[string]{Data: "ml.g5.xlarge", State: plugin.StateIsSet}
	id, err := itd.id()
	require.NoError(t, err)
	assert.Equal(t, "us-east-1/my-cluster/workers/instanceTypeDetail/ml.g5.xlarge", id)
}

// ---- Notebook instance details null state tests ----

func TestNotebookInstanceDetailsNullSubnet(t *testing.T) {
	details := &mqlAwsSagemakerNotebookinstancedetails{}
	assert.Nil(t, details.cacheSubnetId)
}
