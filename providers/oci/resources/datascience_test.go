// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/datascience"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeModelDeploymentSummary runs a list-API record through the SDK's own
// polymorphic decoder, so the tests see the concrete configuration types the
// provider receives at runtime.
func decodeModelDeploymentSummary(t *testing.T, raw string) datascience.ModelDeploymentSummary {
	t.Helper()
	var md datascience.ModelDeploymentSummary
	require.NoError(t, json.Unmarshal([]byte(raw), &md))
	return md
}

func TestOciModelDeploymentNetwork(t *testing.T) {
	t.Run("single model with custom networking", func(t *testing.T) {
		// Synthetic: shape follows the Data Science API reference for a
		// SINGLE_MODEL deployment; no deployment exists in the test tenancy.
		md := decodeModelDeploymentSummary(t, `{
			"id": "ocid1.datasciencemodeldeployment.oc1.iad.md1",
			"modelDeploymentConfigurationDetails": {
				"deploymentType": "SINGLE_MODEL",
				"modelConfigurationDetails": {
					"modelId": "ocid1.datasciencemodel.oc1.iad.m1",
					"instanceConfiguration": {
						"instanceShapeName": "VM.Standard.E4.Flex",
						"subnetId": "ocid1.subnet.oc1.iad.s1",
						"privateEndpointId": "ocid1.datascienceprivateendpoint.oc1.iad.pe1",
						"networkAccessType": "CUSTOM_NETWORKING"
					}
				}
			}
		}`)
		got := ociModelDeploymentNetwork(md.ModelDeploymentConfigurationDetails)
		assert.Equal(t, ociModelDeploymentNetworkConfig{
			modelID:           "ocid1.datasciencemodel.oc1.iad.m1",
			subnetID:          "ocid1.subnet.oc1.iad.s1",
			privateEndpointID: "ocid1.datascienceprivateendpoint.oc1.iad.pe1",
			networkAccessType: "CUSTOM_NETWORKING",
		}, got)
	})

	t.Run("single model with managed internet egress", func(t *testing.T) {
		// Synthetic: managed networking carries no subnet or private endpoint.
		md := decodeModelDeploymentSummary(t, `{
			"modelDeploymentConfigurationDetails": {
				"deploymentType": "SINGLE_MODEL",
				"modelConfigurationDetails": {
					"modelId": "ocid1.datasciencemodel.oc1.iad.m1",
					"instanceConfiguration": {
						"instanceShapeName": "VM.Standard.E4.Flex",
						"networkAccessType": "MANAGED_NETWORKING_INTERNET_ACCESS"
					}
				}
			}
		}`)
		got := ociModelDeploymentNetwork(md.ModelDeploymentConfigurationDetails)
		assert.Equal(t, "ocid1.datasciencemodel.oc1.iad.m1", got.modelID)
		assert.Equal(t, "MANAGED_NETWORKING_INTERNET_ACCESS", got.networkAccessType)
		assert.Empty(t, got.subnetID)
		assert.Empty(t, got.privateEndpointID)
	})

	t.Run("model group on an instance pool", func(t *testing.T) {
		// Synthetic: a MODEL_GROUP deployment serves a model group, so no
		// catalog model is named; the network sits on the infrastructure.
		md := decodeModelDeploymentSummary(t, `{
			"modelDeploymentConfigurationDetails": {
				"deploymentType": "MODEL_GROUP",
				"modelGroupConfigurationDetails": {"modelGroupId": "ocid1.datasciencemodelgroup.oc1.iad.g1"},
				"infrastructureConfigurationDetails": {
					"infrastructureType": "INSTANCE_POOL",
					"instanceConfiguration": {
						"instanceShapeName": "VM.Standard.E4.Flex",
						"subnetId": "ocid1.subnet.oc1.iad.s2",
						"networkAccessType": "MANAGED_NETWORKING_NO_INTERNET_ACCESS"
					}
				}
			}
		}`)
		got := ociModelDeploymentNetwork(md.ModelDeploymentConfigurationDetails)
		assert.Empty(t, got.modelID)
		assert.Equal(t, "ocid1.subnet.oc1.iad.s2", got.subnetID)
		assert.Equal(t, "MANAGED_NETWORKING_NO_INTERNET_ACCESS", got.networkAccessType)
	})

	t.Run("flex deployment on a managed compute cluster", func(t *testing.T) {
		// Synthetic: the flex shape names its model but reports no instance network.
		md := decodeModelDeploymentSummary(t, `{
			"modelDeploymentConfigurationDetails": {
				"deploymentType": "SINGLE_MODEL_FLEX",
				"modelConfigurationDetails": {"modelId": "ocid1.datasciencemodel.oc1.iad.m3"},
				"infrastructureConfigurationDetails": {
					"infrastructureType": "MANAGED_COMPUTE_CLUSTER",
					"computeTargetId": "ocid1.computecluster.oc1.iad.c1",
					"modelDeploymentResourceConfiguration": {}
				}
			}
		}`)
		got := ociModelDeploymentNetwork(md.ModelDeploymentConfigurationDetails)
		assert.Equal(t, ociModelDeploymentNetworkConfig{modelID: "ocid1.datasciencemodel.oc1.iad.m3"}, got)
	})

	t.Run("pointer configuration", func(t *testing.T) {
		// Synthetic: a caller may hold the configuration by pointer.
		got := ociModelDeploymentNetwork(&datascience.SingleModelDeploymentConfigurationDetails{
			ModelConfigurationDetails: &datascience.ModelConfigurationDetails{
				ModelId: strPtr("ocid1.datasciencemodel.oc1.iad.m4"),
				InstanceConfiguration: &datascience.InstanceConfiguration{
					SubnetId: strPtr("ocid1.subnet.oc1.iad.s4"),
				},
			},
		})
		assert.Equal(t, "ocid1.datasciencemodel.oc1.iad.m4", got.modelID)
		assert.Equal(t, "ocid1.subnet.oc1.iad.s4", got.subnetID)
	})

	t.Run("absent configuration", func(t *testing.T) {
		// Synthetic: the summary omits the configuration entirely.
		md := decodeModelDeploymentSummary(t, `{"id": "ocid1.datasciencemodeldeployment.oc1.iad.md2"}`)
		assert.Equal(t, ociModelDeploymentNetworkConfig{}, ociModelDeploymentNetwork(md.ModelDeploymentConfigurationDetails))
		var nilPtr *datascience.SingleModelDeploymentConfigurationDetails
		assert.Equal(t, ociModelDeploymentNetworkConfig{}, ociModelDeploymentNetwork(nilPtr))
	})
}

func TestOciModelDeploymentLogs(t *testing.T) {
	t.Run("access and predict", func(t *testing.T) {
		// Synthetic: both log categories enabled, in different groups.
		md := decodeModelDeploymentSummary(t, `{
			"categoryLogDetails": {
				"access":  {"logId": "ocid1.log.oc1.iad.a", "logGroupId": "ocid1.loggroup.oc1.iad.ga"},
				"predict": {"logId": "ocid1.log.oc1.iad.p", "logGroupId": "ocid1.loggroup.oc1.iad.gp"}
			}
		}`)
		access, predict := ociModelDeploymentLogs(md.CategoryLogDetails)
		assert.Equal(t, ociLogRef{logGroupID: "ocid1.loggroup.oc1.iad.ga", logID: "ocid1.log.oc1.iad.a"}, access)
		assert.Equal(t, ociLogRef{logGroupID: "ocid1.loggroup.oc1.iad.gp", logID: "ocid1.log.oc1.iad.p"}, predict)
	})

	t.Run("predict only", func(t *testing.T) {
		// Synthetic: access logging off leaves its reference empty.
		md := decodeModelDeploymentSummary(t, `{
			"categoryLogDetails": {"predict": {"logId": "ocid1.log.oc1.iad.p", "logGroupId": "ocid1.loggroup.oc1.iad.gp"}}
		}`)
		access, predict := ociModelDeploymentLogs(md.CategoryLogDetails)
		assert.Equal(t, ociLogRef{}, access)
		assert.Equal(t, "ocid1.log.oc1.iad.p", predict.logID)
	})

	t.Run("no logging", func(t *testing.T) {
		// Synthetic: the summary carries no log details.
		access, predict := ociModelDeploymentLogs(nil)
		assert.Equal(t, ociLogRef{}, access)
		assert.Equal(t, ociLogRef{}, predict)
	})
}
