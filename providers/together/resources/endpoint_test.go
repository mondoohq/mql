// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/llx"
)

func TestEndpointTypeName(t *testing.T) {
	// Synthetic: the documented EndpointType values, plus an unknown one.
	cases := map[string]string{
		"ENDPOINT_TYPE_DEDICATED":  "dedicated",
		"ENDPOINT_TYPE_SERVERLESS": "serverless",
		"ENDPOINT_TYPE_RESERVED":   "reserved",
		"ENDPOINT_TYPE_SPOT":       "spot",
		"":                         "",
	}
	for in, want := range cases {
		assert.Equal(t, want, endpointTypeName(in), in)
	}
}

func TestEndpointArgsDecodeTheV2Endpoint(t *testing.T) {
	// Synthetic: shaped like the documented v2 endpoint; the values are invented.
	var e together.Endpoint
	require.NoError(t, json.Unmarshal([]byte(`{
	  "id": "endpoint-0000",
	  "name": "example-project/example-endpoint",
	  "projectId": "proj-2222222222222222",
	  "endpointType": "ENDPOINT_TYPE_DEDICATED",
	  "visibility": "VISIBILITY_INTERNAL",
	  "createdAt": "2026-10-01T12:00:00Z",
	  "updatedAt": "2026-10-02T12:00:00Z",
	  "deployments": [],
	  "trafficSplit": [],
	  "etag": "e1"
	}`), &e))

	args := endpointArgs(e)
	assert.Equal(t, "endpoint-0000", args["id"].Value)
	assert.Equal(t, "example-project/example-endpoint", args["name"].Value)
	assert.Equal(t, "dedicated", args["type"].Value)
	assert.Equal(t, "VISIBILITY_INTERNAL", args["visibility"].Value)
	assert.Equal(t, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), *args["updatedAt"].Value.(*time.Time))

	for _, deprecated := range []string{"model", "state", "owner"} {
		assert.Nil(t, args[deprecated].Value, "%s has no source in the v2 endpoint and must be null, not empty", deprecated)
	}
}

func decodeDeployment(t *testing.T, body string) together.EndpointDeployment {
	t.Helper()
	var d together.EndpointDeployment
	require.NoError(t, json.Unmarshal([]byte(body), &d))
	return d
}

func TestDeploymentPlacementInlineHipaa(t *testing.T) {
	// Synthetic: an inline placement restricted to HIPAA-attested clusters.
	d := decodeDeployment(t, `{"id": "dep-1", "placement": {"inline": {
	  "compliancePolicy": {"hipaa": true},
	  "constraint": "ENFORCEMENT_REQUIRED",
	  "regions": ["us-east-1", "us-west-2"]
	}}}`)

	p := deploymentPlacementOf(d.Placement)
	require.NotNil(t, p.hipaa)
	assert.True(t, *p.hipaa)
	assert.Nil(t, p.profile)
	assert.Equal(t, []any{"us-east-1", "us-west-2"}, p.regions)
}

func TestDeploymentPlacementInlineWithoutCompliancePolicy(t *testing.T) {
	// Synthetic: the API omits false values, so a missing policy is no restriction.
	d := decodeDeployment(t, `{"id": "dep-1", "placement": {"inline": {"regions": ["eu-central-1"]}}}`)

	p := deploymentPlacementOf(d.Placement)
	require.NotNil(t, p.hipaa)
	assert.False(t, *p.hipaa)
	assert.Equal(t, []any{"eu-central-1"}, p.regions)
}

func TestDeploymentPlacementAbsent(t *testing.T) {
	// Synthetic: a deployment with no placement at all.
	d := decodeDeployment(t, `{"id": "dep-1"}`)

	p := deploymentPlacementOf(d.Placement)
	require.NotNil(t, p.hipaa)
	assert.False(t, *p.hipaa)
	assert.Nil(t, p.profile)
	assert.Empty(t, p.regions)
	assert.NotNil(t, p.regions, "no region restriction is an empty list, not an unknown")
}

func TestDeploymentPlacementProfileLeavesComplianceUnknown(t *testing.T) {
	// Synthetic: a saved placement profile carries its policy outside the deployment.
	d := decodeDeployment(t, `{"id": "dep-1", "placement": {"profile": "pp-0000"}}`)

	p := deploymentPlacementOf(d.Placement)
	assert.Nil(t, p.hipaa, "a profile placement must not read as a measured false")
	require.NotNil(t, p.profile)
	assert.Equal(t, "pp-0000", *p.profile)
	assert.Nil(t, p.regions)
}

func TestEndpointDeploymentArgs(t *testing.T) {
	// Synthetic: shaped like the documented deployment; the values are invented.
	d := decodeDeployment(t, `{
	  "id": "dep-1",
	  "name": "example-project/example-endpoint/blue",
	  "model": "projects/proj-x/models/m-1/revisions/r-1",
	  "status": {"state": "DEPLOYMENT_STATE_READY", "message": "serving", "readyReplicas": 2},
	  "trafficMode": "TRAFFIC_MODE_LIVE",
	  "hardware": "2x_nvidia_h100_80gb_sxm",
	  "desiredReplicas": 3,
	  "inactiveTimeout": 30,
	  "placement": {"profile": "pp-0000"}
	}`)

	args := endpointDeploymentArgs(d)
	assert.Equal(t, "DEPLOYMENT_STATE_READY", args["state"].Value)
	assert.Equal(t, "serving", args["statusMessage"].Value)
	assert.Equal(t, int64(2), args["readyReplicas"].Value)
	assert.Equal(t, int64(3), args["desiredReplicas"].Value)
	assert.Equal(t, int64(30), args["inactiveTimeout"].Value)
	assert.Equal(t, "TRAFFIC_MODE_LIVE", args["trafficMode"].Value)
	assert.Equal(t, "projects/proj-x/models/m-1/revisions/r-1", args["model"].Value)
	assert.Equal(t, "pp-0000", args["placementProfile"].Value)
	assert.Equal(t, llx.NilData, args["placementRegions"])
	assert.Nil(t, args["hipaaRequired"].Value)
}
