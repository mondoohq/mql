// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"net/http"
	"testing"

	"github.com/IBM-Cloud/power-go-client/power/client/p_cloud_p_vm_instances"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterRegions(t *testing.T) {
	name := func(s string) *string { return &s }
	all := []vpcv1.Region{{Name: name("us-south")}, {Name: name("eu-de")}}

	got, err := filterRegions(all, nil)
	require.NoError(t, err)
	assert.Equal(t, all, got)

	got, err = filterRegions(all, []string{"eu-de"})
	require.NoError(t, err)
	assert.Equal(t, []vpcv1.Region{{Name: name("eu-de")}}, got)

	_, err = filterRegions(all, []string{"xx-nowhere"})
	assert.ErrorContains(t, err, `unknown IBM Cloud VPC region "xx-nowhere"`)
}

// The Power client's errors are go-swagger response types, a runtime.APIError
// for unmodeled statuses, and a plain "Rate Limited" error for 429; all must
// still yield their status.
func TestStatusCodePowerErrors(t *testing.T) {
	forbidden := fmt.Errorf("failed to Get all PVM Instances: %w", p_cloud_p_vm_instances.NewPcloudPvminstancesGetallForbidden())
	assert.Equal(t, http.StatusForbidden, StatusCode(forbidden))

	unmodeled := fmt.Errorf("wrapped: %w", runtime.NewAPIError("unknown", nil, http.StatusTeapot))
	assert.Equal(t, http.StatusTeapot, StatusCode(unmodeled))

	assert.Equal(t, http.StatusTooManyRequests, StatusCode(errors.New("error: Rate Limited. Please try again later")))
	assert.Equal(t, 0, StatusCode(errors.New("dial tcp: connection refused")))
	assert.Equal(t, 0, StatusCode(nil))
}

func TestStatusCodeCosErrors(t *testing.T) {
	denied := awserr.NewRequestFailure(awserr.New("AccessDenied", "Access Denied", nil), 403, "req-1")
	assert.Equal(t, 403, StatusCode(denied))
	assert.Equal(t, 0, StatusCode(awserr.New("RequestError", "send request failed", nil)), "a transport failure carries no status")
}

func TestDatabasesEndpoint(t *testing.T) {
	assert.Equal(t, "https://api.eu-de.databases.cloud.ibm.com/v5/ibm", DatabasesEndpoint("eu-de"))
}

func TestCosEndpoint(t *testing.T) {
	assert.Equal(t, "https://s3.us-south.cloud-object-storage.appdomain.cloud", CosEndpoint("us-south"))
	assert.Equal(t, "https://s3.ams03.cloud-object-storage.appdomain.cloud", CosEndpoint("ams03"))
}
