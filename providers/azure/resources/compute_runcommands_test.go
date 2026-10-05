// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// An instance view handed over by the list answers every execution field.
// The resource has no runtime, so reaching for the API would panic.
func TestRunCommandExecutionFromSeededInstanceView(t *testing.T) {
	start := time.Date(2026, 10, 5, 18, 38, 59, 0, time.UTC)
	end := start.Add(time.Second)
	rc := &mqlAzureSubscriptionComputeServiceVmRunCommand{}
	rc.cacheInstanceView = &compute.VirtualMachineRunCommandInstanceView{
		ExecutionState: to.Ptr(compute.ExecutionStateSucceeded),
		ExitCode:       to.Ptr[int32](0),
		StartTime:      &start,
		EndTime:        &end,
	}
	state, err := rc.executionState()
	require.NoError(t, err)
	assert.Equal(t, "Succeeded", state)
	code, err := rc.exitCode()
	require.NoError(t, err)
	assert.Equal(t, int64(0), code)
	assert.NotEqual(t, plugin.StateIsSet|plugin.StateIsNull, rc.ExitCode.State,
		"exit code 0 is a real result, not null")
	got, err := rc.endTime()
	require.NoError(t, err)
	assert.Equal(t, &end, got)
}

// The run command list returns no instance view, so without one the fields
// must come from a GET of the run command rather than read as null.
func TestRunCommandWithoutInstanceViewFetches(t *testing.T) {
	rc := &mqlAzureSubscriptionComputeServiceVmRunCommand{}
	assert.Panics(t, func() { _, _ = rc.executionState() },
		"with no runtime, a detail fetch panics; no panic means the empty list answer was used")
}
