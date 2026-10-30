// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestEc2InstanceIsDiscoverable pins which instance states become scan targets.
//
// A terminated instance stays visible to DescribeInstances for about an hour
// after it goes away, and it has no interfaces, volumes or SSM agent, so
// addConnectionInfoToEc2Asset gives it no connections and the scan reports it
// as an asset it could not connect to. Stopped instances must keep being
// discovered: they still hold their volumes and are reachable through EBS.
func TestEc2InstanceIsDiscoverable(t *testing.T) {
	cases := []struct {
		state string
		want  bool
	}{
		{string(types.InstanceStateNameRunning), true},
		{string(types.InstanceStateNamePending), true},
		{string(types.InstanceStateNameStopping), true},
		{string(types.InstanceStateNameStopped), true},
		{string(types.InstanceStateNameShuttingDown), false},
		{string(types.InstanceStateNameTerminated), false},
		// An unrecognized state errs toward discovering it: a state this code
		// has not seen is not evidence the instance is gone.
		{"some-future-state", true},
		{"", true},
	}

	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			assert.Equal(t, tc.want, ec2InstanceIsDiscoverable(tc.state))
		})
	}
}

// TestEc2InstanceIsDiscoverableAgreesWithStateMapping ties the two functions
// together: every state this drops must be one the state mapping already calls
// terminated, so the filter cannot drift from what the asset would report.
func TestEc2InstanceIsDiscoverableAgreesWithStateMapping(t *testing.T) {
	for _, state := range []string{
		string(types.InstanceStateNameRunning),
		string(types.InstanceStateNamePending),
		string(types.InstanceStateNameStopping),
		string(types.InstanceStateNameStopped),
		string(types.InstanceStateNameShuttingDown),
		string(types.InstanceStateNameTerminated),
	} {
		if !ec2InstanceIsDiscoverable(state) {
			assert.Equal(t, inventory.State_STATE_TERMINATED, mapEc2InstanceStateCode(state),
				"state %q is dropped from discovery but does not map to terminated", state)
		}
	}
}
