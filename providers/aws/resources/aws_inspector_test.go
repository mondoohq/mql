// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func coverageRow(accountID, region, resourceID, scanType string) *mqlAwsInspectorCoverage {
	c := &mqlAwsInspectorCoverage{}
	c.AccountId = plugin.TValue[string]{Data: accountID, State: plugin.StateIsSet}
	c.Region = plugin.TValue[string]{Data: region, State: plugin.StateIsSet}
	c.ResourceId = plugin.TValue[string]{Data: resourceID, State: plugin.StateIsSet}
	c.ScanType = plugin.TValue[string]{Data: scanType, State: plugin.StateIsSet}
	return c
}

// TestInspectorCoverageID pins that a coverage row is identified by its scan
// type and region as well as the resource. Inspector reports a resource once
// per scan type, so an instance covered by both PACKAGE and NETWORK produces
// two rows that differ only in scanType; without it the second row resolved to
// the first and became invisible.
func TestInspectorCoverageID(t *testing.T) {
	const (
		account  = "000000000000"
		region   = "us-east-1"
		instance = "i-0123456789abcdef0"
	)

	t.Run("scan types do not collide", func(t *testing.T) {
		pkg, err := coverageRow(account, region, instance, "PACKAGE").id()
		require.NoError(t, err)
		network, err := coverageRow(account, region, instance, "NETWORK").id()
		require.NoError(t, err)
		assert.NotEqual(t, pkg, network)
	})

	t.Run("regions do not collide", func(t *testing.T) {
		// An ECR repository name is only unique within a region, so two regions
		// can legitimately report the same resource id.
		east, err := coverageRow(account, "us-east-1", "my-repo", "PACKAGE").id()
		require.NoError(t, err)
		west, err := coverageRow(account, "us-west-2", "my-repo", "PACKAGE").id()
		require.NoError(t, err)
		assert.NotEqual(t, east, west)
	})

	t.Run("accounts do not collide", func(t *testing.T) {
		first, err := coverageRow("000000000000", region, instance, "PACKAGE").id()
		require.NoError(t, err)
		second, err := coverageRow("111111111111", region, instance, "PACKAGE").id()
		require.NoError(t, err)
		assert.NotEqual(t, first, second)
	})

	t.Run("the same row keys the same", func(t *testing.T) {
		first, err := coverageRow(account, region, instance, "PACKAGE").id()
		require.NoError(t, err)
		second, err := coverageRow(account, region, instance, "PACKAGE").id()
		require.NoError(t, err)
		assert.Equal(t, first, second)
	})
}

// TestInspectorCoverageChildIDsAreNotTagDerived pins that the one-to-one child
// resources are no longer identified by their tag map. That key was neither
// unique — two instances tagged alike produced the same string — nor stable,
// since Go randomizes map iteration, so the same instance could key differently
// between two runs of the same scan.
func TestInspectorCoverageChildIDsAreNotTagDerived(t *testing.T) {
	tags := map[string]any{"Name": "web", "env": "prod", "team": "platform", "app": "api"}

	t.Run("instance id is stable across iterations", func(t *testing.T) {
		inst := &mqlAwsInspectorCoverageInstance{}
		inst.Region = plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet}
		inst.Tags = plugin.TValue[map[string]any]{Data: tags, State: plugin.StateIsSet}

		first, err := inst.id()
		require.NoError(t, err)
		for range 50 {
			again, err := inst.id()
			require.NoError(t, err)
			assert.Equal(t, first, again, "the id must not depend on map iteration order")
		}
	})

	t.Run("image id is stable across iterations", func(t *testing.T) {
		img := &mqlAwsInspectorCoverageImage{}
		img.Region = plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet}
		img.Tags = plugin.TValue[map[string]any]{Data: tags, State: plugin.StateIsSet}

		first, err := img.id()
		require.NoError(t, err)
		for range 50 {
			again, err := img.id()
			require.NoError(t, err)
			assert.Equal(t, first, again)
		}
	})
}
