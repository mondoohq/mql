// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	rds_types "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestEksControlPlaneLogging(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	t.Run("nil logging", func(t *testing.T) {
		// A cluster whose describe response omits logging must produce an empty
		// map, not a nil one: a nil map read as a field would report every log
		// type as absent rather than as unreported.
		assert.Equal(t, map[string]any{}, eksControlPlaneLogging(nil))
	})

	t.Run("splits one LogSetup per enablement state", func(t *testing.T) {
		// This is the shape EKS actually returns: one entry listing the enabled
		// types and one listing the disabled ones. Flattening only the first
		// entry, or reading Enabled off the wrong level, is what this pins.
		got := eksControlPlaneLogging(&ekstypes.Logging{
			ClusterLogging: []ekstypes.LogSetup{
				{Enabled: boolPtr(true), Types: []ekstypes.LogType{ekstypes.LogTypeAudit, ekstypes.LogTypeAuthenticator}},
				{Enabled: boolPtr(false), Types: []ekstypes.LogType{ekstypes.LogTypeApi, ekstypes.LogTypeScheduler}},
			},
		})
		assert.Equal(t, map[string]any{
			"audit":         true,
			"authenticator": true,
			"api":           false,
			"scheduler":     false,
		}, got)
	})

	t.Run("nil Enabled reads as disabled", func(t *testing.T) {
		got := eksControlPlaneLogging(&ekstypes.Logging{
			ClusterLogging: []ekstypes.LogSetup{
				{Types: []ekstypes.LogType{ekstypes.LogTypeAudit}},
			},
		})
		assert.Equal(t, map[string]any{"audit": false}, got)
	})

	t.Run("an enabled entry wins over a conflicting disabled one", func(t *testing.T) {
		// EKS does not return a type twice, but if it ever did, the enabled
		// reading is the one a check can go on and verify.
		got := eksControlPlaneLogging(&ekstypes.Logging{
			ClusterLogging: []ekstypes.LogSetup{
				{Enabled: boolPtr(true), Types: []ekstypes.LogType{ekstypes.LogTypeAudit}},
				{Enabled: boolPtr(false), Types: []ekstypes.LogType{ekstypes.LogTypeAudit}},
			},
		})
		assert.Equal(t, map[string]any{"audit": true}, got)
	})
}

func TestRdsSnapshotAttributeMap(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	splitInstance := func(a rds_types.DBSnapshotAttribute) (*string, []string) {
		return a.AttributeName, a.AttributeValues
	}
	splitCluster := func(a rds_types.DBClusterSnapshotAttribute) (*string, []string) {
		return a.AttributeName, a.AttributeValues
	}

	t.Run("no attributes", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, rdsSnapshotAttributeMap(nil, splitInstance))
	})

	t.Run("instance snapshot shared with named accounts", func(t *testing.T) {
		got := rdsSnapshotAttributeMap([]rds_types.DBSnapshotAttribute{
			{AttributeName: strPtr("restore"), AttributeValues: []string{"111111111111", "222222222222"}},
		}, splitInstance)
		assert.Equal(t, map[string]any{"restore": []any{"111111111111", "222222222222"}}, got)
	})

	t.Run("cluster snapshot shared with everyone", func(t *testing.T) {
		// "all" in the restore attribute is what makes a snapshot public, and
		// the cluster branch reads a different SDK type than the instance one.
		got := rdsSnapshotAttributeMap([]rds_types.DBClusterSnapshotAttribute{
			{AttributeName: strPtr("restore"), AttributeValues: []string{"all"}},
		}, splitCluster)
		assert.Equal(t, map[string]any{"restore": []any{"all"}}, got)
	})

	t.Run("an attribute with no values keeps an empty list", func(t *testing.T) {
		// An unshared snapshot returns the restore attribute with no values.
		// Dropping it would make "restore" absent, which reads as unknown
		// rather than as shared with nobody.
		got := rdsSnapshotAttributeMap([]rds_types.DBSnapshotAttribute{
			{AttributeName: strPtr("restore")},
		}, splitInstance)
		assert.Equal(t, map[string]any{"restore": []any{}}, got)
	})

	t.Run("a nameless attribute is dropped", func(t *testing.T) {
		got := rdsSnapshotAttributeMap([]rds_types.DBSnapshotAttribute{
			{AttributeValues: []string{"all"}},
			{AttributeName: strPtr("restore"), AttributeValues: []string{"all"}},
		}, splitInstance)
		assert.Equal(t, map[string]any{"restore": []any{"all"}}, got)
	})
}

func TestEksNodeCount(t *testing.T) {
	int32Ptr := func(i int32) *int32 { return &i }

	t.Run("an unreported count stays null", func(t *testing.T) {
		// Reading a missing count as 0 would say the node group runs no
		// nodes, which is a real and very different state from "EKS did not
		// report a count".
		assert.Equal(t, llx.NilData, eksNodeCount(nil))
	})

	t.Run("a reported count keeps its value", func(t *testing.T) {
		got := eksNodeCount(int32Ptr(3))
		require.NotNil(t, got)
		assert.Equal(t, int64(3), got.Value)
	})

	t.Run("a reported zero is a value, not a null", func(t *testing.T) {
		// A node group scaled to zero reports 0, and that has to read as 0
		// rather than collapsing into the unreported case.
		got := eksNodeCount(int32Ptr(0))
		require.NotNil(t, got)
		assert.Equal(t, int64(0), got.Value)
		assert.NotEqual(t, llx.NilData, got)
	})
}
