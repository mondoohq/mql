// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iac/connection"
	"go.mondoo.com/mql/utils/syncx"
)

func testSetup(t *testing.T, detections []*connection.Detection) (*plugin.Service, uint32) {
	t.Helper()

	root := &inventory.Asset{
		Id:          "project",
		PlatformIds: []string{"//platform/project"},
		Connections: []*inventory.Config{{Type: connection.ConnectionType}},
	}

	service := plugin.NewService()
	var connID uint32
	runtime, err := service.AddRuntime(root.Connections[0], func(id uint32) (*plugin.Runtime, error) {
		connID = id
		conn := connection.NewIacConnection(id, root, connection.Source{
			Kind: connection.KindFile, Origin: "/repo",
		})
		conn.SetDetections(detections)
		rt := plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
		rt.Resources = &syncx.Map[plugin.Resource]{}
		return rt, nil
	})
	require.NoError(t, err)
	require.NoError(t, CreateDetectionResources(runtime, detections))
	return service, connID
}

func acceptedDetection(tool, path string) (*connection.Detection, *inventory.Asset) {
	child := &inventory.Asset{
		Name:        tool + " asset",
		PlatformIds: []string{"//platform/" + tool + "/" + path},
		Connections: []*inventory.Config{{Type: tool, Path: "/repo/" + path}},
	}
	root := &inventory.Asset{Id: "project", PlatformIds: []string{"//platform/project"}}
	return connection.NewDetection(tool, path, []string{path + "/main"}, child, connection.RootRef(root), nil), child
}

// TestResolveAssetMatchesTheInventoryAsset is the ADR 030 parity check: the
// asset a `detection.asset` read resolves to and the asset the inventory
// carried have to be one object, not two descriptions of one. Drift between
// them is a silent orphan -- an edge that never links to anything.
func TestResolveAssetMatchesTheInventoryAsset(t *testing.T) {
	terraform, tfAsset := acceptedDetection("terraform", "envs/prod")
	helm, helmAsset := acceptedDetection("helm", "charts/api")
	detections := []*connection.Detection{terraform, helm}

	service, connID := testSetup(t, detections)

	inventoryAssets := map[string]*inventory.Asset{
		terraform.AnchorID(): tfAsset,
		helm.AnchorID():      helmAsset,
	}

	for _, d := range detections {
		res, err := service.ResolveAsset(&plugin.ResolveAssetReq{
			Connection:   connID,
			ResourceType: connection.DetectionResourceType,
			ResourceId:   d.AnchorID(),
		})
		require.NoError(t, err)
		require.NotNil(t, res.Asset, "anchor %q resolved to nothing", d.AnchorID())

		want := inventoryAssets[d.AnchorID()]
		assert.Same(t, want, res.Asset)
		assert.Equal(t, want.PlatformIds, res.Asset.PlatformIds)

		// And the asset carries the reverse edge naming this same anchor, so
		// the join closes in both directions.
		require.Len(t, want.Relationships, 1)
		assert.Equal(t, connection.DetectionResourceType, want.Relationships[0].ResourceType)
		assert.Equal(t, d.AnchorID(), want.Relationships[0].ResourceId)
	}
}

func TestResolveAssetOfAFailedDetectionIsNull(t *testing.T) {
	failed := connection.NewDetection("helm", "broken", nil, nil, nil, errors.New("malformed chart"))
	service, connID := testSetup(t, []*connection.Detection{failed})

	res, err := service.ResolveAsset(&plugin.ResolveAssetReq{
		Connection:   connID,
		ResourceType: connection.DetectionResourceType,
		ResourceId:   failed.AnchorID(),
	})
	// An ordinary state -- the tool reported a failure, so there is nothing to
	// connect to -- and not an error.
	require.NoError(t, err)
	assert.Nil(t, res.Asset)
}

func TestResolveAssetOfAnUnknownAnchorIsEmpty(t *testing.T) {
	terraform, _ := acceptedDetection("terraform", "envs/prod")
	service, connID := testSetup(t, []*connection.Detection{terraform})

	res, err := service.ResolveAsset(&plugin.ResolveAssetReq{
		Connection:   connID,
		ResourceType: connection.DetectionResourceType,
		ResourceId:   connection.AnchorID("terraform", "envs/dev"),
	})
	require.NoError(t, err)
	assert.Nil(t, res.Asset)
}

// The detection resources exist before any query reads iac.detections, because
// Service.ResolveAsset answers from the resource cache and never creates one.
func TestDetectionResourcesExistBeforeAnyQuery(t *testing.T) {
	terraform, _ := acceptedDetection("terraform", "envs/prod")
	service, connID := testSetup(t, []*connection.Detection{terraform})

	runtime, err := service.GetRuntime(connID)
	require.NoError(t, err)

	resource, ok := runtime.Resources.Get(connection.DetectionResourceType + "\x00" + terraform.AnchorID())
	require.True(t, ok, "the detection resource was not created at connect")

	detection, ok := resource.(*mqlIacDetection)
	require.True(t, ok)
	assert.Equal(t, "terraform", detection.Tool.Data)
	assert.Equal(t, "envs/prod", detection.Path.Data)
}

func TestDetectionAssetValueCarriesTheAnchor(t *testing.T) {
	terraform, _ := acceptedDetection("terraform", "envs/prod")
	service, connID := testSetup(t, []*connection.Detection{terraform})
	runtime, err := service.GetRuntime(connID)
	require.NoError(t, err)

	resource, _ := runtime.Resources.Get(connection.DetectionResourceType + "\x00" + terraform.AnchorID())
	detection := resource.(*mqlIacDetection)

	value := detection.GetAsset()
	require.NoError(t, value.Error)
	require.NotNil(t, value.Data)
	// Identity and nothing else: this value persists into recordings and
	// upstream, and it is the key ResolveAsset is looked up by.
	assert.Equal(t, connection.DetectionResourceType, value.Data.ResourceType)
	assert.Equal(t, terraform.AnchorID(), value.Data.ResourceId)
}

func TestFailedDetectionAssetIsNullNotMissing(t *testing.T) {
	failed := connection.NewDetection("helm", "broken", nil, nil, nil, errors.New("malformed chart"))
	service, connID := testSetup(t, []*connection.Detection{failed})
	runtime, err := service.GetRuntime(connID)
	require.NoError(t, err)

	resource, _ := runtime.Resources.Get(connection.DetectionResourceType + "\x00" + failed.AnchorID())
	detection := resource.(*mqlIacDetection)

	value := detection.GetAsset()
	require.NoError(t, value.Error)
	assert.Nil(t, value.Data)
	// Without the explicit null state the runtime does not know the field
	// resolved, and the read is reported as a provider that returned neither
	// data nor an error.
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, value.State)
}
