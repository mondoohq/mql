// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
)

// newMultiAssetTestRecording builds a recording with two assets, each reachable
// by its own connection id (1 and 2), mirroring how a multi-asset recording
// file is indexed when loaded from disk.
func newMultiAssetTestRecording(t *testing.T) llx.Recording {
	t.Helper()

	asset1 := &inventory.Asset{
		Name:        "asset1",
		Mrn:         "asset1-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset1"},
		Platform:    &inventory.Platform{Name: "debian"},
	}
	asset2 := &inventory.Asset{
		Name:        "asset2",
		Mrn:         "asset2-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset2"},
		Platform:    &inventory.Platform{Name: "debian"},
	}

	rec := recording.NewWithAsset(asset1)
	rec.EnsureAsset(asset1, "recording", 1, &inventory.Config{Type: "recording", Id: 1})
	rec.EnsureAsset(asset2, "recording", 2, &inventory.Config{Type: "recording", Id: 2})
	return rec
}

func storeUsersList(connID uint32, value string) *plugin.StoreReq {
	return &plugin.StoreReq{
		Connection: connID,
		Resources: []*plugin.ResourceData{{
			Name: "users",
			Id:   "qrid-derived-clone-id",
			Fields: map[string]*llx.Result{
				"list": {Data: llx.StringPrimitive(value)},
			},
		}},
	}
}

// primitiveString extracts a string from a primitive that round-tripped
// through the recording (string values come back as raw bytes).
func primitiveString(p *llx.Primitive) string {
	return string(p.Value)
}

func getUsersList(connID uint32) *plugin.DataReq {
	return &plugin.DataReq{
		Connection: connID,
		Resource:   "users",
		ResourceId: "qrid-derived-clone-id",
		Field:      "list",
	}
}

// TestRecordingProviderConnScopedRouting reproduces
// https://github.com/mondoohq/mql/issues/9461: a single static recording
// provider serves all assets of a multi-asset recording. When queries store
// computed data (e.g. `where` rewrap clones, whose resource id is derived from
// the query checksum and is therefore identical across assets), the provider
// must route GetData/StoreData by the request's connection. Routing by the
// shared selectedAsset instead makes one asset's data land in (or get read
// from) another asset's recording section.
func TestRecordingProviderConnScopedRouting(t *testing.T) {
	rec := newMultiAssetTestRecording(t)

	// Simulate the shared singleton after the scan framework connected asset2
	// last: selectedAsset points at asset2 while both assets are being scanned.
	asset2 := &inventory.Asset{
		Mrn:         "asset2-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset2"},
		Platform:    &inventory.Platform{Name: "debian"},
		Connections: []*inventory.Config{{Type: "recording", Id: 2}},
	}
	p := NewRecordingProvider(WithRecording(rec), WithAsset(asset2))

	// Both assets store a computed clone under the same (checksum-derived)
	// resource id, each tagged with its own connection.
	_, err := p.StoreData(storeUsersList(1, "asset1-list"))
	require.NoError(t, err)
	_, err = p.StoreData(storeUsersList(2, "asset2-list"))
	require.NoError(t, err)

	// Each connection must read back its own asset's data.
	res, err := p.GetData(getUsersList(1))
	require.NoError(t, err)
	assert.Equal(t, "asset1-list", primitiveString(res.Data))

	res, err = p.GetData(getUsersList(2))
	require.NoError(t, err)
	assert.Equal(t, "asset2-list", primitiveString(res.Data))

	// A lookup for data that was never stored under a connection must not be
	// served from another asset's section.
	_, err = p.GetData(&plugin.DataReq{
		Connection: 2,
		Resource:   "users",
		ResourceId: "only-stored-on-conn-1",
		Field:      "list",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doesn't exist")

	_, err = p.StoreData(&plugin.StoreReq{
		Connection: 1,
		Resources: []*plugin.ResourceData{{
			Name:   "users",
			Id:     "only-stored-on-conn-1",
			Fields: map[string]*llx.Result{"list": {Data: llx.StringPrimitive("x")}},
		}},
	})
	require.NoError(t, err)

	_, err = p.GetData(&plugin.DataReq{
		Connection: 2,
		Resource:   "users",
		ResourceId: "only-stored-on-conn-1",
		Field:      "list",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doesn't exist")
}

// TestRecordingProviderSelectedAssetFallback ensures the legacy programmatic
// flow (no connection set on requests) still resolves via the selected asset.
func TestRecordingProviderSelectedAssetFallback(t *testing.T) {
	rec := newMultiAssetTestRecording(t)

	asset1 := &inventory.Asset{
		Mrn:         "asset1-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset1"},
		Platform:    &inventory.Platform{Name: "debian"},
		Connections: []*inventory.Config{{Type: "recording", Id: 1}},
	}
	p := NewRecordingProvider(WithRecording(rec), WithAsset(asset1))

	_, err := p.StoreData(storeUsersList(0, "legacy-value"))
	require.NoError(t, err)

	res, err := p.GetData(getUsersList(0))
	require.NoError(t, err)
	assert.Equal(t, "legacy-value", primitiveString(res.Data))

	// The data must have landed in the selected asset's section (conn id 1),
	// and must not be visible from the other asset's connection.
	res, err = p.GetData(getUsersList(1))
	require.NoError(t, err)
	assert.Equal(t, "legacy-value", primitiveString(res.Data))

	_, err = p.GetData(getUsersList(2))
	require.Error(t, err)
}

// TestRecordingProviderStoreWithoutAsset keeps the existing error behavior for
// StoreData when neither a connection nor a selected asset is available.
func TestRecordingProviderStoreWithoutAsset(t *testing.T) {
	p := NewRecordingProvider(WithRecording(newMultiAssetTestRecording(t)))

	_, err := p.StoreData(storeUsersList(0, "x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no asset selected")
}

// TestRecordingProviderConnectAssignsUniqueConnectionIds covers the input shape
// of https://github.com/mondoohq/mql/issues/9461: a recording file may give
// every one of its assets the same connection id (1), and the recording indexes
// its sections by connection id, so duplicated ids collapse several assets onto
// a single section. Discovery therefore has to hand out a unique id per asset,
// and Connect has to report it back to the runtime, which sends it on every
// GetData/StoreData request.
func TestRecordingProviderConnectAssignsUniqueConnectionIds(t *testing.T) {
	asset1 := &inventory.Asset{
		Name:        "asset1",
		Mrn:         "asset1-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset1"},
		Platform:    &inventory.Platform{Name: "debian"},
		Connections: []*inventory.Config{{Type: "recording", Id: 1}},
	}
	asset2 := &inventory.Asset{
		Name:        "asset2",
		Mrn:         "asset2-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset2"},
		Platform:    &inventory.Platform{Name: "debian"},
		Connections: []*inventory.Config{{Type: "recording", Id: 1}},
	}

	rec := recording.NewWithAsset(asset1)
	rec.EnsureAsset(asset1, "recording", 1, asset1.Connections[0])
	rec.EnsureAsset(asset2, "recording", 1, asset2.Connections[0])

	p := NewRecordingProvider(WithRecording(rec))

	// Discovery pass: an asset without a platform makes the provider enumerate
	// the recording's assets.
	discovery, err := p.Connect(&plugin.ConnectReq{Asset: &inventory.Asset{
		Connections: []*inventory.Config{{Type: "recording"}},
	}}, nil)
	require.NoError(t, err)
	require.NotNil(t, discovery.Inventory)
	require.Zero(t, discovery.Id, "the discovery pass connects no asset")

	discovered := discovery.Inventory.Spec.Assets
	require.Len(t, discovered, 2)
	require.Len(t, discovered[0].Connections, 1)
	require.Len(t, discovered[1].Connections, 1)
	assert.True(t, discovered[0].Connections[0].DelayDiscovery)
	assert.True(t, discovered[1].Connections[0].DelayDiscovery)
	assert.NotZero(t, discovered[0].Connections[0].Id)
	assert.NotEqual(t, discovered[0].Connections[0].Id, discovered[1].Connections[0].Id,
		"each discovered asset needs its own connection id, even though the recording gave them both id 1")

	// Connecting a discovered asset keeps the id it was discovered with...
	discovered[0].Connections[0].DelayDiscovery = false
	res1, err := p.Connect(&plugin.ConnectReq{Asset: discovered[0]}, nil)
	require.NoError(t, err)
	assert.Equal(t, discovered[0].Connections[0].Id, res1.Id)

	// ...and an asset that arrives without one gets a fresh id.
	asset2Conn := &inventory.Asset{
		Mrn:         asset2.Mrn,
		PlatformIds: asset2.PlatformIds,
		Platform:    asset2.Platform,
		Connections: []*inventory.Config{{Type: "recording"}},
	}
	res2, err := p.Connect(&plugin.ConnectReq{Asset: asset2Conn}, nil)
	require.NoError(t, err)
	assert.NotZero(t, res2.Id)
	assert.Equal(t, asset2Conn.Connections[0].Id, res2.Id)
	require.NotEqual(t, res1.Id, res2.Id)

	// Each connection now resolves to its own asset's section. Storing the same
	// computed clone id on both — a `where` rewrap clone is keyed by the query
	// checksum, so its id is identical across assets — must not mix their data,
	// even though selectedAsset points at the asset that connected last.
	_, err = p.StoreData(storeUsersList(res1.Id, "asset1-list"))
	require.NoError(t, err)
	_, err = p.StoreData(storeUsersList(res2.Id, "asset2-list"))
	require.NoError(t, err)

	data, err := p.GetData(getUsersList(res1.Id))
	require.NoError(t, err)
	assert.Equal(t, "asset1-list", primitiveString(data.Data))

	data, err = p.GetData(getUsersList(res2.Id))
	require.NoError(t, err)
	assert.Equal(t, "asset2-list", primitiveString(data.Data))
}

// TestRecordingProviderConnectWithoutPlatformIdsReportsNoConnection: an asset
// that cannot be resolved in the recording (no mrn, no platform ids) must not
// get a connection id, so its requests keep falling back to selectedAsset
// instead of being routed to a section it was never bound to.
func TestRecordingProviderConnectWithoutPlatformIdsReportsNoConnection(t *testing.T) {
	p := NewRecordingProvider(WithRecording(newMultiAssetTestRecording(t)))

	res, err := p.Connect(&plugin.ConnectReq{Asset: &inventory.Asset{
		Name:     "asset-no-ids",
		Platform: &inventory.Platform{Name: "debian"},
		// DelayDiscovery keeps detect() from rejecting the asset outright.
		Connections: []*inventory.Config{{Type: "recording", DelayDiscovery: true}},
	}}, nil)
	require.NoError(t, err)
	assert.Zero(t, res.Id, "an asset with no mrn or platform ids cannot be bound to a recording section")
}

// TestRecordingProviderRoutesByAssetIdentity pins down what a request is routed
// by. A recording loaded from disk may reuse one connection id across several of
// its assets, and the recording indexes a section under EVERY connection id that
// section carries — so the asset indexed last owns a shared id. Routing by the
// id alone would then still serve one asset's data to another, no matter how
// carefully the ids are handed out; the provider routes by the connected asset's
// identity instead.
func TestRecordingProviderRoutesByAssetIdentity(t *testing.T) {
	asset1 := &inventory.Asset{
		Name:        "asset1",
		Mrn:         "asset1-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset1"},
		Platform:    &inventory.Platform{Name: "debian"},
	}
	asset2 := &inventory.Asset{
		Name:        "asset2",
		Mrn:         "asset2-mrn",
		PlatformIds: []string{"//platformid.api.mondoo.app/hostname/asset2"},
		Platform:    &inventory.Platform{Name: "debian"},
	}

	// Both assets carry connection id 1, as every asset of a synthesized
	// recording does.
	rec := recording.NewWithAsset(asset1)
	rec.EnsureAsset(asset1, "recording", 1, &inventory.Config{Type: "recording", Id: 1})
	rec.EnsureAsset(asset2, "recording", 1, &inventory.Config{Type: "recording", Id: 1})

	// asset2 claimed the shared id last, so the recording resolves it to asset2.
	rec.AddData(llx.AddDataReq{
		ConnectionID:      1,
		Resource:          "users",
		ResourceID:        "probe",
		Field:             "list",
		Data:              llx.StringData("routed-by-connection-id"),
		RequestResourceId: "probe",
	})
	_, ok := rec.GetData(llx.AssetRecordingLookup{Mrn: "asset2-mrn"}, "users", "probe", "list")
	require.True(t, ok, "the shared connection id is expected to resolve to asset2")

	connectAsset := func(asset *inventory.Asset, connID uint32) *inventory.Asset {
		return &inventory.Asset{
			Name:        asset.Name,
			Mrn:         asset.Mrn,
			PlatformIds: asset.PlatformIds,
			Platform:    asset.Platform,
			Connections: []*inventory.Config{{Type: "recording", Id: connID}},
		}
	}

	p := NewRecordingProvider(WithRecording(rec))
	res1, err := p.Connect(&plugin.ConnectReq{Asset: connectAsset(asset1, 1)}, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(1), res1.Id, "a preassigned connection id is kept")
	res2, err := p.Connect(&plugin.ConnectReq{Asset: connectAsset(asset2, 2)}, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(2), res2.Id)

	_, err = p.StoreData(storeUsersList(res1.Id, "asset1-list"))
	require.NoError(t, err)
	_, err = p.StoreData(storeUsersList(res2.Id, "asset2-list"))
	require.NoError(t, err)

	// Connection 1 must reach asset1 even though asset2 owns id 1 in the
	// recording's connection index.
	data, err := p.GetData(getUsersList(res1.Id))
	require.NoError(t, err)
	assert.Equal(t, "asset1-list", primitiveString(data.Data))

	data, err = p.GetData(getUsersList(res2.Id))
	require.NoError(t, err)
	assert.Equal(t, "asset2-list", primitiveString(data.Data))

	stored, ok := rec.GetData(llx.AssetRecordingLookup{Mrn: "asset1-mrn"}, "users", "qrid-derived-clone-id", "list")
	require.True(t, ok, "asset1's data must be stored in asset1's own section")
	assert.Equal(t, "asset1-list", stored.Value)
}
