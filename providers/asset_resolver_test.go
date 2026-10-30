// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.uber.org/mock/gomock"
)

// The runtime is what llx dereferences a typed asset reference through.
var _ llx.AssetResolver = (*Runtime)(nil)

// multiAssetRecording is a recording that holds several assets and nothing
// else. Resolution only reads the asset list off it.
type multiAssetRecording struct {
	recording.Null
	assets []*recording.Asset
}

func (m *multiAssetRecording) GetAssetRecordings() []*recording.Asset     { return m.assets }
func (m *multiAssetRecording) SetAssetRecording(uint32, *recording.Asset) {}

func recordedAsset(name string, rels ...*inventory.AssetRelationship) *recording.Asset {
	return &recording.Asset{Asset: &inventory.Asset{
		Name:          name,
		PlatformIds:   []string{"//platformid/" + name},
		Relationships: rels,
	}}
}

func anchoredOn(parent *inventory.Asset, resourceType, resourceID string) *inventory.AssetRelationship {
	return &inventory.AssetRelationship{
		Asset:        parent,
		ResourceType: resourceType,
		ResourceId:   resourceID,
	}
}

func runtimeWith(self *inventory.Asset, assets ...*recording.Asset) *Runtime {
	return &Runtime{
		recording: &multiAssetRecording{assets: assets},
		Provider: &ConnectedProvider{
			Connection: &plugin.ConnectRes{Asset: self},
		},
	}
}

func TestRecordedTargetForAnchor(t *testing.T) {
	host := &inventory.Asset{Name: "host", PlatformIds: []string{"//platformid/host"}}
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "claude.code.mcpServer/github"}

	t.Run("found through the reverse edge", func(t *testing.T) {
		r := runtimeWith(host,
			recordedAsset("other"),
			recordedAsset("mcp-github", anchoredOn(host, anchor.ResourceType, anchor.ResourceId)),
		)

		target, err := r.recordedTargetForAnchor(anchor)
		require.NoError(t, err)
		require.NotNil(t, target)
		assert.Equal(t, "mcp-github", target.Name)
		assert.Equal(t, []string{"//platformid/mcp-github"}, target.PlatformIds)
		// A mock connection is what makes this the recorded leg; the live leg
		// carries the target's real connection instead.
		require.Len(t, target.Connections, 1)
		assert.Equal(t, "mock", target.Connections[0].Type)
	})

	// Nothing recorded is not an error - it is every live scan. It hands over
	// to the provider instead, so this has to be a miss rather than a failure.
	t.Run("a different anchor on the same asset is a miss", func(t *testing.T) {
		r := runtimeWith(host,
			recordedAsset("mcp-github", anchoredOn(host, anchor.ResourceType, "claude.code.mcpServer/other")),
		)

		target, err := r.recordedTargetForAnchor(anchor)
		require.NoError(t, err)
		assert.Nil(t, target)
	})

	t.Run("no multi-asset recording is a miss", func(t *testing.T) {
		r := &Runtime{recording: recording.Null{}}
		target, err := r.recordedTargetForAnchor(anchor)
		require.NoError(t, err)
		assert.Nil(t, target)
	})

	// An anchor id is only unique within one parent, so a recording holding two
	// hosts can carry the same anchor twice. The edge naming *this* asset wins.
	t.Run("disambiguated by which asset is named as the parent", func(t *testing.T) {
		otherHost := &inventory.Asset{Name: "other-host", PlatformIds: []string{"//platformid/other-host"}}
		r := runtimeWith(host,
			recordedAsset("mcp-elsewhere", anchoredOn(otherHost, anchor.ResourceType, anchor.ResourceId)),
			recordedAsset("mcp-here", anchoredOn(host, anchor.ResourceType, anchor.ResourceId)),
		)

		target, err := r.recordedTargetForAnchor(anchor)
		require.NoError(t, err)
		require.NotNil(t, target)
		assert.Equal(t, "mcp-here", target.Name)
	})

	// Ambiguity is an error rather than a fall-through to a live connect: the
	// recording does hold the answer, we just cannot tell which, and guessing
	// would connect the wrong asset.
	t.Run("ambiguous is an error, not a guess and not a miss", func(t *testing.T) {
		hostA := &inventory.Asset{Name: "a", PlatformIds: []string{"//platformid/a"}}
		hostB := &inventory.Asset{Name: "b", PlatformIds: []string{"//platformid/b"}}
		r := runtimeWith(host,
			recordedAsset("mcp-a", anchoredOn(hostA, anchor.ResourceType, anchor.ResourceId)),
			recordedAsset("mcp-b", anchoredOn(hostB, anchor.ResourceType, anchor.ResourceId)),
		)

		_, err := r.recordedTargetForAnchor(anchor)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "several recorded assets are anchored on it")
	})
}

// liveRuntime builds a runtime whose anchor resource is owned by a mocked
// provider, so the ResolveAsset round trip can be exercised without a plugin.
func liveRuntime(t *testing.T, resourceType string) (*Runtime, *MockProviderPlugin) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)
	mockPlugin := NewMockProviderPlugin(ctrl)

	const providerID = "go.mondoo.com/mql/providers/os"
	connected := &ConnectedProvider{
		Instance:   &RunningProvider{ID: providerID, Name: "os", Plugin: mockPlugin},
		Connection: &plugin.ConnectRes{Id: 7},
	}
	r := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		Provider:    connected,
		providers:   map[string]*ConnectedProvider{providerID: connected},
	}

	mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
	mockSchema.EXPECT().Lookup(resourceType).AnyTimes().Return(&resources.ResourceInfo{
		Id: resourceType, Name: resourceType, Provider: providerID,
	})
	return r, mockPlugin
}

// The value carries only the anchor, so reaching the asset means asking the
// provider that owns the resource. This is the half of resolution that cannot
// come from the value (ADR 030/031).
func TestLiveTargetForAnchor(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "claude.code.mcpServer/github"}

	t.Run("asks the owning provider and passes its connection", func(t *testing.T) {
		r, mockPlugin := liveRuntime(t, anchor.ResourceType)

		mockPlugin.EXPECT().ResolveAsset(gomock.Any()).Times(1).
			DoAndReturn(func(req *plugin.ResolveAssetReq) (*plugin.ResolveAssetRes, error) {
				// The provider is asked on the connection it is connected on,
				// for the exact anchor the value carried.
				assert.Equal(t, uint32(7), req.Connection)
				assert.Equal(t, anchor.ResourceType, req.ResourceType)
				assert.Equal(t, anchor.ResourceId, req.ResourceId)
				return &plugin.ResolveAssetRes{Asset: &inventory.Asset{
					Name:        "github-mcp",
					Connections: []*inventory.Config{{Type: "mcp"}},
				}}, nil
			})

		target, err := r.liveTargetForAnchor(anchor)
		require.NoError(t, err)
		assert.Equal(t, "github-mcp", target.Name)
		require.Len(t, target.Connections, 1)
		assert.Equal(t, "mcp", target.Connections[0].Type, "the target's own connection, not a mock one")
	})

	// Most resources are not assets. Answering nothing is the normal case and
	// has to read as "there is nothing here", not as a failure to reach it.
	t.Run("a resource that is not an asset source", func(t *testing.T) {
		r, mockPlugin := liveRuntime(t, anchor.ResourceType)
		mockPlugin.EXPECT().ResolveAsset(gomock.Any()).Times(1).
			Return(&plugin.ResolveAssetRes{}, nil)

		_, err := r.liveTargetForAnchor(anchor)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no asset to connect to")
	})

	// An asset with no connection cannot be connected to. Catching it here says
	// which provider produced it; letting it through fails later with nothing
	// to attribute it to.
	t.Run("an asset with no connection", func(t *testing.T) {
		r, mockPlugin := liveRuntime(t, anchor.ResourceType)
		mockPlugin.EXPECT().ResolveAsset(gomock.Any()).Times(1).
			Return(&plugin.ResolveAssetRes{Asset: &inventory.Asset{Name: "github-mcp"}}, nil)

		_, err := r.liveTargetForAnchor(anchor)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no connection")
	})
}

// Recording first: a replayed asset answers from what was recorded rather than
// reconnecting to something that may no longer exist.
func TestTargetAssetPrefersTheRecording(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "claude.code.mcpServer/github"}
	host := &inventory.Asset{Name: "host", PlatformIds: []string{"//platformid/host"}}

	r, mockPlugin := liveRuntime(t, anchor.ResourceType)
	r.recording = &multiAssetRecording{assets: []*recording.Asset{
		recordedAsset("mcp-github", anchoredOn(host, anchor.ResourceType, anchor.ResourceId)),
	}}
	r.Provider.Connection.Asset = host
	// Never asked: the recording answered.
	mockPlugin.EXPECT().ResolveAsset(gomock.Any()).Times(0)

	target, err := r.targetAssetForAnchor(anchor)
	require.NoError(t, err)
	assert.Equal(t, "mock", target.Connections[0].Type)
}

// A per-runtime cache cannot see an A -> B -> A cycle, because each hop is a
// genuine miss on a different runtime. The depth guard is what bounds it, and
// the chain is in the error so the cycle is readable.
func TestAssetResolveDepthGuard(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "some.server", ResourceId: "some.server/x"}

	r := runtimeWith(&inventory.Asset{Name: "host"})
	r.resolveChain = []string{"a", "b", "c", "d", "e"}

	_, err := r.runtimeForAnchor(anchor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nested too deeply")
	assert.Contains(t, err.Error(), "a -> b -> c -> d -> e -> some.server (some.server/x)")
}

func TestResolveAssetRootRejectsEmptyInput(t *testing.T) {
	r := runtimeWith(&inventory.Asset{Name: "host"})

	_, err := r.ResolveAssetRoot(nil, "mcp")
	assert.ErrorContains(t, err, "empty asset reference")

	_, err = r.ResolveAssetRoot(&llx.AssetValue{ResourceType: "x", ResourceId: "y"}, "")
	assert.ErrorContains(t, err, "no root resource requested")
}

func TestSameAsset(t *testing.T) {
	assert.True(t, sameAsset(
		&inventory.Asset{Mrn: "//a"}, &inventory.Asset{Mrn: "//a"}))
	assert.True(t, sameAsset(
		&inventory.Asset{PlatformIds: []string{"p1", "p2"}}, &inventory.Asset{PlatformIds: []string{"p2"}}))
	assert.False(t, sameAsset(
		&inventory.Asset{Mrn: "//a"}, &inventory.Asset{Mrn: "//b"}))

	// Two assets that both carry real identifiers and do not match are not the
	// same asset, however their display names read.
	assert.False(t, sameAsset(
		&inventory.Asset{Mrn: "//a", Name: "host"}, &inventory.Asset{Mrn: "//b", Name: "host"}))

	// A stub with neither falls back to the name, which is all it has.
	assert.True(t, sameAsset(&inventory.Asset{Name: "host"}, &inventory.Asset{Name: "host"}))
	assert.False(t, sameAsset(&inventory.Asset{Name: "host"}, &inventory.Asset{Name: "other"}))
	assert.False(t, sameAsset(&inventory.Asset{}, &inventory.Asset{}))
	assert.False(t, sameAsset(nil, &inventory.Asset{Name: "host"}))
}

func TestAnchorLabel(t *testing.T) {
	assert.Equal(t, "a.b (a.b/1)", anchorLabel(&llx.AssetValue{ResourceType: "a.b", ResourceId: "a.b/1"}))
	assert.Equal(t, "a.b", anchorLabel(&llx.AssetValue{ResourceType: "a.b"}))
	assert.Equal(t, "<none>", anchorLabel(nil))
}

// The full host-side path: reverse edge -> a runtime for the target -> its root
// resource, pinned to the runtime that answers it. The coordinator is mocked so
// this stays a unit test; connecting a real recorded asset through the mock
// provider is exercised by the integration suite.
func TestResolveAssetRootBindsToTheTargetRuntime(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockSchema := NewMockResourcesSchema(ctrl)

	host := &inventory.Asset{Name: "host", PlatformIds: []string{"//platformid/host"}}
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "claude.code.mcpServer/github"}

	r := runtimeWith(host, recordedAsset("mcp-github", anchoredOn(host, anchor.ResourceType, anchor.ResourceId)))
	r.coordinator = mockC

	// The sub-runtime arrives already connected, which is what RuntimeFor does
	// when the target deduped onto a runtime the coordinator already had.
	sub := &Runtime{
		coordinator: mockC,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance:   &RunningProvider{ID: "os", Name: "os"},
			Connection: &plugin.ConnectRes{Asset: &inventory.Asset{Name: "mcp-github"}},
		},
	}

	var connectedTo *inventory.Asset
	mockC.EXPECT().RuntimeFor(gomock.Any(), r).Times(1).
		DoAndReturn(func(asset *inventory.Asset, parent *Runtime) (*Runtime, error) {
			connectedTo = asset
			return sub, nil
		})
	// CreateResource resolves the root through the sub-runtime's schema. A
	// resource with no provider is a bridging resource, which needs no
	// connection - enough to prove the routing without starting a plugin.
	mockC.EXPECT().Schema().AnyTimes().Return(mockSchema)
	mockSchema.EXPECT().Lookup("mcp").AnyTimes().Return(&resources.ResourceInfo{
		Id: "mcp", Name: "mcp",
	})

	resource, err := r.ResolveAssetRoot(anchor, "mcp")
	require.NoError(t, err)
	require.NotNil(t, resource)

	assert.Equal(t, "mcp-github", connectedTo.Name, "resolved the asset named by the reverse edge")
	assert.Equal(t, "mcp", resource.MqlName())

	bound, ok := resource.(llx.RuntimeBoundResource)
	require.True(t, ok, "the resource has to name the runtime that answers it")
	assert.Same(t, sub, bound.MqlRuntime())

	// A second resolve of the same anchor reuses the runtime rather than
	// connecting again: a discovered asset has no mrn or platform ids yet, so
	// coordinator dedupe cannot see that these are the same asset.
	again, err := r.ResolveAssetRoot(anchor, "mcp")
	require.NoError(t, err)
	assert.Same(t, sub, again.(llx.RuntimeBoundResource).MqlRuntime())

	// And the parent owns it: closing the parent closes what it opened.
	assert.Equal(t, []*Runtime{sub}, r.subRuntimes)
}

// connectFixture builds a parent and an unconnected sub-runtime whose plugin is
// mocked, over the *real* coordinator: Runtime.Connect re-checks which provider
// owns the connected asset, and that goes through the coordinator's provider
// registry. Mocking it there means an unexpected call kills the connecting
// goroutine silently, which looks exactly like the hang this bound exists to
// prevent.
func connectFixture(t *testing.T) (*Runtime, *Runtime, *MockProviderPlugin) {
	t.Helper()
	mockPlugin := NewMockProviderPlugin(gomock.NewController(t))
	// Closing a runtime disconnects its providers; not every path here reaches
	// it, so this is allowed rather than required.
	mockPlugin.EXPECT().Disconnect(gomock.Any()).AnyTimes().Return(&plugin.DisconnectRes{}, nil)

	parent := &Runtime{coordinator: Coordinator, recording: recording.Null{}}
	sub := &Runtime{
		coordinator: Coordinator,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance: &RunningProvider{ID: mockProvider.ID, Name: "mock", Plugin: mockPlugin},
		},
	}
	return parent, sub, mockPlugin
}

// A builtin connector, so Connect's post-connect provider re-check resolves
// in-process instead of going looking for one to install.
func connectTargetAsset(name string) *inventory.Asset {
	return &inventory.Asset{Name: name, Connections: []*inventory.Config{{Type: "mock"}}}
}

// A live connect talks to something outside this process, so it can hang. The
// field read that reached for the asset is blocked on it, and above that sits a
// whole scan - so the bound is what stops one unreachable target taking the
// query down with it.
func TestConnectTargetTimesOut(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "srv/hung"}
	target := connectTargetAsset("hung")

	parent, sub, mockPlugin := connectFixture(t)
	parent.assetReachTimeoutOverride = 50 * time.Millisecond

	release := make(chan struct{})
	entered := make(chan struct{})
	mockPlugin.EXPECT().Connect(gomock.Any(), gomock.Any()).Times(1).
		DoAndReturn(func(*plugin.ConnectReq, plugin.ProviderCallback) (*plugin.ConnectRes, error) {
			close(entered)
			<-release
			return &plugin.ConnectRes{Id: 1, Asset: target}, nil
		})

	err := parent.connectTarget(sub, target, anchorLabel(anchor))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out after 50ms")
	assert.Contains(t, err.Error(), "srv/hung", "the error names the asset it could not reach")

	// The abandoned connect still owns the sub-runtime, so closing it here
	// would race a provider mid-handshake.
	<-entered
	assert.False(t, sub.isClosed, "the sub-runtime was closed while the connect was still running")

	// Once the connect finally returns, the watcher tears it down. Bounding
	// must not mean leaking a runtime and the process behind it.
	close(release)
	require.Eventually(t, func() bool { return sub.isClosed }, 5*time.Second, 10*time.Millisecond,
		"the abandoned connect never closed its runtime")
}

// A connect that answers in time is untouched by the bound.
func TestConnectTargetPassesThrough(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "srv/ok"}
	target := connectTargetAsset("ok")

	parent, sub, mockPlugin := connectFixture(t)
	mockPlugin.EXPECT().Connect(gomock.Any(), gomock.Any()).Times(1).
		Return(&plugin.ConnectRes{Id: 1, Asset: target}, nil)

	require.NoError(t, parent.connectTarget(sub, target, anchorLabel(anchor)))
	assert.NotNil(t, sub.Provider.Connection, "the connection is on the sub-runtime")
	assert.False(t, sub.isClosed)
}

// A connect that fails outright closes its runtime immediately - there is
// nothing still running to race with.
func TestConnectTargetClosesOnFailure(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "srv/refused"}
	target := connectTargetAsset("refused")

	parent, sub, mockPlugin := connectFixture(t)
	mockPlugin.EXPECT().Connect(gomock.Any(), gomock.Any()).Times(1).
		Return(nil, errors.New("connection refused"))

	err := parent.connectTarget(sub, target, anchorLabel(anchor))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Contains(t, err.Error(), "srv/refused")
	assert.True(t, sub.isClosed)
}

// Asking a provider how to reach an asset is bounded too: MqlAsset can call an
// API - inspecting a container, reading a config off a remote - so it is not
// fast by construction.
func TestResolveStepIsBounded(t *testing.T) {
	anchor := &llx.AssetValue{ResourceType: "claude.code.mcpServer", ResourceId: "srv/slow"}

	r := &Runtime{recording: recording.Null{}}
	r.assetReachTimeoutOverride = 50 * time.Millisecond

	release := make(chan struct{})
	defer close(release)

	err := r.bounded("resolving", anchorLabel(anchor), func() error {
		<-release
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out after 50ms resolving asset")
	assert.Contains(t, err.Error(), "srv/slow")
}

func TestAssetReachTimeoutDefaults(t *testing.T) {
	r := &Runtime{}
	assert.Equal(t, defaultAssetReachTimeout, r.assetReachTimeout())

	r.assetReachTimeoutOverride = time.Second
	assert.Equal(t, time.Second, r.assetReachTimeout())
}

// RuntimeForAsset is the same path a query takes, for a caller that already has
// the asset. What it has to keep is everything the anchor path guarantees, not
// just the connect.
func TestRuntimeForAsset(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockC := NewMockProvidersCoordinator(ctrl)
	mockPlugin := NewMockProviderPlugin(ctrl)
	mockPlugin.EXPECT().Disconnect(gomock.Any()).AnyTimes().Return(&plugin.DisconnectRes{}, nil)

	target := connectTargetAsset("discovered")
	sub := &Runtime{
		coordinator: Coordinator,
		recording:   recording.Null{},
		Provider: &ConnectedProvider{
			Instance: &RunningProvider{ID: mockProvider.ID, Name: "mock", Plugin: mockPlugin},
		},
	}

	parent := &Runtime{coordinator: mockC, recording: recording.Null{}}
	mockC.EXPECT().RuntimeFor(target, parent).Times(1).Return(sub, nil)
	mockPlugin.EXPECT().Connect(gomock.Any(), gomock.Any()).Times(1).
		Return(&plugin.ConnectRes{Id: 1, Asset: target}, nil)

	got, err := parent.RuntimeForAsset("docker.image\x00sha256:abc", target)
	require.NoError(t, err)
	assert.Same(t, sub, got)

	// One connection per target however many times it is asked for. The
	// coordinator cannot dedupe this - a freshly built asset has no mrn or
	// platform ids until the connect assigns them - which is why the caller
	// supplies the key.
	again, err := parent.RuntimeForAsset("docker.image\x00sha256:abc", target)
	require.NoError(t, err)
	assert.Same(t, sub, again)

	// And the parent owns it, so it is torn down with the parent rather than
	// left for the coordinator to reap.
	assert.Equal(t, []*Runtime{sub}, parent.subRuntimes)
	parent.closeSubRuntimes()
	assert.True(t, sub.isClosed)
}

// The key is the caller's contract, and the asset needs a way to be reached.
// Both are refused up front rather than surfacing as a confusing connect
// failure, or - worse for the key - as a target connected once per call.
func TestRuntimeForAssetRejectsUnusableInput(t *testing.T) {
	r := &Runtime{coordinator: Coordinator, recording: recording.Null{}}

	_, err := r.RuntimeForAsset("", connectTargetAsset("x"))
	assert.ErrorContains(t, err, "without a key")

	_, err = r.RuntimeForAsset("k", nil)
	assert.ErrorContains(t, err, "no connection to reach it by")

	_, err = r.RuntimeForAsset("k", &inventory.Asset{Name: "x"})
	assert.ErrorContains(t, err, "no connection to reach it by")
}
