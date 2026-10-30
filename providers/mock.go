// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"slices"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
)

var mockProvider = Provider{
	Provider: &plugin.Provider{
		Name:    "mock",
		ID:      "go.mondoo.com/mql/providers/mock",
		Version: mql.GetVersion(),
		Connectors: []plugin.Connector{
			{
				Name:  "mock",
				Use:   "mock",
				Short: "a recording file without an active connection",
			},
			{
				Name:     "upstream",
				Use:      "upstream",
				Short:    "use upstream asset data",
				IsHidden: true,
				Flags: []plugin.Flag{
					{
						Long: "asset",
						Type: plugin.FlagType_String,
						Desc: "the upstream asset MRN to connect with",
					},
				},
			},
		},
	},
}

type mockProviderService struct {
	initialized bool
}

func (s *mockProviderService) Heartbeat(req *plugin.HeartbeatReq) (*plugin.HeartbeatRes, error) {
	return nil, nil
}

// Translations: the mock provider bridges no shapes.
func (s *mockProviderService) Translations(req *plugin.TranslationsReq) (*plugin.TranslationsRes, error) {
	return &plugin.TranslationsRes{}, nil
}

func (s *mockProviderService) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	if req.Connector == "upstream" {
		return s.parseUpstreamCLI(req)
	}

	return &plugin.ParseCLIRes{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "mock",
				},
			},
		},
	}, nil
}

func (s *mockProviderService) parseUpstreamCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	assetMrn := req.Flags["asset"]
	if assetMrn == nil || len(assetMrn.Value) == 0 {
		return nil, errors.New("please specify an asset MRN")
	}

	return &plugin.ParseCLIRes{
		Asset: &inventory.Asset{
			Mrn: string(assetMrn.Value),
			Connections: []*inventory.Config{
				{
					Type: "mock",
				},
			},
		},
	}, nil
}

// TODO: Replace this entire call with a detector
func assetinfo2providerName(asset *inventory.Asset) (string, error) {
	if asset == nil {
		return "", errors.New("no asset information provided to infer a provider")
	}
	if asset.Platform == nil {
		return "", errors.New("no asset platform information provided to infer a provider")
	}

	switch asset.Platform.Kind {
	case "container-image", inventory.AssetKindBaremetal:
		return "os", nil
	}

	switch asset.Platform.Name {
	case "aws":
		return "aws", nil
	case "azure":
		return "azure", nil
	case "gcp":
		return "gcp", nil
	}

	return "", errors.New("cannot determine provider type for this upstream asset: " + asset.Platform.Name)
}

func (s *mockProviderService) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	// This service instance is shared by every runtime in the process, so the
	// runtime to work against comes from the callback of this connect and never
	// from the service. See runtimeFromCallback.
	runtime, err := runtimeFromCallback(callback)
	if err != nil {
		return nil, err
	}

	// If an upstream asset was requested
	if req.Asset.Mrn != "" {
		if req.Upstream == nil {
			return nil, errors.New("missing an upstream configuration")
		}

		ctx := context.Background()
		client, err := req.Upstream.InitClient(ctx)
		if err != nil {
			return nil, err
		}

		explorer, err := recording.NewRemoteServices(client.ApiEndpoint, client.Plugins, client.HttpClient)
		if err != nil {
			return nil, err
		}

		urecording, err := recording.NewUpstreamRecording(ctx, explorer, req.Asset.Mrn)
		if err != nil {
			return nil, err
		}

		asset := urecording.Asset()
		providerName, err := assetinfo2providerName(asset)
		if err != nil {
			return nil, err
		}

		provider := Coordinator.Providers().Lookup(ProviderLookup{ProviderName: providerName})
		if provider == nil {
			return nil, errors.New("failed to look up provider for upstream recording with name=" + providerName)
		}

		addedProvider, err := runtime.addProvider(provider.ID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to init provider for connection in recording")
		}

		conn, err := addedProvider.Instance.Plugin.MockConnect(&plugin.ConnectReq{
			Asset:    asset,
			Features: req.Features,
			Upstream: req.Upstream,
		}, callback)
		if err != nil {
			return nil, errors.Wrap(err, "failed to init referenced provider")
		}

		addedProvider.Connection = conn
		err = runtime.SetRecording(urecording)
		return conn, err
	}

	// initialize all other providers from all asset connections in the recording
	multiRecording, ok := runtime.Recording().(recording.MultiAsset)
	if !ok {
		return nil, errors.New("cannot find assets in recording for mock provider")
	}

	assetRecordings := multiRecording.GetAssetRecordings()
	if len(assetRecordings) == 0 {
		return nil, errors.New("no assets found in recording for mock provider")
	}

	asset := pickAssetRecording(assetRecordings, req.Asset)
	if asset == nil {
		return nil, errors.New("no recording found for asset " + assetLabel(req.Asset))
	}
	if len(asset.Connections) == 0 {
		return nil, errors.New("no connections found in asset")
	}

	var res *plugin.ConnectRes
	for i := range asset.Connections {
		conf := asset.Connections[i]

		provider, err := runtime.addRecordedProvider(conf.ProviderID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to init provider for connection in recording")
		}

		conn, err := provider.Instance.Plugin.MockConnect(&plugin.ConnectReq{
			Asset:    asset.Asset,
			Features: req.Features,
			Upstream: req.Upstream,
		}, callback)
		if err != nil {
			return nil, errors.Wrap(err, "failed to init referenced provider")
		}

		provider.Connection = conn
		if i == 0 {
			res = conn
		}
	}

	return res, nil
}

func (s *mockProviderService) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	// Should never happen: the mock provider should not be called with MockConnect.
	// It is the only thing that should ever call MockConnect to other providers
	// (outside of tests).
	return nil, errors.New("the mock provider does not support the mock connect call, this is an internal error")
}

func (s *mockProviderService) Disconnect(req *plugin.DisconnectReq) (*plugin.DisconnectRes, error) {
	// Nothing to do yet...
	return nil, nil
}

// ResolveAsset: this service owns no resources of its own - it replays or
// wraps another provider's - so there is no anchor here to stand for an asset.
func (s *mockProviderService) ResolveAsset(req *plugin.ResolveAssetReq) (*plugin.ResolveAssetRes, error) {
	return &plugin.ResolveAssetRes{}, nil
}

func (s *mockProviderService) Shutdown(req *plugin.ShutdownReq) (*plugin.ShutdownRes, error) {
	// Nothing to do yet...
	return nil, nil
}

func (s *mockProviderService) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	panic("NO")
}

func (s *mockProviderService) StoreData(req *plugin.StoreReq) (*plugin.StoreRes, error) {
	panic("NO")
}

func (s *mockProviderService) Init(running *RunningProvider) {
	if s.initialized {
		return
	}
	s.initialized = true

	// TODO: Currently not needed, as the coordinator loads all schemas right now.
	// Once it doesn't do that anymore, remember to load all schemas here
	// rt.schema.unsafeLoadAll()
	// rt.schema.unsafeRefresh()
}

// pickAssetRecording finds the recorded asset a connect request is asking for.
//
// A recording holds many assets, and taking the first one was fine while the
// only caller replayed the asset the recording was made for. Cross-asset
// resolution (ADR 031) connects a *specific* recorded asset, and answering with
// the first one hands back the host's data under the target's name - a wrong
// answer rather than a miss, which is the worst shape a bug can take here.
//
// Matching follows the same precedence the coordinator uses to dedupe runtimes
// (coordinator.go:191): MRN, then platform ids, then - only because a stub
// assembled from a relationship may carry neither - the name. A request that
// identifies nothing keeps the historical behavior and gets the first asset.
func pickAssetRecording(assets []*recording.Asset, want *inventory.Asset) *recording.Asset {
	if len(assets) == 0 {
		return nil
	}
	if want == nil || (want.Mrn == "" && len(want.PlatformIds) == 0 && want.Name == "") {
		return assets[0]
	}

	if want.Mrn != "" {
		for _, a := range assets {
			if a.Asset != nil && a.Asset.Mrn == want.Mrn {
				return a
			}
		}
	}
	for _, id := range want.PlatformIds {
		for _, a := range assets {
			if a.Asset == nil {
				continue
			}
			if slices.Contains(a.Asset.PlatformIds, id) {
				return a
			}
		}
	}
	if want.Name != "" {
		for _, a := range assets {
			if a.Asset != nil && a.Asset.Name == want.Name {
				return a
			}
		}
	}
	return nil
}

// assetLabel names an asset for an error message, preferring the most specific
// identifier it carries.
func assetLabel(a *inventory.Asset) string {
	if a == nil {
		return "<none>"
	}
	if a.Mrn != "" {
		return a.Mrn
	}
	if len(a.PlatformIds) > 0 {
		return a.PlatformIds[0]
	}
	if a.Name != "" {
		return a.Name
	}
	return "<unidentified>"
}
