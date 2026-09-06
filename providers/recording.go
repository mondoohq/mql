// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"fmt"
	"sync"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

var (
	_ plugin.ProviderPlugin = &recordingProvider{}
	_ plugin.StaticProvider = &recordingProvider{}

	recordingProviderInstance = Provider{
		Provider: &plugin.Provider{
			Name:            "recording",
			ID:              "go.mondoo.com/mql/providers/recording",
			Version:         mql.GetVersion(),
			ConnectionTypes: []string{"recording"},
			Connectors: []plugin.Connector{
				{
					Name:    "recording",
					Use:     "recording [flags]",
					MinArgs: 0,
					MaxArgs: 1,
					Short:   "read recording file from disk",
					Flags: []plugin.Flag{
						{
							Long: "recording-path",
							Type: plugin.FlagType_String,
							Desc: "path to the recording file",
						},
					},
				},
			},
		},
	}
)

func (*recordingProvider) StaticName() string {
	return "recording"
}

type RecordingProviderOpt func(*recordingProvider)

// allows to set a custom recording implementation programmatically
func WithRecording(rec llx.Recording) RecordingProviderOpt {
	return func(rp *recordingProvider) {
		rp.recording = rec
	}
}

// allows to set the selected asset
func WithAsset(asset *inventory.Asset) RecordingProviderOpt {
	return func(rp *recordingProvider) {
		rp.selectedAsset = asset
	}
}

func NewRecordingProvider(opts ...RecordingProviderOpt) *recordingProvider {
	rp := &recordingProvider{}
	for _, o := range opts {
		o(rp)
	}
	return rp
}

type recordingProvider struct {
	// mu guards selectedAsset and connections: one static provider instance
	// serves every asset of a multi-asset recording, and those assets are
	// connected and scanned concurrently.
	mu            sync.Mutex
	selectedAsset *inventory.Asset
	// the asset each connection was established for, so requests can be routed
	// to that asset's section of the recording
	connections map[uint32]*inventory.Asset
	recording   llx.Recording
}

// asset returns the asset selected by the most recent connect. It only serves
// callers that don't set a connection on their requests; anything that does is
// routed by connection instead.
func (s *recordingProvider) asset() *inventory.Asset {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selectedAsset
}

func (s *recordingProvider) selectAsset(asset *inventory.Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selectedAsset = asset
}

func (s *recordingProvider) addConnection(connID uint32, asset *inventory.Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connections == nil {
		s.connections = map[uint32]*inventory.Asset{}
	}
	s.connections[connID] = asset
}

func (s *recordingProvider) Heartbeat(req *plugin.HeartbeatReq) (*plugin.HeartbeatRes, error) {
	return nil, nil
}

// Translations: a recording replays what was captured, so there is no live
// provider whose shapes could need bridging.
func (s *recordingProvider) Translations(req *plugin.TranslationsReq) (*plugin.TranslationsRes, error) {
	return &plugin.TranslationsRes{}, nil
}

func (s *recordingProvider) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	filePath := ""

	pathFlag := req.Flags["recording-path"]
	if pathFlag != nil && pathFlag.RawData().Value.(string) != "" {
		filePath = pathFlag.RawData().Value.(string)
	}

	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Type: "recording",
				Path: filePath,
			},
		},
	}

	res := &plugin.ParseCLIRes{
		Asset: asset,
	}
	return res, nil
}

func (s *recordingProvider) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing config")
	}

	// initial connection, expecting the recording file path as part of the config
	if s.recording == nil {
		path := req.Asset.Connections[0].Path
		rec, err := recording.LoadRecordingFile(path)
		if err != nil {
			return nil, err
		}
		s.recording = rec
	}

	inv, err := s.detect(req.GetAsset())
	if err != nil {
		return nil, err
	}
	res := &plugin.ConnectRes{
		Asset:     req.GetAsset(),
		Inventory: inv,
	}

	// A concrete asset was connected (as opposed to the discovery pass, which
	// returns the inventory above): remember which asset this connection serves
	// and report the connection id back to the runtime, which then sends it on
	// every GetData/StoreData request. One provider instance serves every asset
	// of a multi-asset recording, so routing by connection is what keeps assets
	// from reading and writing each other's data. Without an id, requests fall
	// back to the shared selectedAsset (see GetData).
	if asset := req.GetAsset(); asset.GetPlatform() != nil && len(asset.GetConnections()) > 0 &&
		(asset.GetMrn() != "" || len(asset.GetPlatformIds()) > 0) {
		conf := asset.Connections[0]
		if conf.Id == 0 {
			conf.Id = Coordinator.NextConnectionId()
		}
		s.addConnection(conf.Id, asset)
		res.Id = conf.Id
	}

	return res, nil
}

func (s *recordingProvider) detect(asset *inventory.Asset) (*inventory.Inventory, error) {
	if asset.GetPlatform() != nil {
		if !asset.Connections[0].DelayDiscovery {
			if asset.GetMrn() == "" && len(asset.GetPlatformIds()) == 0 {
				return nil, errors.New("missing mrn or platform ids for asset selection")
			}
			s.selectAsset(asset)
		}
		return nil, nil
	}

	assets := []*inventory.Asset{}
	for _, a := range s.recording.GetAssets() {
		// we do not allow assets with no connection as they wont work with getting/storing data
		if len(a.Connections) == 0 {
			continue
		}
		// Assign a fresh connection id per asset. The id carried by the recording
		// file is not guaranteed to be unique across its assets — every asset of
		// a synthesized recording may share id 1 — and connections are what
		// requests are routed by, so two assets sharing an id would collapse onto
		// one of them.
		a.Connections = []*inventory.Config{
			{
				Type:           "recording",
				DelayDiscovery: true,
				Id:             Coordinator.NextConnectionId(),
			},
		}
		assets = append(assets, a)
	}

	inv := inventory.New(inventory.WithAssets(assets...))
	return inv, nil
}

func (s *recordingProvider) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("the recording provider does not support the mock connect call, this is an internal error")
}

func (s *recordingProvider) Disconnect(req *plugin.DisconnectReq) (*plugin.DisconnectRes, error) {
	return nil, nil
}

func (s *recordingProvider) Shutdown(req *plugin.ShutdownReq) (*plugin.ShutdownRes, error) {
	return nil, nil
}

// lookupFor identifies the recording section a request belongs to. The mrn and
// platform ids of the connection's asset take precedence over the connection id
// itself: a recording loaded from disk may reuse one connection id across
// several of its assets, in which case the recording's connection index only
// resolves to whichever asset claimed the id last.
func (s *recordingProvider) lookupFor(connID uint32) llx.AssetRecordingLookup {
	s.mu.Lock()
	asset, ok := s.connections[connID]
	s.mu.Unlock()
	if !ok {
		return llx.AssetRecordingLookup{ConnectionId: connID}
	}
	return assetLookup(asset, connID)
}

func assetLookup(asset *inventory.Asset, connID uint32) llx.AssetRecordingLookup {
	return llx.AssetRecordingLookup{
		ConnectionId: connID,
		Mrn:          asset.GetMrn(),
		PlatformIds:  asset.GetPlatformIds(),
	}
}

func (s *recordingProvider) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	resource := req.GetResource()
	id := req.GetResourceId()
	field := req.GetField()
	// When the caller didn't supply an ID (resource init by name + args),
	// fall back to the deterministic args hash so the recording lookup
	// can differentiate e.g. file(path: "/a") from file(path: "/b").
	if id == "" && len(req.GetArgs()) > 0 {
		id = llx.ArgsLookupID(req.GetArgs())
	}
	lookup := llx.AssetRecordingLookup{}
	if connID := req.GetConnection(); connID != 0 {
		// The runtime sets the connection on every request. Scope the lookup to
		// that connection's asset: one static provider instance serves all
		// assets of a multi-asset recording, so routing by the shared
		// selectedAsset would cross-read between assets.
		lookup = s.lookupFor(connID)
	} else if asset := s.asset(); asset != nil {
		lookup = assetLookup(asset, 0)
	}
	data, ok := s.recording.GetData(lookup, resource, id, field)
	if !ok {
		errMsg := fmt.Sprintf("resource %s (id: %s) doesn't exist", resource, id)
		if f := field; f != "" {
			// prettify the error message if we're asking for a field
			errMsg = fmt.Sprintf("resource %s (id: %s, field: %s) doesn't exist", resource, id, f)
		}

		return nil, errors.New(errMsg)
	}

	res := data.Result().Data
	return &plugin.DataRes{Data: res}, nil
}

func (s *recordingProvider) StoreData(req *plugin.StoreReq) (*plugin.StoreRes, error) {
	// The runtime sets the connection on every request; store under that
	// connection's asset (see GetData). Fall back to the selected asset for
	// programmatic callers that don't set a connection.
	connID := req.GetConnection()
	var lookup llx.AssetRecordingLookup
	if connID != 0 {
		lookup = s.lookupFor(connID)
	} else {
		asset := s.asset()
		if asset == nil {
			return nil, errors.New("no asset selected, cannot store data")
		}
		if len(asset.Connections) == 0 {
			return nil, errors.New("selected asset has no connections, cannot store data")
		}
		connID = asset.Connections[0].Id
		lookup = assetLookup(asset, connID)
	}
	for _, info := range req.Resources {
		for field, result := range info.Fields {
			s.recording.AddData(llx.AddDataReq{
				ConnectionID:      connID,
				Lookup:            lookup,
				Resource:          info.Name,
				ResourceID:        info.Id,
				Field:             field,
				Data:              result.RawData(),
				RequestResourceId: info.Id,
			})
		}
	}

	return &plugin.StoreRes{}, nil
}
