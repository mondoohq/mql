// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	iacconf "go.mondoo.com/mql/providers/iac/config"
	iacconn "go.mondoo.com/mql/providers/iac/connection"
	iacresources "go.mondoo.com/mql/providers/iac/resources"
	"go.mondoo.com/mql/providers/iac/walk"
)

var iacProvider = Provider{Provider: &iacconf.Config}

// iacProviderService is the `iac` meta-target (ADR 045): it walks a tree, asks
// the providers whose opt-ins matched whether they want each candidate, and
// hands back what they accepted.
//
// It lives in package providers rather than under providers/iac because the
// probe is made of runtimeFromCallback, Runtime.coordinator and
// providerCallbacks, none of which are exported. sbom sits here for the same
// reason.
//
// plugin.Service is embedded the way core's service embeds it, which supplies
// GetData, StoreData, Disconnect, Heartbeat, Shutdown, Translations and
// ResolveAsset. ResolveAsset in particular is what answers a
// `iac.detection.asset` read, with no code here.
type iacProviderService struct {
	*plugin.Service
}

func (s *iacProviderService) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	if len(req.Args) != 1 {
		return nil, errors.New("the iac provider needs a path to a directory or file")
	}

	conf := &inventory.Config{
		Type:     iacconn.ConnectionType,
		Path:     req.Args[0],
		Options:  map[string]string{},
		Discover: parseIacDiscover(req.Flags),
	}

	// Presence of the flag is what replaces the defaults; its contents are the
	// new set, and an empty set is a valid one. A list flag given "" arrives as
	// one empty entry rather than as no entries at all, and a caller building
	// the request by hand may pass no entries at all: both mean an empty
	// ignore set, which is how you reach a vendored tree on purpose. The CLI
	// only puts the flag here when the user passed it (setConnector checks
	// Changed), so an unset flag never reaches this branch.
	if flag, ok := req.Flags["iac-ignore"]; ok && flag != nil {
		ignore := []string{}
		for i := range flag.Array {
			if v := string(flag.Array[i].Value); v != "" {
				ignore = append(ignore, v)
			}
		}
		conf.Options[iacconn.OptionIgnore] = strings.Join(ignore, ",")
	}

	return &plugin.ParseCLIRes{Asset: &inventory.Asset{
		Connections: []*inventory.Config{conf},
	}}, nil
}

func parseIacDiscover(flags map[string]*llx.Primitive) *inventory.Discovery {
	discovery := &inventory.Discovery{Targets: []string{DiscoveryAuto}}
	if flag, ok := flags["discover"]; ok && len(flag.Array) > 0 {
		discovery.Targets = []string{}
		for i := range flag.Array {
			discovery.Targets = append(discovery.Targets, string(flag.Array[i].Value))
		}
	}
	return discovery
}

func (s *iacProviderService) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil || len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection data provided")
	}

	// This service instance is shared by every runtime in the process, so the
	// runtime to work against comes from the callback of this connect and never
	// from the service. See runtimeFromCallback.
	parent, err := runtimeFromCallback(callback)
	if err != nil {
		return nil, err
	}

	asset := req.Asset
	conf := asset.Connections[0]

	absPath, err := filepath.Abs(iacTargetPath(conf))
	if err != nil {
		return nil, err
	}
	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	// A file as the target widens to its directory for the tools that read one,
	// and stays the file for the tools that read one document -- which is what
	// `scan terraform ./main.tf` already does.
	treeRoot := absPath
	if !stat.IsDir() {
		treeRoot = filepath.Dir(absPath)
	}

	source := iacconn.Source{Kind: iacconn.KindFile, Origin: absPath}
	iacDetectAsset(asset, conf, absPath)

	conn, err := s.iacConnect(req, callback, source)
	if err != nil {
		return nil, err
	}

	optIns, err := s.selectOptIns(parent, conf)
	if err != nil {
		return nil, err
	}

	result, err := s.walkTree(parent, req, treeRoot, absPath, stat.IsDir(), optIns, iacIgnore(conf), asset)
	if err != nil {
		return nil, err
	}
	conn.SetDetections(result.Detections)

	// Create the detection resources now rather than when a query first reads
	// `iac.detections`: plugin.Service.ResolveAsset answers from the resource
	// cache and never creates, so an anchor would otherwise only resolve if
	// something happened to have read the list first.
	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}
	if err := iacresources.CreateDetectionResources(runtime, result.Detections); err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     asset,
		Inventory: inventory.New(inventory.WithAssets(result.Assets...)),
		Root:      iacconf.Config.Root,
	}, nil
}

// iacTargetPath reads the target from wherever the caller put it. The CLI sets
// Path; an inventory file may use either.
func iacTargetPath(conf *inventory.Config) string {
	if conf.Path != "" {
		return conf.Path
	}
	return conf.Options["path"]
}

func iacIgnore(conf *inventory.Config) []string {
	raw, ok := conf.Options[iacconn.OptionIgnore]
	if !ok {
		return iacconn.DefaultIgnore
	}
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// iacDetectAsset gives the project its identity. iac decides its own, the way
// every provider does: for a local tree the hash of the absolute path, the
// scheme kustomize and docker-file already use.
func iacDetectAsset(asset *inventory.Asset, conf *inventory.Config, absPath string) {
	platformID := iacconn.PlatformID(absPath)
	asset.Id = platformID
	asset.PlatformIds = []string{platformID}
	asset.Name = iacconn.AssetName(absPath)
	conf.PlatformId = platformID

	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"iac", "project", iacconn.KindFile},
	}
	iacconn.PlatformByName("iac").Apply(asset.Platform)
}

func (s *iacProviderService) iacConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback, source iacconn.Source) (*iacconn.IacConnection, error) {
	asset := req.Asset
	runtime, err := s.AddRuntime(asset.Connections[0], func(connId uint32) (*plugin.Runtime, error) {
		conn := iacconn.NewIacConnection(connId, asset, source)

		var up *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			var err error
			up, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = conn.ID()
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			iacresources.CreateResource,
			iacresources.NewResource,
			iacresources.GetData,
			iacresources.SetData,
			up), nil
	})
	if err != nil {
		return nil, err
	}
	return runtime.Connection.(*iacconn.IacConnection), nil
}

// selectOptIns resolves this connection's --discover value to the opt-ins the
// walk probes with.
//
// The CLI already did this before cobra ran, so on that path everything is
// installed by now and this is cheap. It is repeated because an inventory file
// and the scan API reach Connect without passing through the CLI at all, and
// they are owed the same answer.
func (s *iacProviderService) selectOptIns(parent *Runtime, conf *inventory.Config) ([]plugin.TargetOptIn, error) {
	universe := TargetUniverse(iacconn.ConnectionType, parent.coordinator.Providers(), DefaultProviders)

	var requested []string
	requestedSet := false
	if discover := conf.GetDiscover(); discover != nil {
		requested = discover.Targets
		requestedSet = true
	}

	selected, unknown := ResolveTargetDiscoveries(universe, requested, requestedSet)
	if len(unknown) > 0 {
		valid := slices.Concat([]string{DiscoveryAll, DiscoveryAuto}, TargetDiscoveryNames(universe))
		return nil, errors.New("unknown discovery target(s) " + strings.Join(unknown, ", ") +
			"; valid values are: " + strings.Join(valid, ", "))
	}

	optIns := make([]plugin.TargetOptIn, 0, len(selected))
	for _, discovery := range selected {
		optIns = append(optIns, discovery.OptIn)
	}
	return optIns, nil
}

func (s *iacProviderService) walkTree(parent *Runtime, req *plugin.ConnectReq, treeRoot, absPath string, isDir bool, optIns []plugin.TargetOptIn, ignore []string, root *inventory.Asset) (*walk.Result, error) {
	if len(optIns) == 0 {
		return &walk.Result{}, nil
	}

	tree := walk.Tree{FS: os.DirFS(treeRoot), Root: treeRoot}
	if !isDir {
		// A single file target: only that file is in the tree, so a directory
		// opt-in still sees the folder it lives in and a PerFile one sees the
		// file.
		tree.FS = singleFileFS{dir: os.DirFS(treeRoot), name: filepath.Base(absPath)}
	}

	prober := newIacProber(parent, req.Features)
	defer prober.Close()

	selection := walk.Selection{
		OptIns: optIns,
		All:    iacDiscoverHasAll(req.Asset.Connections[0]),
	}
	return walk.Walk(tree, selection, walk.Options{Ignore: ignore}, root, prober)
}

func iacDiscoverHasAll(conf *inventory.Config) bool {
	for _, target := range conf.GetDiscover().GetTargets() {
		if target == DiscoveryAll {
			return true
		}
	}
	return false
}

// MockConnect replays a recorded iac scan.
//
// It builds the connection without walking anything: with a recording in hand
// the generated accessors answer `source` and `detections` from it, so walking
// the tree again would be both wrong (the tree may not be here) and pointless.
// The child assets of a recorded scan are reached through the ADR 030 edge each
// one carries, not by probing.
func (s *iacProviderService) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil || len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection data provided")
	}

	asset := req.Asset
	source := iacconn.Source{Kind: iacconn.KindFile, Origin: iacTargetPath(asset.Connections[0])}

	conn, err := s.iacConnect(req, callback, source)
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:    conn.ID(),
		Name:  conn.Name(),
		Asset: asset,
		Root:  iacconf.Config.Root,
	}, nil
}
