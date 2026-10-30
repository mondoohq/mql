// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"maps"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/stackit/connection"
	"go.mondoo.com/mql/providers/stackit/resources"
)

const DefaultConnectionType = "stackit"

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Options: map[string]string{},
	}

	stringOpts := []string{
		connection.OptionProjectID,
		connection.OptionRegion,
		connection.OptionEndpoint,
		connection.OptionServiceAccountKeyPath,
		connection.OptionPrivateKeyPath,
	}
	for _, opt := range stringOpts {
		if v, ok := flags[opt]; ok && len(v.Value) != 0 {
			conf.Options[opt] = string(v.Value)
		}
	}

	secretOpts := []string{
		connection.OptionToken,
		connection.OptionServiceAccountKey,
		connection.OptionPrivateKey,
	}
	for _, opt := range secretOpts {
		if v, ok := flags[opt]; ok && len(v.Value) != 0 {
			cred := vault.NewPasswordCredential(opt, string(v.Value))
			conf.Credentials = append(conf.Credentials, cred)
		}
	}

	// Discovery flags. With no --discover flag we default to "auto" so a plain
	// `cnspec scan stackit` brings in the project's sub-assets (databases, SKE
	// clusters, buckets, …) the way the aws/gcp providers do.
	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	}
	if len(discoverTargets) == 0 {
		discoverTargets = []string{resources.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	asset := &inventory.Asset{
		Name:        "STACKIT",
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: asset}, nil
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	// Start the returned inventory with the connected root asset, then append any
	// discovered sub-assets. Discovered sub-assets carry WithoutDiscovery, so
	// re-connecting to one yields no targets and does not re-expand.
	inv := &inventory.Inventory{
		Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{req.Asset}},
	}
	discovered, err := s.discover(conn)
	if err != nil {
		return nil, err
	}
	if discovered != nil {
		inv.Spec.Assets = append(inv.Spec.Assets, discovered.Spec.Assets...)
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inv,
	}, nil
}

// discover enumerates STACKIT sub-assets for the connection's discovery targets.
// Returns nil when discovery is not requested (e.g. when re-connecting to a
// discovered sub-asset, whose cloned config carries no targets).
func (s *Service) discover(conn *connection.StackitConnection) (*inventory.Inventory, error) {
	if conn.Conf == nil || len(conn.Conf.GetDiscover().GetTargets()) == 0 {
		return nil, nil
	}
	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}
	return resources.Discover(runtime)
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.StackitConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewStackitConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		verifyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := conn.Verify(verifyCtx); err != nil {
			return nil, err
		}

		var upstreamClient *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstreamClient, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = conn.ID()
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstreamClient), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.StackitConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.StackitConnection) error {
	asset.Id = conn.Identifier()
	asset.Platform = conn.PlatformInfo()
	asset.PlatformIds = []string{conn.Identifier()}

	// Prefer the human-readable project name resolved from the resource-manager
	// API (captured during Verify), the way gcp uses project.Name and aws uses
	// the account/host. Fall back to the project ID when it is unavailable.
	if asset.Name == "" || asset.Name == "STACKIT" {
		if name := conn.ProjectName(); name != "" {
			asset.Name = name
		} else {
			asset.Name = "STACKIT project " + conn.ProjectID()
		}
	}

	// Attach the project's labels plus stackit-specific metadata so discovered
	// and directly-connected assets carry the same context as gcp/aws assets.
	if asset.Labels == nil {
		asset.Labels = map[string]string{}
	}
	maps.Copy(asset.Labels, conn.ProjectLabels())
	asset.Labels["mondoo.com/region"] = conn.Region()
	if parent := conn.ProjectParent(); parent != "" {
		asset.Labels["mondoo.com/parent-id"] = parent
	}

	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
