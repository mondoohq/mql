// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/nextdns/connection"
	"go.mondoo.com/mql/providers/nextdns/resources"
)

const (
	DefaultConnectionType = "nextdns"
)

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

	// discovery targets: "all", "auto", "accounts", "profiles"
	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	} else {
		discoverTargets = []string{connection.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	apiKey := ""
	if x, ok := flags["api-key"]; ok && len(x.Value) != 0 {
		apiKey = string(x.Value)
	}
	if apiKey == "" {
		apiKey = os.Getenv("NEXTDNS_API_KEY")
	}
	if apiKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	// We only need to run the detection step when we don't have any asset
	// information yet. Discovered child assets already carry their platform.
	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	inv, err := s.discover(conn)
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inv,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.NextdnsConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.NextdnsConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewNextdnsConnection(connId, asset, conf)
		}
		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
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
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.NextdnsConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.NextdnsConnection) error {
	asset.Platform = conn.PlatformInfo()

	if profileID := conn.ProfileID(); profileID != "" {
		asset.Id = profileID
		asset.PlatformIds = []string{connection.NewNextdnsProfileIdentifier(profileID)}
		if asset.Name == "" {
			asset.Name = "NextDNS Profile " + profileID
		}
		return nil
	}

	// Without a profile scope the connection points at the whole account, which
	// serves only as a discovery hub. The NextDNS API exposes no account-level
	// resources worth scanning (the account id is a synthetic fingerprint of the
	// API key), so the root is left without platform IDs and is not scanned
	// itself — the scanner skips assets that have none. Discovery enumerates the
	// profiles to scan, and a scannable account asset is emitted only when it is
	// an explicit discovery target (`--discover accounts` or `--discover all`).
	accountID := conn.AccountID()
	asset.Id = accountID
	if asset.Name == "" {
		asset.Name = "NextDNS Account"
	}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
