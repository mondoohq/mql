// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/openstack/connection"
	"go.mondoo.com/mql/providers/openstack/resources"
)

const DefaultConnectionType = "openstack"

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

	stringFlags := []string{
		connection.OPTION_CLOUD,
		connection.OPTION_AUTH_URL,
		connection.OPTION_USERNAME,
		connection.OPTION_PROJECT_NAME,
		connection.OPTION_PROJECT_ID,
		connection.OPTION_USER_DOMAIN_NAME,
		connection.OPTION_USER_DOMAIN_ID,
		connection.OPTION_PROJECT_DOMAIN_NAME,
		connection.OPTION_PROJECT_DOMAIN_ID,
		connection.OPTION_REGION,
		connection.OPTION_APPLICATION_CREDENTIAL_ID,
		connection.OPTION_APPLICATION_CREDENTIAL_NAME,
		connection.OPTION_APPLICATION_CREDENTIAL_SECRET,
	}
	for _, name := range stringFlags {
		if v, ok := flags[name]; ok && len(v.Value) > 0 {
			conf.Options[name] = string(v.Value)
		}
	}

	if v, ok := flags[connection.OPTION_PASSWORD]; ok && len(v.Value) > 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", string(v.Value)))
	}

	if v, ok := flags[connection.OPTION_INSECURE]; ok && len(v.Value) > 0 && v.Value[0] != 0 {
		conf.Options[connection.OPTION_INSECURE] = "true"
	}

	// Discovery expands the connected scope into specific child assets.
	discoverTargets := []string{connection.DiscoveryAuto}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		discoverTargets = discoverTargets[:0]
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	asset := &inventory.Asset{
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

	// We only need to run the detection step when we don't have any asset information yet.
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

func (s *Service) discover(conn *connection.OpenstackConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}
	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}
	return resources.Discover(runtime)
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.OpenstackConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewOpenstackConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.OpenstackConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.OpenstackConnection) error {
	// A discovered child asset (e.g. a single security group) carries its scope
	// in the connection options; report its platform instead of the root scope.
	if platform, platformID, name := conn.SubAssetPlatform(); platform != nil {
		asset.Platform = platform
		asset.Id = platformID
		asset.PlatformIds = []string{platformID}
		if asset.Name == "" {
			asset.Name = name
		}
		return nil
	}

	asset.Platform = &inventory.Platform{}

	var platformName string
	switch {
	case conn.ProjectID() != "":
		platformName = "openstack-project"
		asset.Id = connection.PlatformIdOpenstackProject + conn.ProjectID()
		if asset.Name == "" {
			asset.Name = "OpenStack project " + conn.ProjectID()
		}
	case conn.DomainID() != "":
		platformName = "openstack-domain"
		asset.Id = connection.PlatformIdOpenstackDomain + conn.DomainID()
		if asset.Name == "" {
			asset.Name = "OpenStack domain " + conn.DomainID()
		}
	default:
		// System-scoped or otherwise unscoped — derive a stable id from the
		// auth URL so multiple system-scoped connections to the same Keystone
		// share an identity.
		sum := sha256.Sum256([]byte(conn.AuthURL()))
		fp := hex.EncodeToString(sum[:])
		platformName = "openstack-system"
		asset.Id = connection.PlatformIdOpenstackSystem + fp
		if asset.Name == "" {
			asset.Name = "OpenStack at " + conn.AuthURL()
		}
	}
	connection.PlatformByName(platformName).Apply(asset.Platform)
	asset.PlatformIds = []string{asset.Id}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
