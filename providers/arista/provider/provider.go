// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/arista/connection"
	"go.mondoo.com/mql/providers/arista/resources"
	"go.mondoo.com/mql/providers/arista/resources/eos"
)

const (
	ConnectionType = "arista"
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

	conn := &inventory.Config{
		Type: req.Connector,
	}

	// custom flag parsing
	user := ""
	port := 0
	if len(req.Args) != 0 {
		target := req.Args[0]
		if !strings.Contains(target, "://") {
			target = "ssh://" + target
		}

		x, err := url.Parse(target)
		if err != nil {
			return nil, errors.New("incorrect format of target, please use user@host:port")
		}

		user = x.User.Username()
		conn.Host = x.Hostname()

		if sPort := x.Port(); sPort != "" {
			port, err = strconv.Atoi(x.Port())
			if err != nil {
				return nil, errors.New("port '" + x.Port() + "'is incorrectly formatted, must be a number")
			}
		}
	}

	if port > 0 {
		conn.Port = int32(port)
	}

	if x, ok := flags["password"]; ok && len(x.Value) != 0 {
		conn.Credentials = append(conn.Credentials, vault.NewPasswordCredential(user, string(x.Value)))
	}

	// Validate that password was provided
	if len(conn.Credentials) == 0 {
		return nil, errors.New("password is required. Use --password or --ask-pass to provide credentials")
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conn},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// Shutdown is automatically called when the shell closes.
// It is not necessary to implement this method.
// If you want to do some cleanup, you can do it here.

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.AristaConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewAristaConnection(connId, asset, conf)
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
		asset.Connections[0].Id = connId

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

	return runtime.Connection.(*connection.AristaConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.AristaConnection) error {
	asset.Name = conn.Conf.Host
	version := ""
	arch := ""
	model := ""
	aristaVersion, err := conn.GetVersion()
	if err == nil {
		version = aristaVersion.Version
		arch = aristaVersion.Architecture
		model = aristaVersion.ModelName
	}

	platform := &inventory.Platform{
		Version:               version,
		Arch:                  arch,
		TechnologyUrlSegments: []string{"network", "arista"},
	}
	if pi, ok := PlatformByName("arista-eos"); ok {
		pi.Apply(platform)
	}
	// Report the chassis model as the platform runtime so the server can scope
	// EOS advisories to the device's hardware family (models named in a CVE's
	// affected[].platforms). This is set AFTER Apply, which overwrites Runtime
	// with the catalog's "arista" marker; the device is still classified as an
	// Arista EOS asset by its "arista-eos" platform name. Mirrors how the Junos
	// provider reports its hardware model.
	if model != "" {
		platform.Runtime = model
	}
	asset.Platform = platform

	eosClient := eos.NewEos(conn.Client())
	hostname, err := eosClient.ShowHostname()
	if err == nil {
		asset.Fqdn = hostname.Fqdn
	}

	id, err := conn.Identifier()
	if err != nil {
		return err
	}
	asset.PlatformIds = []string{id}
	return nil
}
