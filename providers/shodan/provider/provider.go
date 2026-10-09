// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/vault"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/shodan/connection"
	"go.mondoo.com/mql/providers/shodan/resources"
)

const (
	DefaultConnectionType = "shodan"
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

	// Do custom flag parsing here
	token := ""
	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		token = string(x.Value)
	}
	if token == "" {
		token = os.Getenv("SHODAN_TOKEN")
	}
	if token != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))
	}

	// discovery flags
	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			entry := string(x.Array[i].Value)
			discoverTargets = append(discoverTargets, entry)
		}
	} else {
		discoverTargets = []string{"auto"}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	// shodan also supports the following sub-commands, those are optional
	name := ""
	if len(req.Args) > 0 {
		switch req.Args[0] {
		case "host", "domain":
			if len(req.Args) < 2 {
				return nil, errors.New("the Shodan " + req.Args[0] + " sub-command requires a target, for example `shodan " + req.Args[0] + " example.com`")
			}
			conf.Host = req.Args[1]
			conf.Options["search"] = req.Args[0]
		default:
			return nil, errors.New("invalid Shodan sub-command, supported are: host or domain")
		}
	} else {
		name = "Shodan"
	}

	if networks, ok := flags["networks"]; ok {
		if networks.Array != nil {
			networksValues := []string{}
			for _, network := range networks.Array {
				networksValues = append(networksValues, string(network.Value))
			}

			conf.Options["networks"] = strings.Join(networksValues, ",")
		}
	}

	asset := inventory.Asset{
		Name:        name,
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ShodanConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.ShodanConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewShodanConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.ShodanConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.ShodanConnection) error {
	asset.Id = conn.Conf.Type
	// Only name an asset that has no name: a caller who passed --asset-name (or
	// named the asset in an inventory file) has already named it, and detection
	// must not take that back. The account-level asset has no host to be named
	// after, so it gets a readable default instead of "".
	if asset.Name == "" {
		asset.Name = conn.Conf.Host
	}
	if asset.Name == "" {
		asset.Name = "Shodan"
	}

	platform, err := conn.PlatformInfo()
	if err != nil {
		return err
	}

	asset.Platform = platform
	asset.PlatformIds = []string{conn.Identifier()}
	return nil
}

func (s *Service) discover(conn *connection.ShodanConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime, conf.Options)
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
