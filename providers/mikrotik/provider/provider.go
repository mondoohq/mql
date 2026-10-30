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
	"go.mondoo.com/mql/providers/mikrotik/connection"
	"go.mondoo.com/mql/providers/mikrotik/resources"
)

const (
	DefaultConnectionType = "mikrotik"
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

	// parse the target, e.g. admin@192.168.88.1:8728
	user := ""
	if len(req.Args) != 0 {
		target := req.Args[0]
		if !strings.Contains(target, "://") {
			target = "scheme://" + target
		}
		x, err := url.Parse(target)
		if err != nil {
			return nil, errors.New("incorrect format of target, please use user@host[:port]")
		}
		user = x.User.Username()
		conf.Host = x.Hostname()
		if sPort := x.Port(); sPort != "" {
			// parse with an explicit 32-bit size so the int32 conversion below
			// is provably in range (also satisfies the CodeQL conversion check)
			port, err := strconv.ParseInt(sPort, 10, 32)
			if err != nil {
				return nil, errors.New("port '" + sPort + "' is incorrectly formatted, must be a number")
			}
			if port < 1 || port > 65535 {
				return nil, errors.New("port '" + sPort + "' is out of range, must be between 1 and 65535")
			}
			conf.Port = int32(port)
		}
	}

	// the --tls and --insecure flags carry no string value, so read them as bools
	if x, ok := flags["tls"]; ok {
		if v, ok := x.RawData().Value.(bool); ok && v {
			conf.Options["tls"] = "true"
		}
	}
	if x, ok := flags["insecure"]; ok {
		if v, ok := x.RawData().Value.(bool); ok {
			conf.Insecure = v
		}
	}
	if x, ok := flags["port"]; ok && len(x.Value) != 0 {
		conf.Options["port"] = string(x.Value)
	}

	if x, ok := flags["password"]; ok && len(x.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, string(x.Value)))
	} else if user != "" {
		// Preserve the user even when no password was supplied on the CLI: the
		// secret may be filled in later from a vault, or the --ask-pass flag
		// (handled by the CLI framework) may prompt for it before Connect.
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, ""))
	}

	asset := inventory.Asset{
		Name:        conf.Host,
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.MikrotikConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewMikrotikConnection(connId, asset, conf)
		if err != nil {
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

	return runtime.Connection.(*connection.MikrotikConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.MikrotikConnection) error {
	identity, _ := conn.PrintOne("/system/identity")
	resource, _ := conn.PrintOne("/system/resource")
	routerboard, _ := conn.PrintOne("/system/routerboard")

	name := identity["name"]
	if name == "" {
		name = conn.Conf.Host
	}
	asset.Name = name

	version := resource["version"]

	asset.Platform = &inventory.Platform{
		Version: version,
		Labels:  map[string]string{},
	}
	if pi, ok := PlatformByName("mikrotik"); ok {
		pi.Apply(asset.Platform)
	}
	if board := resource["board-name"]; board != "" {
		asset.Platform.Labels["mikrotik.com/board-name"] = board
	}
	if arch := resource["architecture-name"]; arch != "" {
		asset.Platform.Arch = arch
	}

	// prefer the RouterBOARD serial number for a stable platform id; fall back
	// to the host when it is unavailable (e.g. CHR / x86 instances)
	serial := routerboard["serial-number"]
	if serial != "" {
		asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/mikrotik/serial/" + serial}
	} else {
		asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/mikrotik/host/" + conn.Conf.Host}
	}

	asset.Id = conn.Conf.Type
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
