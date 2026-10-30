// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"fmt"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
	"go.mondoo.com/mql/providers/proxmox/resources"
)

const ProviderName = "proxmox"

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil || len(req.Asset.Connections) == 0 {
		return nil, fmt.Errorf("no connection configuration provided")
	}

	conf := req.Asset.Connections[0]

	host := conf.Options["host"]
	token := conf.Options["token"]

	// cnspec sets insecure in two places:
	// - conf.Insecure: set internally by cnspec via the --insecure flag
	// - conf.Options["insecure"]: set by ParseCLI
	insecure, _ := strconv.ParseBool(conf.Options["insecure"])
	insecure = insecure || conf.Insecure

	if host == "" {
		return nil, fmt.Errorf("--host is required (e.g. https://192.168.1.10:8006)")
	}
	if token == "" {
		return nil, fmt.Errorf("--token is required (format: PVEAPIToken=user@realm!id=secret)")
	}

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn := connection.NewConnection(connId, host, token, insecure)
		if err := conn.Verify(); err != nil {
			return nil, fmt.Errorf("proxmox connection failed: %w", err)
		}

		if req.Asset.Name == "" {
			req.Asset.Name = host
		}

		req.Asset.Platform = &inventory.Platform{}
		if pi, ok := connection.PlatformByName("proxmox"); ok {
			pi.Apply(req.Asset.Platform)
		}

		req.Asset.PlatformIds = []string{
			"//platformid.api.mondoo.com/runtime/proxmox/host/" + host,
		}

		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			nil,
		), nil
	})
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:    runtime.Connection.ID(),
		Asset: req.Asset,
	}, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return s.Connect(req, callback)
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	host := ""
	if x, ok := flags["host"]; ok {
		host = string(x.Value)
	}
	token := ""
	if x, ok := flags["token"]; ok {
		token = string(x.Value)
	}

	// Bool primitives are encoded as []byte{1} (true) or []byte{0} (false),
	// not as a string — use RawData() instead of strconv.ParseBool
	insecure := false
	if x, ok := flags["insecure"]; ok {
		raw := x.RawData()
		if v, ok := raw.Value.(bool); ok {
			insecure = v
		}
	}

	conf := &inventory.Config{
		Type:     ProviderName,
		Insecure: insecure,
		Options: map[string]string{
			"host":  host,
			"token": token,
		},
	}

	return &plugin.ParseCLIRes{
		Asset: &inventory.Asset{
			Name:        host,
			Connections: []*inventory.Config{conf},
		},
	}, nil
}
