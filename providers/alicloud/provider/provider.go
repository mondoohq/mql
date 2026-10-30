// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"maps"
	"os"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/providers/alicloud/resources"
)

const (
	DefaultConnectionType = "alicloud"
)

// stringFlag reads a string CLI flag, falling back to the given environment
// variables in order.
func stringFlag(flags map[string]*llx.Primitive, name string, envs ...string) string {
	if x, ok := flags[name]; ok && len(x.Value) != 0 {
		return string(x.Value)
	}
	for _, e := range envs {
		if v := os.Getenv(e); v != "" {
			return v
		}
	}
	return ""
}

// filterOptPrefixes are the --filters keys the provider understands. Anything
// else is dropped rather than silently stored, so a typo surfaces as a filter
// that plainly did nothing instead of one that appears accepted.
var filterOptPrefixes = []string{
	"regions",
	"exclude:regions",
	"tag:",
	"exclude:tag:",
}

// parseFlagsToFiltersOpts flattens the --filters key-value flag into connection
// options the connection reads back through DiscoveryFiltersFromOpts.
func parseFlagsToFiltersOpts(flags map[string]*llx.Primitive) map[string]string {
	opts := map[string]string{}

	x, ok := flags["filters"]
	if !ok || len(x.Map) == 0 {
		return opts
	}
	for k, v := range x.Map {
		for _, prefix := range filterOptPrefixes {
			if strings.HasPrefix(k, prefix) {
				opts[k] = string(v.Value)
				break
			}
		}
	}
	return opts
}

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

	if v := stringFlag(flags, "access-key-id", "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY"); v != "" {
		conf.Options[connection.OptionAccessKeyID] = v
	}
	if v := stringFlag(flags, "region", "ALIBABA_CLOUD_REGION", "ALIBABA_CLOUD_REGION_ID"); v != "" {
		conf.Options[connection.OptionRegion] = v
	}
	if v := stringFlag(flags, "regions"); v != "" {
		conf.Options[connection.OptionRegions] = v
	}
	if v := stringFlag(flags, "role-arn"); v != "" {
		conf.Options[connection.OptionRoleArn] = v
	}
	if v := stringFlag(flags, "role-session-name"); v != "" {
		conf.Options[connection.OptionRoleSessionName] = v
	}

	// The access-key secret and STS token are secrets: carry them through the
	// credential vault rather than the plaintext options map. The connection
	// reads the STS token from the environment when a token flow is in use.
	secret := stringFlag(flags, "access-key-secret", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_SECRET_KEY")
	if secret != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", secret))
	}

	maps.Copy(conf.Options, parseFlagsToFiltersOpts(flags))

	discoverTargets := []string{resources.DiscoveryAuto}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		discoverTargets = discoverTargets[:0]
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.AlicloudConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn *connection.AlicloudConnection
		var err error

		switch conf.Type {
		default:
			conn, err = connection.NewAlicloudConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.AlicloudConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.AlicloudConnection) error {
	accountID, err := conn.Identify()
	if err != nil {
		return err
	}

	asset.Id = "alicloud/" + accountID
	asset.Name = "Alibaba Cloud account " + accountID
	asset.Platform = connection.NewAccountPlatform(accountID)
	asset.PlatformIds = []string{connection.NewAccountIdentifier(accountID)}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
