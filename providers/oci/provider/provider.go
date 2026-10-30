// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/providers/oci/resources"
)

const ConnectionType = "oci"

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
		Options: make(map[string]string),
	}

	// Do custom flag parsing here
	tenancy := ""
	if x, ok := flags["tenancy"]; ok && len(x.Value) != 0 {
		tenancy = string(x.Value)
	}

	user := ""
	if x, ok := flags["user"]; ok && len(x.Value) != 0 {
		user = string(x.Value)
	}

	region := ""
	if x, ok := flags["region"]; ok && len(x.Value) != 0 {
		region = string(x.Value)
	}

	keyPath := ""
	if x, ok := flags["key-path"]; ok && len(x.Value) != 0 {
		keyPath = string(x.Value)
	}

	fingerprint := ""
	if x, ok := flags["fingerprint"]; ok && len(x.Value) != 0 {
		fingerprint = string(x.Value)
	}

	keySecret := ""
	if x, ok := flags["key-secret"]; ok && len(x.Value) != 0 {
		keySecret = string(x.Value)
	}

	profile := ""
	if x, ok := flags["profile"]; ok && len(x.Value) != 0 {
		profile = string(x.Value)
	}

	configFile := ""
	if x, ok := flags["config-file"]; ok && len(x.Value) != 0 {
		configFile = string(x.Value)
	}

	authMethod := ""
	if x, ok := flags["auth-method"]; ok && len(x.Value) != 0 {
		authMethod = string(x.Value)
		if !slices.Contains(connection.SupportedAuthMethods, authMethod) {
			return nil, errors.New("unsupported --auth-method " + authMethod +
				"; supported methods are " + strings.Join(connection.SupportedAuthMethods, ", "))
		}
		conf.Options["auth-method"] = authMethod
	}

	if tenancy != "" {
		conf.Options["tenancy"] = tenancy
	}
	if fingerprint != "" {
		conf.Options["fingerprint"] = fingerprint
	}
	if region != "" {
		conf.Options["region"] = region
	}
	if user != "" {
		conf.Options["user"] = user
	}
	if profile != "" {
		conf.Options["profile"] = profile
	}
	if configFile != "" {
		conf.Options["config-file"] = configFile
	}

	if keyPath != "" {
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:           vault.CredentialType_private_key,
			PrivateKeyPath: keyPath,
			Password:       keySecret,
		})
	}

	maps.Copy(conf.Options, parseFilters(flags))

	conf.Discover = &inventory.Discovery{Targets: []string{}}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			conf.Discover.Targets = append(conf.Discover.Targets, string(x.Array[i].Value))
		}
	} else {
		conf.Discover.Targets = []string{resources.DiscoveryAuto}
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// filterKeyPrefixes is the set of --filters keys the provider understands.
//
// It has to be kept in step with connection.DiscoveryFiltersFromOpts: a key
// missing from this list never reaches the connection, so the flag parses
// cleanly, the scan runs, and the filter is simply not applied. Anything
// unrecognised is warned about rather than dropped in silence, because the
// failure is otherwise indistinguishable from a filter that matched everything.
var filterKeyPrefixes = []string{
	"regions",
	"exclude:regions",
	"compartments",
	"exclude:compartments",
	"tag:",
	"exclude:tag:",
}

// parseFilters pulls the recognised --filters entries out of the raw flags.
func parseFilters(flags map[string]*llx.Primitive) map[string]string {
	res := map[string]string{}

	x, ok := flags["filters"]
	if !ok || len(x.Map) == 0 {
		return res
	}

	for k, v := range x.Map {
		matched := false
		for _, prefix := range filterKeyPrefixes {
			if strings.HasPrefix(k, prefix) {
				res[k] = string(v.Value)
				matched = true
				break
			}
		}
		if !matched {
			log.Warn().Str("filter", k).Msg("oci: unknown --filters key; it will be ignored")
		}
	}

	return res
}

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

// discover runs the per-resource discovery pass when the connection config
// requests it. Returns nil inventory when discovery was not requested so the
// common "tenancy-only" scan path skips the extra work.
func (s *Service) discover(conn *connection.OciConnection) (*inventory.Inventory, error) {
	if conn.Conf == nil || len(conn.Conf.GetDiscover().GetTargets()) == 0 {
		return nil, nil
	}
	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}
	return resources.Discover(runtime)
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.OciConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewOciConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.OciConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.OciConnection) error {
	asset.Name = conn.Conf.Host

	info, err := conn.Tenant(context.Background())
	if err != nil {
		return err
	}
	// Tenant() returns a non-nil tenancy whenever err is nil, but Name is
	// optional on the SDK model and is absent for a tenancy with no display
	// name, so it needs its own guard.
	if info != nil && info.Name != nil {
		asset.Name = fmt.Sprintf("OCI Tenant %s", *info.Name)
	}

	asset.Platform = &inventory.Platform{
		TechnologyUrlSegments: []string{"oci", "tenancy"},
	}
	resources.PlatformByName("oci").Apply(asset.Platform)

	platformID := "//platformid.api.mondoo.app/runtime/oci/" + conn.TenantID()
	asset.PlatformIds = []string{platformID}
	return nil
}
