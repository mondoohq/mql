// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/providers/gcp/connection/gcpinstancesnapshot"
	"go.mondoo.com/mql/providers/gcp/connection/shared"
	"go.mondoo.com/mql/providers/gcp/resources"
)

const ConnectionType = "gcp"

var (
	cacheExpirationTime = 3 * time.Hour
	cacheCleanupTime    = 6 * time.Hour
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		plugin.NewService(),
	}
}

// returns only the env vars that have a set value
func readEnvs(envs ...string) []string {
	vals := []string{}
	for i := range envs {
		val := os.Getenv(envs[i])
		if val != "" {
			vals = append(vals, val)
		}
	}

	return vals
}

// to be used by gcp/googleworkspace cmds, fetches the creds from either the env vars provided or from a flag in the provided cmd
func getGoogleCreds(credentialPath string, envs ...string) []byte {
	var credsPaths []string
	// env vars have precedence over the --credentials-path arg
	credsPaths = readEnvs(envs...)

	if credentialPath != "" {
		credsPaths = append(credsPaths, credentialPath)
	}

	for i := range credsPaths {
		path := credsPaths[i]

		serviceAccount, err := os.ReadFile(path)
		if err == nil {
			return serviceAccount
		}
	}
	return nil
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	if len(req.Args) != 2 {
		return nil, status.Error(codes.InvalidArgument, "missing argument, use `gcp project id`, `gcp organization id`, `gcp folder id`, `gcp instance name`, or `gcp snapshot name`")
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Options: map[string]string{},
	}

	// custom flag parsing
	var credentialsPath string
	if x, ok := flags["credentials-path"]; ok && len(x.Value) != 0 {
		credentialsPath = string(x.Value)
	}

	// used for snapshot and instance sub-commands
	var projectId string
	if x, ok := flags["project-id"]; ok && len(x.Value) != 0 {
		projectId = string(x.Value)
	}

	var zone string
	if x, ok := flags["zone"]; ok && len(x.Value) != 0 {
		zone = string(x.Value)
	}
	// ^^ snapshot and instance flags

	// these flags are currently only used for the instance sub-command
	var createSnapshot string
	if x, ok := flags["create-snapshot"]; ok && len(x.Value) != 0 {
		createSnapshot = string(x.Value)
	}
	// ^^ instance flags

	envVars := []string{
		"GOOGLE_APPLICATION_CREDENTIALS",
		"GOOGLE_CREDENTIALS",
		"GOOGLE_CLOUD_KEYFILE_JSON",
		"GCLOUD_KEYFILE_JSON",
	}
	serviceAccount := getGoogleCreds(credentialsPath, envVars...)
	if serviceAccount != nil {
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:   vault.CredentialType_json,
			Secret: serviceAccount,
		})
	}

	// parse discovery flags
	conf.Discover = &inventory.Discovery{
		Targets: []string{},
	}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			entry := string(x.Array[i].Value)
			conf.Discover.Targets = append(conf.Discover.Targets, entry)
		}
	} else {
		conf.Discover.Targets = []string{resources.DiscoveryAuto}
	}
	conf.Discover.Filter = parseFlagsToFiltersOpts(flags)

	switch req.Args[0] {
	case "org", "organization":
		conf.Options["organization-id"] = req.Args[1]
	case "project":
		conf.Options["project-id"] = req.Args[1]
	case "folder":
		conf.Options["folder-id"] = req.Args[1]
	case "gcr":
		conf.Options["project-id"] = req.Args[1]
		conf.Options["repository"] = string(flags["repository"].Value)
		conf.Runtime = "gcp-gcr"
	case "snapshot":
		if err := validateSnapshotTarget(projectId); err != nil {
			return nil, err
		}
		conf.Options["snapshot-name"] = req.Args[1]
		conf.Options["project-id"] = projectId
		conf.Options["zone"] = zone
		conf.Options["type"] = "snapshot"
		conf.Type = string(gcpinstancesnapshot.SnapshotConnectionType)
		conf.Discover = nil
	case "instance":
		if err := validateInstanceTarget(projectId, zone); err != nil {
			return nil, err
		}
		conf.Options["instance-name"] = req.Args[1]
		conf.Options["type"] = "instance"
		conf.Options["project-id"] = projectId
		conf.Options["zone"] = zone
		conf.Options["create-snapshot"] = createSnapshot
		conf.Type = string(gcpinstancesnapshot.SnapshotConnectionType)
		conf.Discover = nil
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// parseFlagsToFiltersOpts extracts the known discovery filter keys from the
// --filters key/value flag. Only recognized prefixes are passed through so that
// unknown keys don't silently leak into the discovery config.
func parseFlagsToFiltersOpts(m map[string]*llx.Primitive) map[string]string {
	o := map[string]string{}

	x, ok := m["filters"]
	if !ok || len(x.Map) == 0 {
		return o
	}

	knownKeys := []string{
		// storage filters
		"storage:bucket-names",
		"storage:exclude:bucket-names",
		// project-level filters
		"propagate-project-labels",
	}
	for k, v := range x.Map {
		if slices.Contains(knownKeys, k) {
			o[k] = string(v.Value)
		}
	}

	return o
}

// validateInstanceTarget ensures the required flags for instance scanning are
// present. Both project-id and zone are needed to locate the instance.
func validateInstanceTarget(projectId, zone string) error {
	var missing []string
	if projectId == "" {
		missing = append(missing, "--project-id")
	}
	if zone == "" {
		missing = append(missing, "--zone")
	}
	if len(missing) > 0 {
		return status.Errorf(codes.InvalidArgument, "the %s flag(s) are required for gcp instance scanning", strings.Join(missing, " and "))
	}
	return nil
}

// validateSnapshotTarget ensures the required flags for snapshot scanning are
// present. The project-id is needed to locate the snapshot.
func validateSnapshotTarget(projectId string) error {
	if projectId == "" {
		return status.Error(codes.InvalidArgument, "the --project-id flag is required for gcp snapshot scanning")
	}
	return nil
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

	var inventory *inventory.Inventory
	// discovery assets for further scanning
	if conn.Config().Discover != nil {
		// detection of the platform is done in the discovery phase
		inventory, err = s.discover(conn)
		if err != nil {
			return nil, err
		}
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inventory,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (shared.GcpConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn shared.GcpConnection
		var err error

		switch conf.Type {
		case string(gcpinstancesnapshot.SnapshotConnectionType):
			// A GcpSnapshotConnection is a wrapper around a FilesystemConnection
			// To make sure the connection is later handled by the os provider, override the type
			conf.Type = "filesystem"
			conn, err = gcpinstancesnapshot.NewGcpSnapshotConnection(connId, conf, asset)
		default:
			conn, err = connection.NewGcpConnection(connId, asset, conf)
		}

		if err != nil {
			return nil, err
		}

		// verify the connection only once
		_, _, err = s.Memoize(fmt.Sprintf("conn_%d", conn.Hash()), func() (any, error) {
			log.Trace().Str("type", string(conn.Type())).Msg("verifying connection client")
			return nil, conn.Verify()
		})
		if err != nil {
			return nil, err
		}

		var upstreamClient *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			data, _, err := s.Memoize(
				fmt.Sprintf("upstream_%d", req.Upstream.Hash()), func() (any, error) {
					return req.Upstream.InitClient(context.Background())
				})
			if err != nil {
				return nil, err
			}
			upstreamClient = data.(*upstream.UpstreamClient)
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

	return runtime.Connection.(shared.GcpConnection), nil
}

func (s *Service) discover(conn shared.GcpConnection) (*inventory.Inventory, error) {
	if conn.Config().Discover == nil {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime)
}
