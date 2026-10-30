// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/providers/google-workspace/resources"
)

const ConnectionType = "google-workspace"

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
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
func getGoogleCreds(credentialPath string, envs ...string) ([]byte, error) {
	var credsPaths []string
	// env vars have precedence over the --credentials-path arg
	credsPaths = readEnvs(envs...)

	errs := []error{}
	if credentialPath != "" {
		credsPaths = append(credsPaths, credentialPath)
	}

	for _, path := range credsPaths {
		serviceAccount, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
		} else {
			return serviceAccount, nil
		}
	}
	return nil, errors.Join(errs...)
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
	missingCliFlags := false

	var credentialsPath string
	if x, ok := flags["credentials-path"]; ok && len(x.Value) != 0 {
		credentialsPath = string(x.Value)
	}

	envVars := []string{
		"GOOGLE_APPLICATION_CREDENTIALS",
		"GOOGLEWORKSPACE_CREDENTIALS",
		"GOOGLEWORKSPACE_CLOUD_KEYFILE_JSON",
		"GOOGLE_CREDENTIALS",
	}
	serviceAccount, err := getGoogleCreds(credentialsPath, envVars...)
	if err != nil {
		log.Error().Err(err).Msg("could not read service account credentials")
		return nil, err
	}
	if serviceAccount != nil {
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:   vault.CredentialType_json,
			Secret: serviceAccount,
		})
	}
	if len(conf.Credentials) == 0 {
		log.Error().Msg("google workspace provider requires a service account. please set option `credentials-path`")
		missingCliFlags = true
	}

	if x, ok := flags["customer-id"]; ok && len(x.Value) != 0 {
		conf.Options["customer-id"] = string(x.Value)
	} else {
		log.Error().Msg("google workspace provider requires an customer id. please set option `customer-id`")
		missingCliFlags = true
	}

	if x, ok := flags["impersonated-user-email"]; ok && len(x.Value) != 0 {
		conf.Options["impersonated-user-email"] = string(x.Value)
	} else {
		log.Error().Msg("google workspace provider requires an impersonated user email. please set option `impersonated-user-email`")
		missingCliFlags = true
	}

	if missingCliFlags {
		return nil, errors.New("missing required flags")
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
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

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: nil,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.GoogleWorkspaceConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewGoogleWorkspaceConnection(connId, asset, conf)
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
	return runtime.Connection.(*connection.GoogleWorkspaceConnection), err
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.GoogleWorkspaceConnection) error {
	pd, err := resources.GetPrimaryDomain(conn)
	if err != nil {
		log.Error().Err(err).Msg("could not get primary domain for google workspace")
		asset.Name = fmt.Sprintf("Google Workspace (%s)", conn.CustomerID())
	} else {
		asset.Name = fmt.Sprintf("Google Workspace %s (%s)", pd, conn.CustomerID())
	}
	platform := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "google-workspace", conn.CustomerID()},
	}
	if pi, ok := PlatformByName("google-workspace"); ok {
		pi.Apply(platform)
	}
	asset.Platform = platform

	asset.PlatformIds = []string{"//platformid.api.mondoo.app/runtime/googleworkspace/customer/" + conn.CustomerID()}
	return nil
}
