// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"go.mondoo.com/mql/providers/artifactory/resources"
)

const DefaultConnectionType = "artifactory"

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

	rawURL := flagValue(flags, "url")
	// A bare argument is the URL, so `mql shell artifactory https://example.jfrog.io`
	// works as well as the flag.
	if rawURL == "" && len(req.Args) > 0 {
		rawURL = req.Args[0]
	}
	if rawURL == "" {
		rawURL = os.Getenv("ARTIFACTORY_URL")
	}
	if rawURL == "" {
		rawURL = os.Getenv("JFROG_URL")
	}
	if rawURL != "" {
		conf.Options[connection.OptionURL] = rawURL
	}

	token := flagValue(flags, "token")
	if token == "" {
		token = os.Getenv("ARTIFACTORY_TOKEN")
	}
	if token == "" {
		token = os.Getenv("JFROG_ACCESS_TOKEN")
	}
	if token != "" {
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:   vault.CredentialType_bearer,
			Secret: []byte(token),
		})
	}

	apiKey := flagValue(flags, "api-key")
	if apiKey == "" {
		apiKey = os.Getenv("ARTIFACTORY_API_KEY")
	}
	if apiKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func flagValue(flags map[string]*llx.Primitive, name string) string {
	if x, ok := flags[name]; ok && len(x.Value) != 0 {
		return strings.TrimSpace(string(x.Value))
	}
	return ""
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
		Id:    conn.ID(),
		Name:  conn.Name(),
		Asset: req.Asset,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ArtifactoryConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewArtifactoryConnection(connId, asset, conf)
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

	return runtime.Connection.(*connection.ArtifactoryConnection), nil
}

// detect names the asset after the instance and stamps its platform. The
// service identifier is the instance's own stable name, so it survives a URL
// change. An instance that does not report one falls back to the host, which
// keeps the scan usable rather than failing on an identity read.
func (s *Service) detect(asset *inventory.Asset, conn *connection.ArtifactoryConnection) error {
	info := resources.FetchSystemInfo(context.Background(), conn)

	instanceID := info.ServiceID
	if instanceID == "" {
		instanceID = conn.Host()
	}

	asset.Id = conn.Name()
	asset.Name = conn.Host()
	asset.Platform = connection.NewArtifactoryPlatform(instanceID, info.Version)
	asset.PlatformIds = []string{connection.NewArtifactoryIdentifier(instanceID)}
	return nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}
