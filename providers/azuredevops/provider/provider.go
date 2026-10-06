// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/resources"
)

const (
	ConnectionType = "azuredevops"

	envToken        = "AZURE_DEVOPS_TOKEN"
	envClientSecret = "AZURE_CLIENT_SECRET"
	envTenantID     = "AZURE_TENANT_ID"
	envClientID     = "AZURE_CLIENT_ID"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

// flagString is the value of a string flag, or "" when it is not set.
func flagString(flags map[string]*llx.Primitive, name string) string {
	if x, ok := flags[name]; ok && x != nil && len(x.Value) != 0 {
		return string(x.Value)
	}
	return ""
}

// firstNonEmpty is the flag value, or the environment variable when the flag is
// not set.
func firstNonEmpty(flag, env string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv(env)
}

// parseRepoArg splits "<org>/<project>/<repo>". Azure DevOps does not allow a
// slash in any of the three names, so the split is unambiguous.
func parseRepoArg(arg string) (org, project, repo string, err error) {
	parts := strings.Split(arg, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("invalid repository %q, use <organization>/<project>/<repository>", connection.RedactUserinfo(arg))
	}
	org, err = connection.ParseOrganization(parts[0])
	if err != nil {
		return "", "", "", err
	}
	return org, parts[1], parts[2], nil
}

// credentials decides how the scan authenticates.
//
//  1. A --tenant-id or --client-id flag means a Microsoft Entra service
//     principal.
//  2. Otherwise a personal access token, from --token or AZURE_DEVOPS_TOKEN.
//  3. Otherwise a service principal from AZURE_TENANT_ID, AZURE_CLIENT_ID and
//     AZURE_CLIENT_SECRET.
//
// The order keeps an AZURE_TENANT_ID that happens to be set in the environment
// from silently overriding a token the user passed.
func credentials(flags map[string]*llx.Primitive, conf *inventory.Config) error {
	tenantFlag := flagString(flags, "tenant-id")
	clientFlag := flagString(flags, "client-id")
	token := firstNonEmpty(flagString(flags, "token"), envToken)

	entra := tenantFlag != "" || clientFlag != ""
	if !entra && token == "" {
		entra = os.Getenv(envTenantID) != "" && os.Getenv(envClientID) != ""
	}

	if !entra {
		if token == "" {
			return errors.New("a valid Azure DevOps authentication is required, pass --token '<personal access token>', " +
				"set the " + envToken + " environment variable, or use a service principal with --tenant-id, --client-id and --client-secret")
		}
		log.Debug().Msg("using an Azure DevOps personal access token")
		if flagString(flags, "client-secret") != "" {
			log.Warn().Msg("--client-secret is ignored without --tenant-id and --client-id, using the personal access token")
		}
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))
		return nil
	}

	tenant := firstNonEmpty(tenantFlag, envTenantID)
	client := firstNonEmpty(clientFlag, envClientID)
	secret := firstNonEmpty(flagString(flags, "client-secret"), envClientSecret)
	if tenant == "" || client == "" {
		return errors.New("a service principal needs both --tenant-id and --client-id")
	}
	if secret == "" {
		return errors.New("a service principal needs its secret, pass --client-secret or set the " + envClientSecret + " environment variable")
	}
	if token != "" {
		log.Warn().Msg("both a personal access token and a service principal were provided, using the service principal")
	}
	conf.Options[connection.OPTION_TENANT_ID] = tenant
	conf.Options[connection.OPTION_CLIENT_ID] = client
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", secret))
	return nil
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	if len(req.Args) < 2 {
		return nil, errors.New("invalid. must specify org <organization> or repo <organization>/<project>/<repository>")
	}

	conf := &inventory.Config{
		Type:     req.Connector,
		Options:  map[string]string{},
		Discover: &inventory.Discovery{},
	}

	switch req.Args[0] {
	case "org":
		org, err := connection.ParseOrganization(req.Args[1])
		if err != nil {
			return nil, err
		}
		conf.Options[connection.OPTION_ORGANIZATION] = org
	case "repo":
		org, project, repo, err := parseRepoArg(req.Args[1])
		if err != nil {
			return nil, err
		}
		conf.Options[connection.OPTION_ORGANIZATION] = org
		conf.Options[connection.OPTION_PROJECT] = project
		conf.Options[connection.OPTION_REPOSITORY] = repo
	default:
		return nil, errors.New("invalid Azure DevOps sub-command, supported are: org or repo")
	}

	if err := credentials(flags, conf); err != nil {
		return nil, err
	}

	discoverTargets := []string{}
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		for i := range x.Array {
			discoverTargets = append(discoverTargets, string(x.Array[i].Value))
		}
	} else {
		discoverTargets = []string{connection.DiscoveryAuto}
	}
	conf.Discover = &inventory.Discovery{Targets: discoverTargets}

	if v := flagString(flags, connection.OPTION_REPOS); v != "" {
		conf.Options[connection.OPTION_REPOS] = v
	}
	if v := flagString(flags, connection.OPTION_REPOS_EXCLUDE); v != "" {
		conf.Options[connection.OPTION_REPOS_EXCLUDE] = v
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
		s.detect(req.Asset, conn)
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
		// Which kind this asset actually is; the static Root can only name one
		// for a provider serving several (ADR 031).
		Root: assetRoot(req.Asset.GetPlatform()),
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.AzuredevopsConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	runtime, err := s.AddRuntime(asset.Connections[0], func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewAzuredevopsConnection(connId, asset)
		if err != nil {
			return nil, err
		}

		// verify the connection only once
		_, _, err = s.Memoize(fmt.Sprintf("conn_%d", conn.OptionsHash), func() (any, error) {
			log.Debug().Msg("verifying azure devops connection")
			return nil, conn.Verify(context.Background())
		})
		if err != nil {
			return nil, err
		}

		// create an upstream client only once
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

		asset.Connections[0].Id = connId
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

	return runtime.Connection.(*connection.AzuredevopsConnection), nil
}

// detect names the asset after what the connection stands for. The platform id
// is left to discovery, which sets it on every asset it emits, as the GitHub
// provider does.
func (s *Service) detect(asset *inventory.Asset, conn *connection.AzuredevopsConnection) {
	if conn.IsRepository() {
		asset.Name = conn.Project() + "/" + conn.Repository()
	} else {
		asset.Name = conn.Organization()
	}
	asset.Platform = conn.PlatformInfo()
}

func (s *Service) discover(conn *connection.AzuredevopsConnection) (*inventory.Inventory, error) {
	defer logger.FuncDur(time.Now(), "provider.azuredevops.service.discover")

	// inventory.WithoutDiscovery leaves an empty Discovery rather than none, and
	// a connect made that way must not read anything.
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime)
}
