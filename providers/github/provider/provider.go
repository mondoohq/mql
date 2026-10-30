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
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/providers/github/resources"
)

const ConnectionType = "github"

var (
	cacheExpirationTime = 24 * time.Hour
	cacheCleanupTime    = 48 * time.Hour
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	if len(req.Args) == 0 {
		return nil, errors.New("invalid. must specify org, repo, or user")
	}

	conf := &inventory.Config{
		Type:     req.Connector,
		Options:  map[string]string{},
		Discover: &inventory.Discovery{},
	}

	if x, ok := flags["enterprise-url"]; ok && len(x.Value) != 0 {
		conf.Options[connection.OPTION_ENTERPRISE_URL] = string(x.Value)
	}

	// Github provide has two authentication methods.
	//
	// 1. Application credentials
	// 2. Personal access token
	//
	// We give precedence to the former and, if both auth methods are provided,
	// we will output a warning.
	isAppAuth := false
	appId, ok := flags[connection.OPTION_APP_ID]
	if ok && len(appId.Value) > 0 {
		conf.Options[connection.OPTION_APP_ID] = string(appId.Value)

		installId := req.Flags[connection.OPTION_APP_INSTALLATION_ID]
		conf.Options[connection.OPTION_APP_INSTALLATION_ID] = string(installId.Value)

		// The GitHub App private key may be provided three ways: as a file path
		// (--app-private-key), as inline PEM content (--app-private-key-content),
		// or via the GITHUB_APP_PRIVATE_KEY environment variable. Inline content
		// takes precedence and is passed as a private_key credential so the
		// connection can authenticate without reading from the filesystem.
		appPrivateKey := ""
		if x, ok := flags[connection.OPTION_APP_PRIVATE_KEY_CONTENT]; ok && len(x.Value) != 0 {
			appPrivateKey = string(x.Value)
			log.Debug().Msg("loaded GitHub App private key from flag")
		}
		if appPrivateKey == "" && len(os.Getenv("GITHUB_APP_PRIVATE_KEY")) != 0 {
			appPrivateKey = os.Getenv("GITHUB_APP_PRIVATE_KEY")
			log.Debug().Msg("loaded GitHub App private key from GITHUB_APP_PRIVATE_KEY env variable")
		}
		if appPrivateKey != "" {
			conf.Credentials = append(conf.Credentials,
				vault.NewPrivateKeyCredential("", []byte(appPrivateKey), ""))
		} else if pk, ok := flags[connection.OPTION_APP_PRIVATE_KEY]; ok && len(pk.Value) != 0 {
			conf.Options[connection.OPTION_APP_PRIVATE_KEY] = string(pk.Value)
		}

		isAppAuth = true
		log.Debug().Msg("application credentials provided")
	}

	token := ""
	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		token = string(x.Value)
		log.Debug().Msg("loaded token from flag")
	}
	if token == "" && len(os.Getenv("GITHUB_TOKEN")) != 0 {
		token = os.Getenv("GITHUB_TOKEN")
		log.Debug().Msg("loaded token from GITHUB_TOKEN env variable")
	}
	if token == "" && !isAppAuth {
		return nil, errors.New("a valid GitHub authentication is required, pass --token '<yourtoken>', " +
			"set GITHUB_TOKEN environment variable or provide GitHub App credentials")
	}
	if token != "" {
		if isAppAuth {
			log.Warn().Msg("both authentication methods provided, using application credentials")
		} else {
			conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))
		}
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

	// Do custom flag parsing here
	switch req.Args[0] {
	case "org":
		conf.Options["organization"] = req.Args[1]
	case "user":
		conf.Options["user"] = req.Args[1]
	case "repo":
		conf.Options["repository"] = req.Args[1]
	default:
		return nil, errors.New("invalid GitHub sub-command, supported are: org, user, or repo")
	}

	if repos, ok := req.Flags[connection.OPTION_REPOS]; ok {
		conf.Options[connection.OPTION_REPOS] = string(repos.Value)
	}

	if repos, ok := req.Flags[connection.OPTION_REPOS_EXCLUDE]; ok {
		conf.Options[connection.OPTION_REPOS_EXCLUDE] = string(repos.Value)
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

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.GithubConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	runtime, err := s.AddRuntime(asset.Connections[0], func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewGithubConnection(connId, asset)
		if err != nil {
			return nil, err
		}

		// verify the connection only once
		_, _, err = s.Memoize(fmt.Sprintf("conn_%d", conn.OptionsHash), func() (any, error) {
			log.Debug().Msg("verifying github connection client")
			err := conn.Verify()
			return nil, err
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

	return runtime.Connection.(*connection.GithubConnection), err
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.GithubConnection) error {
	defer logger.FuncDur(time.Now(), "provider.github.service.detect")

	conf := asset.Connections[0]
	asset.Name = conf.Host

	repoOpt := conf.Options["repository"]
	ownerOpt := conf.Options["owner"]
	// try and parse the repo only if the owner isn't explicitly set
	if repoOpt != "" && ownerOpt == "" {
		repoParts := strings.Split(repoOpt, "/")
		if len(repoParts) > 1 {
			conf.Options["owner"] = repoParts[0]
			conf.Options["repository"] = repoParts[1]
		}
	}

	platform, err := conn.PlatformInfo()
	if err != nil {
		return err
	}

	asset.Platform = platform
	return nil
}

func (s *Service) discover(conn *connection.GithubConnection) (*inventory.Inventory, error) {
	defer logger.FuncDur(time.Now(), "provider.github.service.discover")

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
