// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/bndr/gojenkins"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
)

// Flag Options
const (
	OPTION_URL   = "url"
	OPTION_USER  = "user"
	OPTION_TOKEN = "token"
)

// Jenkins environment variables
const (
	JENKINS_URL_VAR   = "JENKINS_URL"
	JENKINS_USER_VAR  = "JENKINS_USER"
	JENKINS_TOKEN_VAR = "JENKINS_TOKEN"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/jenkins.json so the CLI and generated docs can
// list what the provider supports. Add an entry here for every platform your
// asset discovery produces.
var Platforms = []*plugin.PlatformInfo{
	{Name: "jenkins", Title: "Jenkins", Family: []string{"jenkins"}, Kind: []string{"api"}, Runtime: []string{"jenkins"}},
}

type JenkinsConnection struct {
	plugin.Connection
	Conf    *inventory.Config
	asset   *inventory.Asset
	baseUrl string
	client  *gojenkins.Jenkins

	nodesOnce sync.Once
	nodes     any
	nodesErr  error
}

func NewJenkinsConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*JenkinsConnection, error) {
	conn := &JenkinsConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	baseUrl := conf.Host
	if baseUrl == "" {
		baseUrl = os.Getenv(JENKINS_URL_VAR)
	}
	if conf.Options != nil && conf.Options[OPTION_URL] != "" {
		baseUrl = conf.Options[OPTION_URL]
	}
	if baseUrl == "" {
		return nil, errors.New("a Jenkins base URL is required, pass --url 'https://jenkins.example.com' or set JENKINS_URL")
	}
	baseUrl = strings.TrimRight(baseUrl, "/")

	user := os.Getenv(JENKINS_USER_VAR)
	token := os.Getenv(JENKINS_TOKEN_VAR)
	if conf.Options != nil && conf.Options[OPTION_USER] != "" {
		user = conf.Options[OPTION_USER]
	}
	for i := range conf.Credentials {
		cred := conf.Credentials[i]
		switch cred.Type {
		case vault.CredentialType_password:
			if cred.User != "" {
				user = cred.User
			}
			token = string(cred.Secret)
		default:
			log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Jenkins provider")
		}
	}
	if user == "" || token == "" {
		return nil, errors.New("a Jenkins username and API token are required, pass --user/--token or set JENKINS_USER/JENKINS_TOKEN")
	}

	client, err := gojenkins.CreateJenkins(nil, baseUrl, user, token).Init(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to Jenkins at "+baseUrl)
	}

	conn.baseUrl = baseUrl
	conn.client = client

	return conn, nil
}

func (c *JenkinsConnection) Name() string {
	return "jenkins"
}

func (c *JenkinsConnection) Asset() *inventory.Asset {
	return c.asset
}

// BaseUrl returns the Jenkins base URL this connection targets.
func (c *JenkinsConnection) BaseUrl() string {
	return c.baseUrl
}

// Client returns the authenticated gojenkins client.
func (c *JenkinsConnection) Client() *gojenkins.Jenkins {
	return c.client
}

// CachedNodes returns the controller's node list, fetching it at most once per
// connection via fetch and memoizing the result (including an error). It lets
// many job.node resolutions share a single /computer read instead of paying
// one fetch each.
func (c *JenkinsConnection) CachedNodes(fetch func() (any, error)) (any, error) {
	c.nodesOnce.Do(func() {
		c.nodes, c.nodesErr = fetch()
	})
	return c.nodes, c.nodesErr
}
