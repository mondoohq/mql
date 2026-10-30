// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"os"
	"strings"

	together "github.com/togethercomputer/together-go"
	"github.com/togethercomputer/together-go/option"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	OptionToken   = "token"
	OptionBaseURL = "base-url"
	OptionProject = "project"
)

type TogetherConnection struct {
	plugin.Connection
	Conf    *inventory.Config
	asset   *inventory.Asset
	client  together.Client
	token   string
	project string
}

func NewTogetherConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*TogetherConnection, error) {
	token := tokenFromConfig(conf)
	if token == "" {
		return nil, fmt.Errorf("together: API token is required (use --token or set TOGETHER_API_KEY)")
	}

	opts := []option.RequestOption{
		option.WithAPIKey(token),
	}

	if conf.Options != nil {
		if raw := strings.TrimSpace(conf.Options[OptionBaseURL]); raw != "" {
			opts = append(opts, option.WithBaseURL(normalizeBaseURL(raw)))
		}
	}

	client := together.NewClient(opts...)

	var project string
	if conf.Options != nil {
		project = strings.TrimSpace(conf.Options[OptionProject])
	}

	conn := &TogetherConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		token:      token,
		project:    project,
	}

	return conn, nil
}

func (c *TogetherConnection) Name() string {
	return "together"
}

func (c *TogetherConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *TogetherConnection) Client() *together.Client {
	return &c.client
}

func (c *TogetherConnection) Token() string {
	return c.token
}

func (c *TogetherConnection) Project() string {
	return c.project
}

func tokenFromConfig(conf *inventory.Config) string {
	token := os.Getenv("TOGETHER_API_KEY")
	if conf.Options != nil && conf.Options[OptionToken] != "" {
		token = conf.Options[OptionToken]
	}
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			token = string(cred.Secret)
		}
	}
	return strings.TrimSpace(token)
}

// normalizeBaseURL turns a --base-url value into the API root together-go
// expects. Up to together-go v0.12 the client's base URL included the /v1
// version segment and request paths were relative to it; from v0.13 the base
// URL is the API root and every path carries its own version (v1/files,
// v2/projects/..., v3/whoami). A base URL ending in /v1, as documented for this
// flag until now, is cut back to the root so existing configurations keep
// working.
func normalizeBaseURL(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	u = strings.TrimSuffix(u, "/v1")
	return u + "/"
}
