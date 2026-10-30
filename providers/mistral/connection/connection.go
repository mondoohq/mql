// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"os"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/mistral/internal/mistralai"
)

const (
	OptionToken     = "token"
	OptionBaseURL   = "base-url"
	OptionWorkspace = "workspace"
)

type MistralConnection struct {
	plugin.Connection
	Conf      *inventory.Config
	asset     *inventory.Asset
	client    *mistralai.Client
	token     string
	workspace string
}

func NewMistralConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*MistralConnection, error) {
	token := tokenFromConfig(conf)
	if token == "" {
		return nil, fmt.Errorf("mistral: API key is required (use --token or set MISTRAL_API_KEY)")
	}

	var opts []mistralai.ClientOption
	if conf.Options != nil {
		if raw := strings.TrimSpace(conf.Options[OptionBaseURL]); raw != "" {
			opts = append(opts, mistralai.WithBaseURL(raw))
		}
	}

	client := mistralai.NewClient(token, opts...)

	var workspace string
	if conf.Options != nil {
		workspace = strings.TrimSpace(conf.Options[OptionWorkspace])
	}

	conn := &MistralConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		token:      token,
		workspace:  workspace,
	}

	return conn, nil
}

func (c *MistralConnection) Name() string {
	return "mistral"
}

func (c *MistralConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *MistralConnection) Client() *mistralai.Client {
	return c.client
}

func (c *MistralConnection) Workspace() string {
	return c.workspace
}

func tokenFromConfig(conf *inventory.Config) string {
	token := os.Getenv("MISTRAL_API_KEY")
	if token == "" {
		token = os.Getenv("MISTRAL_KEY")
	}
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
