// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"net/http"
	"os"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// apiBaseURL is the root of the Neon API, including the version prefix every
// documented endpoint is served under.
const apiBaseURL = "https://console.neon.tech/api/v2"

type NeonConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	token   string
	baseURL string
	client  *http.Client
}

func NewNeonConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NeonConnection, error) {
	conn := &NeonConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		baseURL:    apiBaseURL,
		client:     &http.Client{Timeout: 60 * time.Second},
	}

	token := os.Getenv("NEON_API_KEY")
	if token == "" {
		token = os.Getenv("NEON_TOKEN")
	}
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			token = string(cred.Secret)
		}
	}
	if token == "" {
		return nil, errors.New("a valid Neon API key is required (set NEON_API_KEY or use --token)")
	}
	conn.token = token

	return conn, nil
}

func (c *NeonConnection) Name() string {
	return "neon"
}

func (c *NeonConnection) Asset() *inventory.Asset {
	return c.asset
}

// OrganizationFilter returns the organization the connection is scoped to,
// either from the --organization flag or from a discovered child asset. It is
// the empty string when every organization the key can reach is in scope.
func (c *NeonConnection) OrganizationFilter() string {
	if org := c.option("orgId"); org != "" {
		return org
	}
	return c.option("organization")
}

// ProjectFilter returns the project a discovered project asset is scoped to, or
// the empty string when every project of the organizations in scope is in
// scope.
func (c *NeonConnection) ProjectFilter() string {
	return c.option("projectId")
}

func (c *NeonConnection) option(key string) string {
	if c.Conf == nil || c.Conf.Options == nil {
		return ""
	}
	return c.Conf.Options[key]
}
