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

// apiBaseURL is the root of the Vercel REST API.
const apiBaseURL = "https://api.vercel.com"

type VercelConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	token   string
	baseURL string
	client  *http.Client
}

func NewVercelConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*VercelConnection, error) {
	conn := &VercelConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		baseURL:    apiBaseURL,
		client:     &http.Client{Timeout: 60 * time.Second},
	}

	token := os.Getenv("VERCEL_TOKEN")
	if token == "" {
		token = os.Getenv("VERCEL_API_TOKEN")
	}
	if len(conf.Credentials) > 0 {
		for _, cred := range conf.Credentials {
			if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
				token = string(cred.Secret)
			}
		}
	}
	if token == "" {
		return nil, errors.New("a valid Vercel token is required (set VERCEL_TOKEN or use --token)")
	}
	conn.token = token

	return conn, nil
}

func (c *VercelConnection) Name() string {
	return "vercel"
}

func (c *VercelConnection) Asset() *inventory.Asset {
	return c.asset
}

// TeamID returns the team the current asset is scoped to, or the empty string
// when the connection is not scoped to a specific team.
func (c *VercelConnection) TeamID() string {
	if c.Conf == nil || c.Conf.Options == nil {
		return ""
	}
	return c.Conf.Options["teamId"]
}

// ProjectID returns the project the current asset is scoped to, or the empty
// string when the connection is not scoped to a specific project.
func (c *VercelConnection) ProjectID() string {
	if c.Conf == nil || c.Conf.Options == nil {
		return ""
	}
	return c.Conf.Options["projectId"]
}
