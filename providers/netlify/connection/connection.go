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

// apiBaseURL is the root of the Netlify REST API, including the version prefix
// every documented endpoint is served under.
const apiBaseURL = "https://api.netlify.com/api/v1"

type NetlifyConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	token   string
	baseURL string
	client  *http.Client
}

func NewNetlifyConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NetlifyConnection, error) {
	conn := &NetlifyConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		baseURL:    apiBaseURL,
		client:     &http.Client{Timeout: 60 * time.Second},
	}

	token := os.Getenv("NETLIFY_AUTH_TOKEN")
	if token == "" {
		token = os.Getenv("NETLIFY_TOKEN")
	}
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			token = string(cred.Secret)
		}
	}
	if token == "" {
		return nil, errors.New("a valid Netlify token is required (set NETLIFY_AUTH_TOKEN or use --token)")
	}
	conn.token = token

	return conn, nil
}

func (c *NetlifyConnection) Name() string {
	return "netlify"
}

func (c *NetlifyConnection) Asset() *inventory.Asset {
	return c.asset
}

// AccountFilter returns the account the connection is scoped to, either from
// the --account flag or from the account of a discovered child asset. It is the
// empty string when every accessible account is in scope.
func (c *NetlifyConnection) AccountFilter() string {
	// A discovered child asset carries the account it was scoped to under
	// accountId, while the --account flag arrives as account. Reading only the
	// flag would leave every discovered asset unscoped, so each one would
	// report every account the token can reach rather than its own.
	if account := c.option("accountId"); account != "" {
		return account
	}
	return c.option("account")
}

// SiteFilter returns the site a discovered site asset is scoped to, or the
// empty string when every site of the accounts in scope is in scope.
func (c *NetlifyConnection) SiteFilter() string {
	return c.option("siteId")
}

func (c *NetlifyConnection) option(key string) string {
	if c.Conf == nil || c.Conf.Options == nil {
		return ""
	}
	return c.Conf.Options[key]
}
