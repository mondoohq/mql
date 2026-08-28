// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"os"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Flag Options
const (
	OPTION_TOKEN = "token"
)

// CircleCI environment variables
const (
	CIRCLECI_TOKEN_VAR = "CIRCLECI_TOKEN"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/circleci.json so the CLI and generated docs can
// list what the provider supports. Add an entry here for every platform your
// asset discovery produces.
var Platforms = []*plugin.PlatformInfo{
	{Name: "circleci", Title: "CircleCI", Family: []string{"circleci"}, Kind: []string{"api"}, Runtime: []string{"circleci"}},
}

type CircleciConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client *Client
}

func NewCircleciConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CircleciConnection, error) {
	conn := &CircleciConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	token := os.Getenv(CIRCLECI_TOKEN_VAR)
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			token = string(cred.Secret)
		}
	}
	if t, ok := conf.Options[OPTION_TOKEN]; ok && t != "" {
		token = t
	}
	if token == "" {
		return nil, errors.New("a valid CircleCI API token is required (set CIRCLECI_TOKEN or use --token)")
	}

	conn.client = NewClient(token)

	return conn, nil
}

func (c *CircleciConnection) Name() string {
	return "circleci"
}

func (c *CircleciConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the authenticated CircleCI API v2 client.
func (c *CircleciConnection) Client() *Client {
	return c.client
}

// Verify validates the token by issuing the cheapest authenticated read
// against the current-user endpoint, and returns the authenticated user so
// callers don't have to fetch it a second time.
func (c *CircleciConnection) Verify() (*User, error) {
	u, err := c.client.GetMe(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "unable to authenticate with CircleCI")
	}
	return u, nil
}
