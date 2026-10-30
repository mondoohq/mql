// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"os"

	"github.com/auth0/go-auth0/management"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Flag Options
const (
	OPTION_DOMAIN        = "domain"
	OPTION_CLIENT_ID     = "client-id"
	OPTION_CLIENT_SECRET = "client-secret"
)

// Auth0 environment variables
const (
	AUTH0_DOMAIN_VAR        = "AUTH0_DOMAIN"
	AUTH0_CLIENT_ID_VAR     = "AUTH0_CLIENT_ID"
	AUTH0_CLIENT_SECRET_VAR = "AUTH0_CLIENT_SECRET"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/auth0.json so the CLI and generated docs can
// list what the provider supports. Add an entry here for every platform your
// asset discovery produces.
var Platforms = []*plugin.PlatformInfo{
	{Name: "auth0", Title: "Auth0", Family: []string{"auth0"}, Kind: []string{"api"}, Runtime: []string{"auth0"}},
}

type Auth0Connection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	domain string
	client *management.Management
}

func NewAuth0Connection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*Auth0Connection, error) {
	conn := &Auth0Connection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	domain := conf.Options[OPTION_DOMAIN]
	if domain == "" {
		domain = os.Getenv(AUTH0_DOMAIN_VAR)
	}
	if domain == "" {
		return nil, errors.New("a valid Auth0 tenant domain is required (set AUTH0_DOMAIN or use --domain)")
	}
	conn.domain = domain

	clientID := os.Getenv(AUTH0_CLIENT_ID_VAR)
	clientSecret := os.Getenv(AUTH0_CLIENT_SECRET_VAR)
	for _, cred := range conf.Credentials {
		switch cred.Type {
		case vault.CredentialType_password:
			// --client-secret (or a credential injected via vault)
			clientSecret = string(cred.Secret)
		}
	}
	if id, ok := conf.Options[OPTION_CLIENT_ID]; ok && id != "" {
		clientID = id
	}
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("a valid Auth0 client ID and client secret are required " +
			"(set AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET, or use --client-id/--client-secret)")
	}

	mgmt, err := management.New(domain,
		management.WithClientCredentials(context.Background(), clientID, clientSecret),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate to Auth0 Management API")
	}
	conn.client = mgmt

	return conn, nil
}

func (c *Auth0Connection) Name() string {
	return "auth0"
}

func (c *Auth0Connection) Asset() *inventory.Asset {
	return c.asset
}

// Domain returns the Auth0 tenant domain this connection targets.
func (c *Auth0Connection) Domain() string {
	return c.domain
}

// Client returns the authenticated Auth0 Management API client.
func (c *Auth0Connection) Client() *management.Management {
	return c.client
}

// Verify validates the machine-to-machine credentials by issuing the cheapest
// authenticated read against the tenant settings endpoint.
func (c *Auth0Connection) Verify() error {
	_, err := c.client.Tenant.Read(context.Background())
	if err != nil {
		return errors.Wrap(err, "failed to verify Auth0 credentials")
	}
	return nil
}
