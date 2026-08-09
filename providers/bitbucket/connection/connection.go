// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
)

// Flag options
const (
	OPTION_WORKSPACE    = "workspace"
	OPTION_USERNAME     = "username"
	OPTION_TOKEN        = "token"
	OPTION_APP_PASSWORD = "app-password"
)

// Bitbucket environment variables
const (
	BITBUCKET_WORKSPACE_VAR    = "BITBUCKET_WORKSPACE"
	BITBUCKET_USERNAME_VAR     = "BITBUCKET_USERNAME"
	BITBUCKET_TOKEN_VAR        = "BITBUCKET_TOKEN"
	BITBUCKET_APP_PASSWORD_VAR = "BITBUCKET_APP_PASSWORD"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/bitbucket.json so the CLI and generated docs can
// list what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "bitbucket", Title: "Bitbucket", Family: []string{"bitbucket"}, Kind: []string{"api"}, Runtime: []string{"bitbucket"}},
}

type BitbucketConnection struct {
	plugin.Connection
	Conf      *inventory.Config
	asset     *inventory.Asset
	client    *Client
	workspace string

	// verifiedWorkspace caches the workspace record fetched during Verify(),
	// so the bitbucket.workspace root accessor can reuse it instead of
	// issuing a second identical GET.
	verifiedWorkspace *Workspace
}

// NewBitbucketConnection resolves the workspace and credentials for a
// Bitbucket Cloud connection and wires up the API client. Auth uses either a
// workspace/repository Access Token (Bearer) or a username + App Password
// (HTTP Basic); the Access Token, if present, takes precedence.
func NewBitbucketConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*BitbucketConnection, error) {
	conn := &BitbucketConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	workspace := os.Getenv(BITBUCKET_WORKSPACE_VAR)
	if ws := conf.Options[OPTION_WORKSPACE]; ws != "" {
		workspace = ws
	}
	if workspace == "" {
		return nil, errors.New("a Bitbucket workspace is required (set " + BITBUCKET_WORKSPACE_VAR + " or use --workspace)")
	}
	conn.workspace = workspace

	username := os.Getenv(BITBUCKET_USERNAME_VAR)
	if u := conf.Options[OPTION_USERNAME]; u != "" {
		username = u
	}

	token := os.Getenv(BITBUCKET_TOKEN_VAR)
	appPassword := os.Getenv(BITBUCKET_APP_PASSWORD_VAR)

	// A vault credential (from --token/--app-password, or one injected by the
	// inventory) takes precedence over the environment. Its User field tells
	// the two auth modes apart: a credential minted from --app-password
	// carries the username (see provider.ParseCLI), an Access Token
	// credential does not.
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			continue
		}
		if cred.User != "" {
			username = cred.User
			appPassword = string(cred.Secret)
		} else {
			token = string(cred.Secret)
		}
	}

	transport := &bitbucketAuthTransport{base: http.DefaultTransport}
	switch {
	case token != "":
		// workspace or repository Access Token
		transport.token = token
	case username != "" && appPassword != "":
		// legacy App Password
		transport.username, transport.appPassword = username, appPassword
	default:
		return nil, errors.New(
			"Bitbucket credentials are required: set " + BITBUCKET_TOKEN_VAR +
				", or " + BITBUCKET_USERNAME_VAR + " + " + BITBUCKET_APP_PASSWORD_VAR +
				" (or the matching --token / --username + --app-password flags)")
	}

	conn.client = NewClient(&http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	})

	return conn, nil
}

func (c *BitbucketConnection) Name() string {
	return "bitbucket"
}

func (c *BitbucketConnection) Asset() *inventory.Asset {
	return c.asset
}

// Workspace returns the workspace slug selected by the connection
// (BITBUCKET_WORKSPACE or --workspace).
func (c *BitbucketConnection) Workspace() string {
	return c.workspace
}

// Client returns the Bitbucket Cloud API client.
func (c *BitbucketConnection) Client() *Client {
	return c.client
}

// VerifiedWorkspace returns the workspace record fetched by Verify, or nil
// if Verify has not run yet.
func (c *BitbucketConnection) VerifiedWorkspace() *Workspace {
	return c.verifiedWorkspace
}

// Verify validates the connection's credentials and workspace by issuing the
// cheapest authenticated read: fetching the connected workspace itself. The
// fetched record is cached so the first bitbucket.workspace query doesn't
// repeat the request.
func (c *BitbucketConnection) Verify() error {
	w, err := c.client.GetWorkspace(context.Background(), c.workspace)
	if err != nil {
		return errors.Wrapf(err, "failed to verify Bitbucket credentials for workspace %q", c.workspace)
	}
	c.verifiedWorkspace = w
	return nil
}
