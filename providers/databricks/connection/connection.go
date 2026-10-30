// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"

	databricks "github.com/databricks/databricks-sdk-go"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// PlaneAccount marks an asset connected to the Databricks account console API.
	PlaneAccount = "account"
	// PlaneWorkspace marks an asset connected to a single Databricks workspace API.
	PlaneWorkspace = "workspace"

	OptionPlane       = "plane"
	OptionAccountID   = "account-id"
	OptionHost        = "host"
	OptionClientID    = "client-id"
	OptionWorkspaceID = "workspace-id"

	// CredentialClientSecret tags the OAuth M2M client secret credential.
	CredentialClientSecret = "client-secret"
	// CredentialToken tags a personal access token credential.
	CredentialToken = "token"

	// defaultAccountHost is the account console host for AWS-hosted Databricks.
	// Azure (accounts.azuredatabricks.net) and GCP (accounts.gcp.databricks.com)
	// callers override this with --host.
	defaultAccountHost = "https://accounts.cloud.databricks.com"
)

type DatabricksConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	plane       string
	accountID   string
	workspaceID string
	host        string

	account   *databricks.AccountClient
	workspace *databricks.WorkspaceClient
}

func NewDatabricksConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DatabricksConnection, error) {
	conn := &DatabricksConnection{
		Connection:  plugin.NewConnection(id, asset),
		Conf:        conf,
		asset:       asset,
		accountID:   conf.Options[OptionAccountID],
		workspaceID: conf.Options[OptionWorkspaceID],
		host:        conf.Options[OptionHost],
	}

	// Determine which API plane this asset lives on. Discovery marks workspace
	// child assets explicitly; a direct connect defaults to the account plane
	// when an account id is present and to a single workspace otherwise.
	conn.plane = conf.Options[OptionPlane]
	if conn.plane == "" {
		if conn.accountID != "" {
			conn.plane = PlaneAccount
		} else {
			conn.plane = PlaneWorkspace
		}
	}

	clientID := conf.Options[OptionClientID]
	clientSecret, token := credentials(conf)

	cfg := &databricks.Config{
		Host:         conn.host,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Token:        token,
	}

	switch conn.plane {
	case PlaneAccount:
		if cfg.Host == "" {
			cfg.Host = defaultAccountHost
		}
		cfg.AccountID = conn.accountID
		acc, err := databricks.NewAccountClient(cfg)
		if err != nil {
			return nil, errors.Join(errors.New("failed to create Databricks account client"), err)
		}
		conn.account = acc
	case PlaneWorkspace:
		if cfg.Host == "" {
			return nil, errors.New("a workspace host is required to connect to a Databricks workspace (set --host or DATABRICKS_HOST)")
		}
		ws, err := databricks.NewWorkspaceClient(cfg)
		if err != nil {
			return nil, errors.Join(errors.New("failed to create Databricks workspace client"), err)
		}
		conn.workspace = ws
	default:
		return nil, errors.New("unknown Databricks connection plane: " + conn.plane)
	}

	return conn, nil
}

// credentials extracts the OAuth client secret and personal access token from
// the connection config, distinguished by the credential's user tag.
func credentials(conf *inventory.Config) (clientSecret string, token string) {
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			continue
		}
		switch cred.User {
		case CredentialClientSecret:
			clientSecret = string(cred.Secret)
		case CredentialToken:
			token = string(cred.Secret)
		}
	}
	return
}

func (c *DatabricksConnection) Name() string {
	return "databricks"
}

func (c *DatabricksConnection) Asset() *inventory.Asset {
	return c.asset
}

// Plane reports whether this connection targets the account or a workspace.
func (c *DatabricksConnection) Plane() string {
	return c.plane
}

// AccountID returns the Databricks account id for account-plane connections.
func (c *DatabricksConnection) AccountID() string {
	return c.accountID
}

// WorkspaceID returns the Databricks workspace id for workspace-plane connections.
func (c *DatabricksConnection) WorkspaceID() string {
	return c.workspaceID
}

// Host returns the API host this connection was built against.
func (c *DatabricksConnection) Host() string {
	return c.host
}

// Account returns the account console client, or nil on a workspace connection.
func (c *DatabricksConnection) Account() *databricks.AccountClient {
	return c.account
}

// Workspace returns the workspace client, or nil on an account connection.
func (c *DatabricksConnection) Workspace() *databricks.WorkspaceClient {
	return c.workspace
}
