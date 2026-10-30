// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type GoogleWorkspaceConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// Add custom connection fields here
	serviceAccountSubject string
	customerId            string
	cred                  *vault.Credential
}

func NewGoogleWorkspaceConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*GoogleWorkspaceConnection, error) {
	conn := &GoogleWorkspaceConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	if len(conf.Credentials) != 0 {
		conn.cred = conf.Credentials[0]
	}

	if conn.cred == nil {
		return nil, errors.New("google workspace provider requires a service account")
	}

	conn.customerId = conf.Options["customer-id"]
	conn.serviceAccountSubject = conf.Options["impersonated-user-email"]

	// check if we have access to the workspace
	_, err := conn.GetWorkspaceCustomer(conn.customerId)
	if err != nil {
		log.Error().Err(err).Msgf("could not access to Google Workspace %s", conn.customerId)
		return nil, err
	}

	return conn, nil
}

func (c *GoogleWorkspaceConnection) Name() string {
	return "google-workspace"
}

func (c *GoogleWorkspaceConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *GoogleWorkspaceConnection) CustomerID() string {
	return c.customerId
}
