// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package admin

import (
	"context"
	"errors"

	"github.com/ctreminiom/go-atlassian/v2/admin"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/shared"
)

const (
	Admin shared.ConnectionType = "admin"
)

type AdminConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *admin.Client
	name   string
}

func NewConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*AdminConnection, error) {
	// A hosted scan delivers the token as an inventory vault credential; a CLI
	// scan as --admin-token or the env var. See shared.Secret.
	adminToken := shared.Secret(conf, "admin-token", "ATLASSIAN_ADMIN_TOKEN")
	if adminToken == "" {
		return nil, errors.New("you must provide an Atlassian admin token via the ATLASSIAN_ADMIN_TOKEN env or via the --admin-token flag")
	}

	client, err := admin.New(nil)
	if err != nil {
		return nil, err
	}

	client.Auth.SetBearerToken(adminToken)
	client.Auth.SetUserAgent("curl/7.54.0")

	if _, response, probeErr := client.Organization.Gets(context.Background(), ""); probeErr != nil {
		if response != nil && response.StatusCode == 401 {
			return nil, errors.New("failed to authenticate")
		}
		return nil, errors.New("failed to reach Atlassian Admin: " + probeErr.Error())
	}

	return &AdminConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		name:       "admin.atlassian.com",
	}, nil
}

func (c *AdminConnection) Name() string {
	return c.name
}

func (c *AdminConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *AdminConnection) Client() *admin.Client {
	return c.client
}

func (c *AdminConnection) Type() shared.ConnectionType {
	return Admin
}

func (c *AdminConnection) ConnectionType() string {
	return "admin"
}

func (c *AdminConnection) Config() *inventory.Config {
	return c.Conf
}
