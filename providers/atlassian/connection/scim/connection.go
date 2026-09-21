// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package scim

import (
	"context"
	"errors"
	"fmt"

	"github.com/ctreminiom/go-atlassian/v2/admin"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/shared"
)

const (
	Scim shared.ConnectionType = "scim"
)

type ScimConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *admin.Client
	name   string
}

func NewConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ScimConnection, error) {
	token := shared.Secret(conf, "scim-token", "ATLASSIAN_SCIM_TOKEN")
	if token == "" {
		return nil, errors.New("you must provide an Atlassian SCIM token via the ATLASSIAN_SCIM_TOKEN env or via the --scim-token flag")
	}

	if conf.Options["directory-id"] == "" {
		return nil, errors.New("you must provide a directory ID for SCIM")
	}

	client, err := admin.New(nil)
	if err != nil {
		return nil, err
	}

	client.Auth.SetBearerToken(token)
	client.Auth.SetUserAgent("curl/7.54.0")

	if _, response, probeErr := client.SCIM.Schema.User(context.Background(), conf.Options["directory-id"]); probeErr != nil {
		if response != nil && response.StatusCode == 401 {
			return nil, errors.New("failed to authenticate")
		}
		return nil, errors.New("failed to reach Atlassian SCIM directory: " + probeErr.Error())
	}

	name := fmt.Sprintf("Directory %s", conf.Options["directory-id"])

	return &ScimConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		name:       name,
	}, nil
}

func (c *ScimConnection) Name() string {
	return c.name
}

func (c *ScimConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *ScimConnection) Client() *admin.Client {
	return c.client
}

func (p *ScimConnection) Type() shared.ConnectionType {
	return Scim
}

func (c *ScimConnection) Directory() string {
	return c.Conf.Options["directory-id"]
}

func (c *ScimConnection) ConnectionType() string {
	return "scim"
}

func (c *ScimConnection) Config() *inventory.Config {
	return c.Conf
}
