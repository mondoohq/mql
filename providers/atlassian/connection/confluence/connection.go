// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package confluence

import (
	"context"
	"errors"
	"os"

	"github.com/ctreminiom/go-atlassian/v2/confluence"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/shared"
)

const (
	Confluence shared.ConnectionType = "confluence"
)

type ConfluenceConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *confluence.Client
	name   string
}

func NewConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ConfluenceConnection, error) {
	host := conf.Options["host"]
	if host == "" {
		host = os.Getenv("ATLASSIAN_HOST")
	}
	if host == "" {
		return nil, errors.New("you must provide an Atlassian hostname via ATLASSIAN_HOST env or via the --host flag")
	}

	user := conf.Options["user"]
	if user == "" {
		user = os.Getenv("ATLASSIAN_USER")
	}
	if user == "" {
		return nil, errors.New("you must provide an Atlassian username via ATLASSIAN_USER env or via the --user flag")
	}

	token := shared.Secret(conf, "user-token", "ATLASSIAN_USER_TOKEN")
	if token == "" {
		return nil, errors.New("you must provide an Atlassian user token via the ATLASSIAN_USER_TOKEN env or via the --user-token flag")
	}

	client, err := confluence.New(nil, host)
	if err != nil {
		return nil, err
	}

	client.Auth.SetBasicAuth(user, token)
	client.Auth.SetUserAgent("curl/7.54.0")

	if _, response, probeErr := client.Label.Get(context.Background(), "test", "page", 0, 50); probeErr != nil {
		if response != nil && response.StatusCode == 401 {
			return nil, errors.New("failed to authenticate")
		}
		return nil, errors.New("failed to reach Confluence: " + probeErr.Error())
	}

	return &ConfluenceConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		name:       host,
	}, nil
}

func (c *ConfluenceConnection) Name() string {
	return c.name
}

func (c *ConfluenceConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *ConfluenceConnection) Client() *confluence.Client {
	return c.client
}

func (c *ConfluenceConnection) Type() shared.ConnectionType {
	return Confluence
}

func (c *ConfluenceConnection) ConnectionType() string {
	return string(Confluence)
}

func (c *ConfluenceConnection) Config() *inventory.Config {
	return c.Conf
}
