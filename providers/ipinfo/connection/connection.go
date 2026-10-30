// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type IpinfoConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	token  string
	client any // ipinfo client will be stored here
}

func NewIpinfoConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*IpinfoConnection, error) {
	conn := &IpinfoConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	conn.token = os.Getenv("IPINFO_TOKEN")

	return conn, nil
}

func (c *IpinfoConnection) Name() string {
	return "ipinfo"
}

func (c *IpinfoConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *IpinfoConnection) Client() any {
	return c.client
}

func (c *IpinfoConnection) SetClient(client any) {
	c.client = client
}

func (c *IpinfoConnection) Token() string {
	return c.token
}
