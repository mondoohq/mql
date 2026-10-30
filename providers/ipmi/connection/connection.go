// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	impi_client "go.mondoo.com/mql/providers/ipmi/connection/client"
)

type IpmiConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	//  custom connection fields
	client   *impi_client.IpmiClient
	guidLock sync.Mutex
	guid     string
}

func NewIpmiConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*IpmiConnection, error) {
	conn := &IpmiConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize connection
	if conf == nil || conf.Type != "ipmi" {
		return nil, errors.New("provider type does not match") // TODO: use plugin.ErrProviderTypeDoesNotMatch
	}

	port := conf.Port
	if port == 0 {
		port = 623
	}

	// search for password secret
	c, err := vault.GetPassword(conf.Credentials)
	if err != nil {
		return nil, errors.New("missing password for ipmi provider")
	}

	client, err := impi_client.NewIpmiClient(&impi_client.Connection{
		Hostname:  conf.Host,
		Port:      port,
		Username:  c.User,
		Password:  string(c.Secret),
		Interface: "lan",
	})
	if err != nil {
		return nil, err
	}

	err = client.Open()
	if err != nil {
		return nil, err
	}

	conn.client = client
	return conn, nil
}

func (c *IpmiConnection) Name() string {
	return "ipmi"
}

func (c *IpmiConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *IpmiConnection) Client() *impi_client.IpmiClient {
	return c.client
}

func (c *IpmiConnection) Identifier() (string, error) {
	guid, err := c.Guid()
	if err != nil {
		return "", err
	}
	return "//platformid.api.mondoo.app/runtime/ipmi/deviceid/" + guid, nil
}

func (c *IpmiConnection) Guid() (string, error) {
	c.guidLock.Lock()
	defer c.guidLock.Unlock()

	if c.guid != "" {
		return c.guid, nil
	}

	resp, err := c.client.DeviceGUID()
	if err != nil {
		return "", err
	}

	c.guid = resp.GUID
	return c.guid, nil
}
