// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/rs/zerolog/log"
	"github.com/vmware/go-vcloud-director/v3/govcd"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type VcdConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// custom fields
	client *govcd.VCDClient
	host   string
}

func NewVcdConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*VcdConnection, error) {
	conn := &VcdConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize connection
	if len(conf.Credentials) == 0 {
		return nil, errors.New("missing credentials for VMware Cloud Director")
	}

	cfg := &vcdConfig{
		Host:     conf.Host,
		Insecure: conf.Insecure,
	}

	// determine the organization for the user
	org, ok := conf.Options["organization"]
	if ok {
		cfg.Org = org
	} else {
		cfg.Org = "system" // default in vcd
	}

	// if a secret was provided, it always overrides the env variable since it has precedence
	if len(conf.Credentials) > 0 {
		for i := range conf.Credentials {
			cred := conf.Credentials[i]
			if cred.Type == vault.CredentialType_password {
				cfg.User = cred.User
				cfg.Password = string(cred.Secret)
			} else {
				log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for VMware Cloud Director provider")
			}
		}
	}

	client, err := newVcdClient(cfg)
	if err != nil {
		return nil, err
	}

	conn.client = client

	return conn, nil
}

func (c *VcdConnection) Name() string {
	return "vcd"
}

func (c *VcdConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *VcdConnection) Client() *govcd.VCDClient {
	return c.client
}

type vcdConfig struct {
	User     string
	Password string
	Host     string
	Org      string
	Insecure bool
}

func (c *vcdConfig) Href() string {
	return fmt.Sprintf("https://%s/api", c.Host)
}

func newVcdClient(c *vcdConfig) (*govcd.VCDClient, error) {
	u, err := url.ParseRequestURI(c.Href())
	if err != nil {
		return nil, fmt.Errorf("unable to pass url: %s", err)
	}

	vcdClient := govcd.NewVCDClient(*u, c.Insecure)

	err = vcdClient.Authenticate(c.User, c.Password, c.Org)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate: %s", err)
	}
	return vcdClient, nil
}
