// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package connection

import (
	"errors"
	"os"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type CloudflareConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// Cf is the cloudflare-go v7 client.
	Cf *cloudflare.Client
}

func NewCloudflareConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CloudflareConnection, error) {
	conn := &CloudflareConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	token := os.Getenv("CLOUDFLARE_TOKEN")
	if len(conf.Credentials) > 0 {
		for _, cred := range conf.Credentials {
			if cred.Type == vault.CredentialType_password {
				token = string(cred.Secret)
			}
		}
	}
	if token == "" {
		return nil, errors.New("a valid Cloudflare token is required (set CLOUDFLARE_TOKEN or use --token)")
	}

	conn.Cf = cloudflare.NewClient(option.WithAPIToken(token))

	return conn, nil
}

func (c *CloudflareConnection) Name() string {
	return "cloudflare"
}

func (c *CloudflareConnection) Asset() *inventory.Asset {
	return c.asset
}
