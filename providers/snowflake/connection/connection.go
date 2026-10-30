// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	gosnowflake "github.com/snowflakedb/gosnowflake/v2"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"golang.org/x/crypto/ssh"
)

type SnowflakeConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// Custom connection fields
	client *sdk.Client
	// database is set when the connection is scoped to a single database,
	// making the asset a snowflake-database rather than the whole account.
	database string
	// account caches the current session's account name; it is resolved once
	// via Account() so detect() and discover() share a single lookup.
	accountOnce sync.Once
	account     string
	accountErr  error
}

func NewSnowflakeConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*SnowflakeConnection, error) {
	conn := &SnowflakeConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize your connection here

	if len(conf.Credentials) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing credentials for snowflake connection")
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}

	conn.database = conf.Options[OptionDatabase]

	cfg := &gosnowflake.Config{
		Account:  conf.Options["account"],
		Region:   conf.Options["region"],
		Role:     conf.Options["role"],
		Database: conn.database,
	}

	for i := range conf.Credentials {
		cred := conf.Credentials[i]
		switch cred.Type {
		case vault.CredentialType_password:
			cfg.User = cred.User
			cfg.Password = string(cred.Secret)
			cfg.Authenticator = gosnowflake.AuthTypeSnowflake
		case vault.CredentialType_private_key:
			cfg.User = cred.User

			// snowflake requires a RSA private key in PEM format
			key, err := parsePrivateKey(cred.Secret, []byte(cred.Password))
			if err != nil {
				return nil, err
			}
			cfg.PrivateKey = key
			cfg.Authenticator = gosnowflake.AuthTypeJwt
		case vault.CredentialType_bearer:
			// A programmatic access token (PAT) is passed as a bearer token.
			cfg.User = cred.User
			cfg.Token = string(cred.Secret)
			cfg.Authenticator = gosnowflake.AuthTypePat
		}
	}

	client, err := sdk.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	conn.client = client

	return conn, nil
}

func parsePrivateKey(privateKeyBytes []byte, passphrase []byte) (*rsa.PrivateKey, error) {
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, errors.New("could not decode private key")
	}

	var privateKey any
	var err error
	if privateKeyBlock.Type == "ENCRYPTED PRIVATE KEY" {
		if len(passphrase) == 0 {
			return nil, errors.New("private key is encrypted, but no passphrase provided")
		}

		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBlock.Bytes, passphrase)
		if err != nil {
			return nil, errors.New("could not parse encrypted private key " + err.Error())
		}
	} else {
		privateKey, err = ssh.ParseRawPrivateKey(privateKeyBytes)
		if err != nil {
			return nil, errors.New("could not parse private key err " + err.Error())
		}
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("snowflake requires a RSA private key in PEM format")
	}
	return rsaPrivateKey, nil
}

func (c *SnowflakeConnection) Name() string {
	return "snowflake"
}

func (c *SnowflakeConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *SnowflakeConnection) Client() *sdk.Client {
	return c.client
}

// Account returns the current session's account name, resolving it once and
// caching the result so repeated callers (detect and discover) share a single
// CurrentSessionDetails round-trip.
func (c *SnowflakeConnection) Account() (string, error) {
	c.accountOnce.Do(func() {
		details, err := c.client.ContextFunctions.CurrentSessionDetails(context.Background())
		if err != nil {
			c.accountErr = err
			return
		}
		c.account = details.Account
	})
	return c.account, c.accountErr
}

// Database returns the database this connection is scoped to, or "" when the
// connection covers the whole account.
func (c *SnowflakeConnection) Database() string {
	return c.database
}

// IsDatabaseScoped reports whether the connection is scoped to a single
// database (a snowflake-database asset) rather than the account.
func (c *SnowflakeConnection) IsDatabaseScoped() bool {
	return c.database != ""
}
