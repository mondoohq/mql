// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"sync"

	"github.com/stmcginnis/gofish"
	"github.com/stmcginnis/gofish/schemas"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const DefaultPort = 443

type RedfishConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *gofish.APIClient
	vendor Vendor
	id     string

	// endpoint is the base URL of the management service, and insecure records
	// whether the caller waived TLS verification. Both are kept so the
	// unauthenticated service-root probe can reach the same target as the
	// authenticated client.
	endpoint string
	insecure bool

	// Systems and managers are immutable for the lifetime of a scan, so they
	// are fetched once and reused across vendor detection, the platform
	// identifier, and every resource that navigates from them.
	systemsOnce  sync.Once
	systems      []*schemas.ComputerSystem
	systemsErr   error
	managersOnce sync.Once
	managers     []*schemas.Manager
	managersErr  error

	// The session service backs both redfish.sessionService and
	// redfish.sessions, so it is fetched once as well.
	sessionServiceOnce sync.Once
	sessionService     *schemas.SessionService
	sessionServiceErr  error

	// The account service backs both redfish.accounts and
	// redfish.accountService, so it is fetched once as well.
	accountServiceOnce sync.Once
	accountService     *schemas.AccountService
	accountServiceErr  error

	idOnce sync.Once

	// anonOnce guards the single unauthenticated service-root probe.
	anonOnce sync.Once
	anon     bool
	anonErr  error
}

// Systems returns the compute systems exposed by the service, fetched once and
// cached for the lifetime of the connection.
func (c *RedfishConnection) Systems() ([]*schemas.ComputerSystem, error) {
	c.systemsOnce.Do(func() {
		if c.client == nil || c.client.Service == nil {
			c.systemsErr = errors.New("no redfish service available")
			return
		}
		c.systems, c.systemsErr = c.client.Service.Systems()
	})
	return c.systems, c.systemsErr
}

// Managers returns the management controllers exposed by the service, fetched
// once and cached for the lifetime of the connection.
func (c *RedfishConnection) Managers() ([]*schemas.Manager, error) {
	c.managersOnce.Do(func() {
		if c.client == nil || c.client.Service == nil {
			c.managersErr = errors.New("no redfish service available")
			return
		}
		c.managers, c.managersErr = c.client.Service.Managers()
	})
	return c.managers, c.managersErr
}

// SessionService returns the session service of the management service,
// fetched once and cached for the lifetime of the connection. It returns nil
// without an error when the service root links no session service.
func (c *RedfishConnection) SessionService() (*schemas.SessionService, error) {
	c.sessionServiceOnce.Do(func() {
		if c.client == nil || c.client.Service == nil {
			c.sessionServiceErr = errors.New("no redfish service available")
			return
		}
		c.sessionService, c.sessionServiceErr = c.client.Service.SessionService()
	})
	return c.sessionService, c.sessionServiceErr
}

// AccountService returns the account service of the management service,
// fetched once and cached for the lifetime of the connection. It returns nil
// without an error when the service root links no account service.
func (c *RedfishConnection) AccountService() (*schemas.AccountService, error) {
	c.accountServiceOnce.Do(func() {
		if c.client == nil || c.client.Service == nil {
			c.accountServiceErr = errors.New("no redfish service available")
			return
		}
		c.accountService, c.accountServiceErr = c.client.Service.AccountService()
	})
	return c.accountService, c.accountServiceErr
}

func NewRedfishConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*RedfishConnection, error) {
	conn := &RedfishConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	if conf == nil || conf.Type != "redfish" {
		return nil, errors.New("provider type does not match")
	}
	if conf.Host == "" {
		return nil, errors.New("missing host for redfish provider")
	}

	cred, err := vault.GetPassword(conf.Credentials)
	if err != nil {
		return nil, errors.New("missing password for redfish provider")
	}

	port := conf.Port
	if port == 0 {
		port = DefaultPort
	}

	insecure := conf.Options != nil && conf.Options["insecure"] == "true"
	endpoint := fmt.Sprintf("https://%s:%d", conf.Host, port)

	client, err := gofish.Connect(gofish.ClientConfig{
		Endpoint: endpoint,
		Username: cred.User,
		Password: string(cred.Secret),
		Insecure: insecure,
	})
	if err != nil {
		return nil, err
	}

	conn.client = client
	conn.endpoint = endpoint
	conn.insecure = insecure
	conn.vendor = detectVendorFromService(conn)
	return conn, nil
}

func (c *RedfishConnection) Name() string {
	return "redfish"
}

func (c *RedfishConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the connected gofish API client.
func (c *RedfishConnection) Client() *gofish.APIClient {
	return c.client
}

// Vendor returns the detected hardware vendor.
func (c *RedfishConnection) Vendor() Vendor {
	return c.vendor
}

// Close logs out the Redfish session.
func (c *RedfishConnection) Close() {
	if c.client != nil {
		c.client.Logout()
	}
}

// Identifier derives a stable platform ID from the first system or manager
// UUID, falling back to the host when neither is available.
func (c *RedfishConnection) Identifier() (string, error) {
	// idOnce guards the read-compute-write of c.id so concurrent callers cannot
	// race, and ensures the Systems/Managers lookups run at most once even when
	// they yield no UUID and we fall back to the host.
	c.idOnce.Do(func() {
		uid := ""
		if systems, err := c.Systems(); err == nil {
			for _, s := range systems {
				if s.UUID != "" {
					uid = s.UUID
					break
				}
			}
		}
		if uid == "" {
			if managers, err := c.Managers(); err == nil {
				for _, m := range managers {
					if m.UUID != "" {
						uid = m.UUID
						break
					}
				}
			}
		}
		if uid == "" {
			uid = c.Conf.Host
		}

		c.id = "//platformid.api.mondoo.app/runtime/redfish/uuid/" + uid
	})
	return c.id, nil
}
