// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"os"
	"strconv"
	"sync"

	"github.com/fastly/go-fastly/v10/fastly"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// OptionBaseURL overrides the Fastly API endpoint, for a private instance.
	OptionBaseURL = "base-url"

	// EnvAPIKeyVar is the environment variable the Fastly API token is read
	// from when no credential is passed. It matches the name the Fastly CLI
	// and go-fastly use.
	EnvAPIKeyVar = "FASTLY_API_KEY"
	// EnvAPIURLVar overrides the API endpoint from the environment.
	EnvAPIURLVar = "FASTLY_API_URL"
)

type FastlyConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client     *fastly.Client
	customerID string

	// healthCheckCache memoizes a service version's health checks so a backend
	// resolving its health check does not list them once per backend.
	healthCheckMu    sync.Mutex
	healthCheckCache map[string][]*fastly.HealthCheck
}

func NewFastlyConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*FastlyConnection, error) {
	token := os.Getenv(EnvAPIKeyVar)
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			token = string(cred.Secret)
		}
	}
	if token == "" {
		return nil, errors.New("a Fastly API token is required (set " + EnvAPIKeyVar + " or use --api-token)")
	}

	baseURL := conf.Options[OptionBaseURL]
	if baseURL == "" {
		baseURL = os.Getenv(EnvAPIURLVar)
	}

	var client *fastly.Client
	var err error
	if baseURL != "" {
		client, err = fastly.NewClientForEndpoint(token, baseURL)
	} else {
		client, err = fastly.NewClient(token)
	}
	if err != nil {
		return nil, errors.New("failed to create Fastly client: " + err.Error())
	}

	conn := &FastlyConnection{
		Connection:       plugin.NewConnection(id, asset),
		Conf:             conf,
		asset:            asset,
		client:           client,
		healthCheckCache: map[string][]*fastly.HealthCheck{},
	}

	// The current user identifies the account the token belongs to. It is the
	// stable key for the asset, so a failure here means the token is unusable.
	user, err := client.GetCurrentUser()
	if err != nil {
		return nil, errors.New("failed to authenticate with Fastly: " + err.Error())
	}
	if user.CustomerID != nil {
		conn.customerID = *user.CustomerID
	}

	return conn, nil
}

func (c *FastlyConnection) Name() string {
	return "fastly"
}

func (c *FastlyConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the authenticated Fastly API client.
func (c *FastlyConnection) Client() *fastly.Client {
	return c.client
}

// CustomerID is the ID of the customer the API token belongs to. It keys the
// asset.
func (c *FastlyConnection) CustomerID() string {
	return c.customerID
}

// HealthChecks returns the health checks of a service version, listing them
// once per version and caching the result. It is used to resolve a backend's
// health check without a list call per backend.
func (c *FastlyConnection) HealthChecks(serviceID string, version int) ([]*fastly.HealthCheck, error) {
	key := serviceID + "/" + strconv.Itoa(version)

	c.healthCheckMu.Lock()
	defer c.healthCheckMu.Unlock()
	if hcs, ok := c.healthCheckCache[key]; ok {
		return hcs, nil
	}

	hcs, err := c.client.ListHealthChecks(&fastly.ListHealthChecksInput{
		ServiceID:      serviceID,
		ServiceVersion: version,
	})
	if err != nil {
		return nil, err
	}
	c.healthCheckCache[key] = hcs
	return hcs, nil
}
