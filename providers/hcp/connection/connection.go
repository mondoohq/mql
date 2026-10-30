// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"sync"

	"github.com/go-openapi/runtime"
	hcpconf "github.com/hashicorp/hcp-sdk-go/config"
	"github.com/hashicorp/hcp-sdk-go/httpclient"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// Connection option keys.
	OptionScope     = "scope"
	OptionOrgID     = "org-id"
	OptionProjectID = "project-id"
	OptionClientID  = "client-id"
	// OptionResourceID carries the id of a leaf asset (a cluster, registry, or
	// application) for resource-scoped connections produced by discovery.
	OptionResourceID = "resource-id"

	// CredentialClientSecret tags the HCP service principal client secret.
	CredentialClientSecret = "client-secret"

	// Discovery targets.
	DiscoveryAll                  = "all"
	DiscoveryAuto                 = "auto"
	DiscoveryProjects             = "projects"
	DiscoveryVaultClusters        = "vault-clusters"
	DiscoveryConsulClusters       = "consul-clusters"
	DiscoveryBoundaryClusters     = "boundary-clusters"
	DiscoveryPackerRegistries     = "packer-registries"
	DiscoveryWaypointApplications = "waypoint-applications"
)

type HcpConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	scope      string
	orgID      string
	orgIDMu    sync.Mutex
	projectID  string
	resourceID string

	// transport is the authenticated go-openapi transport shared by every HCP
	// service client. Resource files build the per-service client on top of it.
	transport runtime.ClientTransport
}

func NewHcpConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*HcpConnection, error) {
	conn := &HcpConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		orgID:      conf.Options[OptionOrgID],
		projectID:  conf.Options[OptionProjectID],
		resourceID: conf.Options[OptionResourceID],
	}

	// A scope may be set explicitly by discovery; otherwise infer it from the
	// ids that were supplied. A project id scopes to a single project, else the
	// connection is rooted at the organization.
	conn.scope = conf.Options[OptionScope]
	if conn.scope == "" {
		if conn.projectID != "" {
			conn.scope = ScopeProject
		} else {
			conn.scope = ScopeOrg
		}
	}

	clientID := conf.Options[OptionClientID]
	clientSecret := clientSecretFromConf(conf)
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("HCP credentials required: set --client-id and --client-secret (service principal)")
	}

	hcpConfig, err := hcpconf.NewHCPConfig(
		hcpconf.WithClientCredentials(clientID, clientSecret),
		hcpconf.WithoutBrowserLogin(),
	)
	if err != nil {
		return nil, errors.Join(errors.New("failed to configure HCP client"), err)
	}

	transport, err := httpclient.New(httpclient.Config{
		HCPConfig: hcpConfig,
	})
	if err != nil {
		return nil, errors.Join(errors.New("failed to create HCP client"), err)
	}
	conn.transport = transport

	return conn, nil
}

// clientSecretFromConf extracts the service principal client secret from the
// connection credentials. The credentials are keyed by their user tag (a
// routing label, not a secret), so the switch selects the client-secret
// credential rather than comparing any secret material.
func clientSecretFromConf(conf *inventory.Config) string {
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			continue
		}
		switch cred.User {
		case CredentialClientSecret:
			return string(cred.Secret)
		}
	}
	return ""
}

func (c *HcpConnection) Name() string {
	return "hcp"
}

func (c *HcpConnection) Asset() *inventory.Asset {
	return c.asset
}

// Transport returns the authenticated transport shared by all HCP service
// clients.
func (c *HcpConnection) Transport() runtime.ClientTransport {
	return c.transport
}

// Scope reports which kind of asset this connection targets.
func (c *HcpConnection) Scope() string { return c.scope }

// OrgID returns the organization id (empty until resolved).
func (c *HcpConnection) OrgID() string { return c.orgID }

// ProjectID returns the project id for project- and resource-scoped connections.
func (c *HcpConnection) ProjectID() string { return c.projectID }

// ResourceID returns the leaf asset id for resource-scoped connections.
func (c *HcpConnection) ResourceID() string { return c.resourceID }

// EnsureOrgID returns the organization id, deriving it once from the service
// principal's accessible organization when it was not supplied. It is safe to
// call concurrently.
func (c *HcpConnection) EnsureOrgID(ctx context.Context) (string, error) {
	c.orgIDMu.Lock()
	defer c.orgIDMu.Unlock()
	if c.orgID != "" {
		return c.orgID, nil
	}
	orgID, err := c.firstOrganizationID(ctx)
	if err != nil {
		return "", err
	}
	if orgID == "" {
		return "", errors.New("no accessible HCP organization; pass --org-id")
	}
	c.orgID = orgID
	return c.orgID, nil
}
