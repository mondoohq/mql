// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/mitchellh/hashstructure/v2"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Connection options, as they appear in inventory.Config.Options and as CLI
// flags of the same name.
const (
	OPTION_ORGANIZATION = "organization"
	OPTION_PROJECT      = "project"
	OPTION_REPOSITORY   = "repository"
	OPTION_TENANT_ID    = "tenant-id"
	OPTION_CLIENT_ID    = "client-id"
	// OPTION_API_ENDPOINT points the REST client at another address. Only a
	// loopback address is accepted. It exists for tests.
	OPTION_API_ENDPOINT = "api-endpoint"
)

// ConnOption customizes NewAzuredevopsConnection. Tests use it to inject a fake
// token source.
type ConnOption func(*connectionSettings)

type connectionSettings struct {
	auth *Authenticator
}

// WithAuthenticator replaces the authenticator built from the config.
func WithAuthenticator(a *Authenticator) ConnOption {
	return func(s *connectionSettings) { s.auth = a }
}

// AzuredevopsConnection is a connection to one Azure DevOps organization. With
// a project and a repository it stands for that repository.
type AzuredevopsConnection struct {
	plugin.Connection
	asset *inventory.Asset

	org     string
	project string
	repo    string

	auth   *Authenticator
	client *Client
	filter *RepoFilter

	dataOnce sync.Once
	data     *ConnectionData
	dataErr  error

	listOnce sync.Once
	listing  *Listing
	listErr  error

	// OptionsHash lets the provider verify a client once per distinct options.
	OptionsHash uint64
}

// hashedOptions is what identifies a client for OptionsHash. The project and the
// repository are left out on purpose: every repository of an organization shares
// the one verified client of that organization.
type hashedOptions struct {
	Organization string
	TenantID     string
	ClientID     string
	Secret       string
	Endpoint     string
}

// NewAzuredevopsConnection reads the options of the asset's first connection.
// It makes no network call.
func NewAzuredevopsConnection(id uint32, asset *inventory.Asset, opts ...ConnOption) (*AzuredevopsConnection, error) {
	if asset == nil || len(asset.Connections) == 0 {
		return nil, errors.New("azure devops: no connection details for the asset")
	}
	conf := asset.Connections[0]

	settings := &connectionSettings{}
	for _, opt := range opts {
		opt(settings)
	}

	org, err := ParseOrganization(conf.Options[OPTION_ORGANIZATION])
	if err != nil {
		return nil, err
	}
	project := conf.Options[OPTION_PROJECT]
	repo := conf.Options[OPTION_REPOSITORY]
	if repo != "" && project == "" {
		return nil, errors.New("azure devops: a repository needs its project, set both project and repository")
	}
	if project != "" && repo == "" {
		return nil, errors.New("azure devops: a project connection is not supported, set the repository too or connect to the organization")
	}

	filter, err := NewRepoFilter(conf.Options[OPTION_REPOS], conf.Options[OPTION_REPOS_EXCLUDE])
	if err != nil {
		return nil, err
	}

	cred := secretCredential(conf)
	auth := settings.auth
	if auth == nil {
		// The credential goes to the authenticator whenever the asset carries
		// one. Without it the Azure sign-in chain falls back to the login of the
		// machine, which is meant only for an asset that carries no credential.
		auth, err = NewAuthenticator(AuthOptions{
			TenantID:   conf.Options[OPTION_TENANT_ID],
			ClientID:   conf.Options[OPTION_CLIENT_ID],
			Credential: cred,
		})
		if err != nil {
			return nil, err
		}
	}

	client, err := NewClient(org, auth, ClientOptions{Endpoint: conf.Options[OPTION_API_ENDPOINT]})
	if err != nil {
		return nil, err
	}

	hashed := hashedOptions{
		Organization: org,
		TenantID:     conf.Options[OPTION_TENANT_ID],
		ClientID:     conf.Options[OPTION_CLIENT_ID],
		Endpoint:     conf.Options[OPTION_API_ENDPOINT],
	}
	if cred != nil {
		hashed.Secret = string(cred.Secret)
	}
	hash, err := hashstructure.Hash(hashed, hashstructure.FormatV2, nil)
	if err != nil {
		return nil, err
	}

	return &AzuredevopsConnection{
		Connection:  plugin.NewConnection(id, asset),
		asset:       asset,
		org:         org,
		project:     project,
		repo:        repo,
		auth:        auth,
		client:      client,
		filter:      filter,
		OptionsHash: hash,
	}, nil
}

// secretCredential is the credential of the config that carries the PAT or the
// client secret. A password or a certificate wins. When the config holds only
// credentials of another kind, the first of them is returned anyway, so the
// authenticator reports that it cannot use it instead of the connection
// quietly signing in some other way.
func secretCredential(conf *inventory.Config) *vault.Credential {
	var other *vault.Credential
	for _, c := range conf.Credentials {
		if c == nil {
			continue
		}
		if c.Type == vault.CredentialType_password || c.Type == vault.CredentialType_pkcs12 {
			return c
		}
		if other == nil {
			other = c
		}
	}
	return other
}

func (c *AzuredevopsConnection) Name() string { return "azuredevops" }

func (c *AzuredevopsConnection) Asset() *inventory.Asset { return c.asset }

func (c *AzuredevopsConnection) Client() *Client { return c.client }

// Organization is the organization name.
func (c *AzuredevopsConnection) Organization() string { return c.org }

// Project is the project of a repository connection, empty for an organization.
func (c *AzuredevopsConnection) Project() string { return c.project }

// Repository is the repository of a repository connection, empty for an
// organization.
func (c *AzuredevopsConnection) Repository() string { return c.repo }

// IsRepository reports a connection that stands for one repository.
func (c *AzuredevopsConnection) IsRepository() bool { return c.repo != "" }

// Filter is the repository filter of the connection.
func (c *AzuredevopsConnection) Filter() *RepoFilter { return c.filter }

// AuthMode is how the connection authenticates.
func (c *AzuredevopsConnection) AuthMode() AuthMode { return c.auth.Mode() }

// GitCredential is a credential for cloning with the connection's token.
func (c *AzuredevopsConnection) GitCredential(ctx context.Context) (*vault.Credential, error) {
	return c.auth.GitCredential(ctx)
}

// ConnectionData reads the organization identity once and keeps it.
//
// The result is cached with a sync.Once, a failure included: an error is kept for
// the life of the connection, so a retry needs a new connection.
func (c *AzuredevopsConnection) ConnectionData(ctx context.Context) (*ConnectionData, error) {
	c.dataOnce.Do(func() {
		c.data, c.dataErr = c.client.ConnectionData(ctx)
	})
	return c.data, c.dataErr
}

// Listing lists every project and repository once and keeps the result, so the
// discovery and the resources of one process share a single walk.
//
// It fails when the credential can read the repositories of no project.
// Enumerate reports each unreadable project and carries on, so without this
// check a credential that reads nothing would look like an organization that
// holds nothing.
//
// The result is cached with a sync.Once, a failure included: an error is kept for
// the life of the connection, so a retry needs a new connection.
func (c *AzuredevopsConnection) Listing(ctx context.Context) (*Listing, error) {
	c.listOnce.Do(func() {
		listing, err := c.client.Enumerate(ctx)
		if err != nil {
			c.listErr = err
			return
		}
		if err := c.requireAReadableProject(listing); err != nil {
			c.listErr = err
			return
		}
		c.listing = listing
	})
	return c.listing, c.listErr
}

// requireAReadableProject turns a listing with no readable project into an
// error. The answer of the first unreadable project is quoted because it says
// what Azure DevOps objected to. It holds a status and a path, never a secret.
//
// No projects at all is an error too: Azure DevOps lists only the projects the
// credential may see, so a service principal that is a member of the
// organization but of none of its projects gets an empty list, exactly like an
// organization without projects. The two cannot be told apart, and the first is
// the common setup mistake.
func (c *AzuredevopsConnection) requireAReadableProject(l *Listing) error {
	total := len(l.Projects)
	if total == 0 {
		return fmt.Errorf("azure devops: the credential sees no projects in organization %q. "+
			"Azure DevOps lists only the projects a credential may read: add the service principal to the "+
			"projects to scan (for example to their Readers group), or give the personal access token "+
			"the Project and Team (Read) scope", c.org)
	}
	if len(l.Unreadable()) != total {
		return nil
	}

	which := fmt.Sprintf("any of its %d projects", total)
	if total == 1 {
		which = "its only project"
	}
	var first error
	for _, p := range l.Projects {
		if p.NoAccess != nil {
			first = p.NoAccess
			break
		}
	}
	return fmt.Errorf("azure devops: organization %q has projects but the credential cannot read the repositories of %s. "+
		"Check that it may read repositories: a personal access token needs the Code (Read) scope, "+
		"and a service principal must be a member of the projects. First answer: %v", c.org, which, first)
}

// Verify proves the credential belongs to a member of the organization and that
// the organization is an Azure DevOps Services one.
func (c *AzuredevopsConnection) Verify(ctx context.Context) error {
	data, err := c.ConnectionData(ctx)
	if err != nil {
		return c.explain(err)
	}
	if data.DeploymentType != "hosted" {
		return fmt.Errorf("azure devops: organization %q reports the deployment type %q, only Azure DevOps Services (dev.azure.com) is supported",
			c.org, data.DeploymentType)
	}
	return nil
}

// explain turns the answers of connectionData into advice. Every case is told
// apart by the HTTP status of the answer, never by its wording, which Microsoft
// words as it likes and in the language of the account. An error that is not an
// answer of Azure DevOps (a network failure, a failed token request) comes back
// as it is.
func (c *AzuredevopsConnection) explain(err error) error {
	switch {
	case IsUnauthorized(err) && c.auth.Mode() == AuthEntra:
		return fmt.Errorf("azure devops: organization %q did not accept the service principal. Add it to the organization "+
			"(Organization settings, Users) and check the tenant-id, client-id and client secret: %w", c.org, err)
	case IsUnauthorized(err):
		return fmt.Errorf("azure devops: organization %q did not accept the personal access token. Check the value of --token "+
			"or AZURE_DEVOPS_TOKEN and that the token has not expired: %w", c.org, err)
	case IsNoAccess(err):
		// Reached for 403 only: 401 is answered above.
		return fmt.Errorf("azure devops: the credential may not read organization %q: %w", c.org, err)
	case IsNotFound(err):
		return fmt.Errorf("azure devops: organization %q was not found. Check the organization name: %w", c.org, err)
	}
	return err
}

// PlatformInfo is the platform of the asset the connection stands for.
func (c *AzuredevopsConnection) PlatformInfo() *inventory.Platform {
	if c.IsRepository() {
		return NewRepoPlatform(c.org, c.project)
	}
	return NewOrgPlatform(c.org)
}
