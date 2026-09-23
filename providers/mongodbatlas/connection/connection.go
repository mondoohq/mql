// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

const (
	// PlaneOrg marks an asset connected to a MongoDB Atlas organization.
	PlaneOrg = "org"
	// PlaneProject marks an asset scoped to a single Atlas project.
	PlaneProject = "project"

	OptionPlane     = "plane"
	OptionOrgID     = "org-id"
	OptionProjectID = "project-id"
	OptionPublicKey = "public-key"
	OptionClientID  = "client-id"

	// CredentialPrivateKey tags the programmatic API key's private key.
	CredentialPrivateKey = "private-key"
	// CredentialClientSecret tags a service account OAuth client secret.
	CredentialClientSecret = "client-secret"
)

type MongoDBAtlasConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	plane     string
	orgID     string
	orgIDMu   sync.Mutex
	projectID string

	// client talks to the Atlas Admin API and serves both planes; org-level
	// calls take the org id and project-level calls take a project (group) id.
	client *admin.APIClient
}

func NewMongoDBAtlasConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*MongoDBAtlasConnection, error) {
	conn := &MongoDBAtlasConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		orgID:      conf.Options[OptionOrgID],
		projectID:  conf.Options[OptionProjectID],
	}

	// A project id scopes the asset to a single project; otherwise it is the
	// organization (which discovers its projects).
	conn.plane = conf.Options[OptionPlane]
	if conn.plane == "" {
		if conn.projectID != "" {
			conn.plane = PlaneProject
		} else {
			conn.plane = PlaneOrg
		}
	}

	publicKey := conf.Options[OptionPublicKey]
	clientID := conf.Options[OptionClientID]
	privateKey, clientSecret := credentials(conf)

	var modifier admin.ClientModifier
	switch {
	case publicKey != "" && privateKey != "":
		modifier = admin.UseDigestAuth(publicKey, privateKey)
	case clientID != "" && clientSecret != "":
		modifier = admin.UseOAuthAuth(context.Background(), clientID, clientSecret)
	default:
		return nil, errors.New("MongoDB Atlas credentials required: set --public-key/--private-key (programmatic API key) or --client-id/--client-secret (service account)")
	}

	client, err := admin.NewClient(modifier)
	if err != nil {
		return nil, errors.Join(errors.New("failed to create MongoDB Atlas client"), err)
	}
	conn.client = client

	return conn, nil
}

// credentials extracts the API key private key and the service account client
// secret from the connection config, distinguished by the credential user tag.
func credentials(conf *inventory.Config) (privateKey string, clientSecret string) {
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			continue
		}
		switch cred.User {
		case CredentialPrivateKey:
			privateKey = string(cred.Secret)
		case CredentialClientSecret:
			clientSecret = string(cred.Secret)
		}
	}
	return
}

func (c *MongoDBAtlasConnection) Name() string {
	return "mongodbatlas"
}

func (c *MongoDBAtlasConnection) Asset() *inventory.Asset {
	return c.asset
}

// Plane reports whether this connection targets an organization or a project.
func (c *MongoDBAtlasConnection) Plane() string {
	return c.plane
}

// OrgID returns the Atlas organization id (empty until resolved).
func (c *MongoDBAtlasConnection) OrgID() string {
	return c.orgID
}

// EnsureOrgID returns the organization id, deriving it once from the accessible
// organizations when it was not supplied on the command line. It is safe to
// call concurrently from multiple resource accessors.
func (c *MongoDBAtlasConnection) EnsureOrgID(ctx context.Context) (string, error) {
	c.orgIDMu.Lock()
	defer c.orgIDMu.Unlock()
	if c.orgID != "" {
		return c.orgID, nil
	}
	orgs, _, err := c.client.OrganizationsAPI.ListOrgs(ctx).Execute()
	if err != nil {
		return "", err
	}
	results := orgs.GetResults()
	if len(results) == 0 {
		return "", errors.New("no accessible MongoDB Atlas organizations; pass --org-id")
	}
	c.orgID = results[0].GetId()
	return c.orgID, nil
}

// ProjectID returns the Atlas project (group) id for project-plane connections.
func (c *MongoDBAtlasConnection) ProjectID() string {
	return c.projectID
}

// Client returns the Atlas Admin API client.
func (c *MongoDBAtlasConnection) Client() *admin.APIClient {
	return c.client
}
