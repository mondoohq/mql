// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"golang.org/x/oauth2/clientcredentials"
)

// Flag Options
const (
	OPTION_CLIENT_ID     = "client-id"
	OPTION_CLIENT_SECRET = "client-secret"
	OPTION_API_URL       = "api-url"
	OPTION_IDENTITY_URL  = "identity-url"
)

// Bitwarden environment variables
const (
	BITWARDEN_CLIENT_ID_VAR     = "BITWARDEN_CLIENT_ID"
	BITWARDEN_CLIENT_SECRET_VAR = "BITWARDEN_CLIENT_SECRET"
	BITWARDEN_API_URL_VAR       = "BITWARDEN_API_URL"
	BITWARDEN_IDENTITY_URL_VAR  = "BITWARDEN_IDENTITY_URL"
)

const (
	defaultApiUrl      = "https://api.bitwarden.com/public"
	defaultIdentityUrl = "https://identity.bitwarden.com/connect/token"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/bitwarden.json so the CLI and generated docs can
// list what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "bitwarden", Title: "Bitwarden Organization", Family: []string{"bitwarden"}, Kind: []string{"api"}, Runtime: []string{"bitwarden"}},
}

type BitwardenConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *Client
	orgID  string

	// memberCache memoizes the organization member list for the lifetime of
	// the connection. The member-to-collection access flags are only exposed
	// on the member record, so a query like
	// `bitwarden.collections { members memberAccess }` would otherwise issue
	// two full member-list calls per collection; caching collapses that to a
	// single call for the whole scan.
	membersOnce sync.Once
	members     []Member
	membersErr  error
}

func NewBitwardenConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*BitwardenConnection, error) {
	conn := &BitwardenConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	clientID := os.Getenv(BITWARDEN_CLIENT_ID_VAR)
	clientSecret := os.Getenv(BITWARDEN_CLIENT_SECRET_VAR)
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			clientSecret = string(cred.Secret)
		}
	}
	if v, ok := conf.Options[OPTION_CLIENT_ID]; ok && v != "" {
		clientID = v
	}
	if clientID == "" || clientSecret == "" {
		return nil, errors.New(
			"a Bitwarden organization client ID and client secret are required " +
				"(set BITWARDEN_CLIENT_ID/BITWARDEN_CLIENT_SECRET, or use --client-id/--client-secret)")
	}

	apiUrl := firstNonEmpty(conf.Options[OPTION_API_URL], os.Getenv(BITWARDEN_API_URL_VAR), defaultApiUrl)
	identityUrl := firstNonEmpty(conf.Options[OPTION_IDENTITY_URL], os.Getenv(BITWARDEN_IDENTITY_URL_VAR), defaultIdentityUrl)

	// client_id has the form "organization.<uuid>"; extract the org UUID for
	// use as the __id of the root organization resource and the platform ID,
	// since the Public API has no endpoint that returns it directly.
	conn.orgID = orgIDFromClientID(clientID)

	oauthConf := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     identityUrl,
		Scopes:       []string{"api.organization"},
	}

	conn.client = NewClient(apiUrl, oauthConf.Client(context.Background()))

	return conn, nil
}

func (c *BitwardenConnection) Name() string {
	return "bitwarden"
}

func (c *BitwardenConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the Bitwarden Public API client for this connection.
func (c *BitwardenConnection) Client() *Client {
	return c.client
}

// OrgID returns the organization UUID this connection authenticates as, as
// extracted from the client ID.
func (c *BitwardenConnection) OrgID() string {
	return c.orgID
}

// ListMembersCached returns the organization member list, fetching it from the
// Public API exactly once per connection and reusing the result on subsequent
// calls. Use this instead of Client().ListMembers when the same list may be
// read by several accessors during a single scan (e.g. per-collection member
// and access lookups) to avoid redundant API calls.
func (c *BitwardenConnection) ListMembersCached(ctx context.Context) ([]Member, error) {
	c.membersOnce.Do(func() {
		c.members, c.membersErr = c.client.ListMembers(ctx)
	})
	return c.members, c.membersErr
}

// Verify validates the client-credentials by issuing the cheapest
// authenticated read available on the Public API. There is no dedicated
// "get organization" endpoint, so the policies list (typically small, and
// present on every Teams/Enterprise organization) doubles as the auth check.
func (c *BitwardenConnection) Verify() error {
	_, err := c.client.ListPolicies(context.Background())
	if err != nil {
		return errors.Wrap(err, "failed to verify Bitwarden credentials")
	}
	return nil
}

// orgIDFromClientID extracts the organization UUID from a Bitwarden
// organization client ID of the form "organization.<uuid>". If the client ID
// doesn't match that shape, it is returned unchanged so a platform ID is
// still produced.
func orgIDFromClientID(clientID string) string {
	if _, id, ok := strings.Cut(clientID, "."); ok {
		return id
	}
	return clientID
}

// firstNonEmpty returns the first non-empty string among vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
