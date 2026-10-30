// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/url"
	"sync"

	"github.com/cockroachdb/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// userIndexPageSize is the page size used when building the account user index.
const userIndexPageSize = 300

// zoomTokenURL is the Server-to-Server OAuth token endpoint.
const zoomTokenURL = "https://zoom.us/oauth/token"

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/zoom.json so the CLI and generated docs can
// list what the provider supports. Add an entry here for every platform your
// asset discovery produces.
var Platforms = []*plugin.PlatformInfo{
	{Name: "zoom", Title: "Zoom", Family: []string{"zoom"}, Kind: []string{"api"}, Runtime: []string{"zoom"}},
}

type ZoomConnection struct {
	plugin.Connection
	Conf      *inventory.Config
	asset     *inventory.Asset
	accountID string
	client    *Client

	userIndexLock sync.Mutex
	userIndex     map[string]*User

	groupIndexLock sync.Mutex
	groupIndex     map[string]*Group

	roleIndexLock sync.Mutex
	roleIndex     map[string]*Role
}

func NewZoomConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ZoomConnection, error) {
	conn := &ZoomConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	accountID, ok := GetAccountID(conf)
	if !ok {
		return nil, errors.New("a Zoom account ID is required, set ZOOM_ACCOUNT_ID or use --account-id")
	}
	clientID, ok := GetClientID(conf)
	if !ok {
		return nil, errors.New("a Zoom client ID is required, set ZOOM_CLIENT_ID or use --client-id")
	}
	clientSecret, ok := GetClientSecret(conf)
	if !ok {
		return nil, errors.New("a Zoom client secret is required, set ZOOM_CLIENT_SECRET or use --client-secret")
	}
	conn.accountID = accountID

	oauthCfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     zoomTokenURL,
		AuthStyle:    oauth2.AuthStyleInHeader,
		EndpointParams: url.Values{
			"grant_type": {"account_credentials"},
			"account_id": {accountID},
		},
	}
	httpClient := oauthCfg.Client(context.Background())
	conn.client = newClient(httpClient)

	return conn, nil
}

func (c *ZoomConnection) Name() string {
	return "zoom"
}

func (c *ZoomConnection) Asset() *inventory.Asset {
	return c.asset
}

// AccountID returns the Zoom account ID this connection targets.
func (c *ZoomConnection) AccountID() string {
	return c.accountID
}

// Client returns the authenticated Zoom API client.
func (c *ZoomConnection) Client() *Client {
	return c.client
}

// UserIndex returns every account user keyed by ID, in every provisioning
// status, fetching the roster at most once per connection. Role and group
// membership are returned as bare user IDs; resolving each through this index
// turns a role or group with N members into one roster walk rather than N
// per-member GetUser calls. Users Zoom returns without an ID (pending users
// have none) are not indexable by ID and are left out of the index; callers
// that need them read the roster directly. On error the index is not cached,
// so a later call can retry.
func (c *ZoomConnection) UserIndex(ctx context.Context) (map[string]*User, error) {
	c.userIndexLock.Lock()
	defer c.userIndexLock.Unlock()
	if c.userIndex != nil {
		return c.userIndex, nil
	}

	users, err := c.client.ListAllUsers(ctx, userIndexPageSize)
	if err != nil {
		return nil, err
	}

	index := make(map[string]*User, len(users))
	for i := range users {
		if users[i].ID == "" {
			continue
		}
		index[users[i].ID] = &users[i]
	}

	c.userIndex = index
	return c.userIndex, nil
}

// GroupIndex returns every group on the account keyed by ID, fetching the
// list at most once per connection. Group references arrive as bare IDs on
// users and on the two-factor settings; resolving them through this index
// costs one List Groups call for the whole connection instead of one Get
// Group call per reference. On error the index is not cached, so a later call
// can retry.
func (c *ZoomConnection) GroupIndex(ctx context.Context) (map[string]*Group, error) {
	c.groupIndexLock.Lock()
	defer c.groupIndexLock.Unlock()
	if c.groupIndex != nil {
		return c.groupIndex, nil
	}

	list, err := c.client.ListGroups(ctx)
	if err != nil {
		return nil, err
	}

	index := make(map[string]*Group, len(list.Groups))
	for i := range list.Groups {
		index[list.Groups[i].ID] = &list.Groups[i]
	}

	c.groupIndex = index
	return c.groupIndex, nil
}

// RoleIndex returns every role on the account keyed by ID, fetching the list
// at most once per connection, for the same reason as GroupIndex: a role
// reference on a user is a bare ID, and an account-wide roster of users would
// otherwise cost one Get Role call each.
func (c *ZoomConnection) RoleIndex(ctx context.Context) (map[string]*Role, error) {
	c.roleIndexLock.Lock()
	defer c.roleIndexLock.Unlock()
	if c.roleIndex != nil {
		return c.roleIndex, nil
	}

	list, err := c.client.ListRoles(ctx)
	if err != nil {
		return nil, err
	}

	index := make(map[string]*Role, len(list.Roles))
	for i := range list.Roles {
		index[list.Roles[i].ID] = &list.Roles[i]
	}

	c.roleIndex = index
	return c.roleIndex, nil
}

// Verify validates the Server-to-Server OAuth credentials by issuing the
// cheapest authenticated read against the API.
func (c *ZoomConnection) Verify() error {
	_, err := c.client.GetMe(context.Background())
	if err != nil {
		return errors.Wrap(err, "failed to verify Zoom credentials")
	}
	return nil
}
