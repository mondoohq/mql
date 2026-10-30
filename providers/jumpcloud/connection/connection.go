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
)

// ConnectionType is the connector type string for this provider.
const ConnectionType = "jumpcloud"

// JumpcloudConnection holds the authenticated client for a JumpCloud
// organization plus a set of per-type caches. The caches let the typed
// association accessors (for example jumpcloud.user.systems) resolve related
// objects by id against a single full-list fetch, so traversing the membership
// graph never turns into a per-member API call.
type JumpcloudConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *Client
	orgID  string

	// orgOnce guards the lazy resolution of orgID. The platform-id lookup and
	// a resource accessor can both reach OrganizationID concurrently.
	orgOnce sync.Once
	orgErr  error

	users        listCache[SystemUser]
	systems      listCache[System]
	userGroups   listCache[Group]
	systemGroups listCache[Group]
	applications listCache[Application]
}

func NewJumpcloudConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*JumpcloudConnection, error) {
	if conf.Type != ConnectionType {
		return nil, errors.New("provider type does not match")
	}

	var apiKey string
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			apiKey = string(cred.Secret)
		}
	}
	if apiKey == "" {
		return nil, errors.New("jumpcloud provider requires an API key, pass --api-key or set JUMPCLOUD_API_KEY")
	}

	orgID := ""
	baseURL := ""
	if conf.Options != nil {
		orgID = conf.Options["org-id"]
		baseURL = conf.Options["url"]
	}

	conn := &JumpcloudConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		orgID:      orgID,
		client:     NewClient(apiKey, orgID, baseURL),
	}

	return conn, nil
}

func (c *JumpcloudConnection) Name() string {
	return "jumpcloud"
}

func (c *JumpcloudConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the authenticated JumpCloud API client.
func (c *JumpcloudConnection) Client() *Client {
	return c.client
}

// OrganizationID returns the organization id, resolving it from the API when it
// was not supplied on the command line. It doubles as the connection's stable
// platform identifier.
//
// The resolution runs at most once. Like listCache, a failure is memoized
// rather than retried: a scan should fail consistently instead of re-querying
// on every accessor that needs the id.
func (c *JumpcloudConnection) OrganizationID() (string, error) {
	c.orgOnce.Do(func() {
		if c.orgID != "" {
			return
		}
		orgs, err := c.client.Organizations(context.Background())
		if err != nil {
			c.orgErr = errors.Join(errors.New("failed to resolve JumpCloud organization id"), err)
			return
		}
		if len(orgs) == 0 || orgs[0].EffectiveID() == "" {
			c.orgErr = errors.New("failed to resolve JumpCloud organization id: empty response")
			return
		}
		c.orgID = orgs[0].EffectiveID()
	})
	return c.orgID, c.orgErr
}

// Users returns the full user list and an id-indexed view, fetched once.
func (c *JumpcloudConnection) Users(ctx context.Context) ([]*SystemUser, map[string]*SystemUser, error) {
	return c.users.load(
		func() ([]*SystemUser, error) { return c.client.SystemUsers(ctx) },
		func(u *SystemUser) string { return u.EffectiveID() },
	)
}

// Systems returns the full system list and an id-indexed view, fetched once.
func (c *JumpcloudConnection) Systems(ctx context.Context) ([]*System, map[string]*System, error) {
	return c.systems.load(
		func() ([]*System, error) { return c.client.Systems(ctx) },
		func(s *System) string { return s.EffectiveID() },
	)
}

// UserGroups returns the full user-group list and an id-indexed view, fetched
// once.
func (c *JumpcloudConnection) UserGroups(ctx context.Context) ([]*Group, map[string]*Group, error) {
	return c.userGroups.load(
		func() ([]*Group, error) { return c.client.UserGroups(ctx) },
		func(g *Group) string { return g.ID },
	)
}

// SystemGroups returns the full system-group list and an id-indexed view,
// fetched once.
func (c *JumpcloudConnection) SystemGroups(ctx context.Context) ([]*Group, map[string]*Group, error) {
	return c.systemGroups.load(
		func() ([]*Group, error) { return c.client.SystemGroups(ctx) },
		func(g *Group) string { return g.ID },
	)
}

// Applications returns the full application list and an id-indexed view,
// fetched once.
func (c *JumpcloudConnection) Applications(ctx context.Context) ([]*Application, map[string]*Application, error) {
	return c.applications.load(
		func() ([]*Application, error) { return c.client.Applications(ctx) },
		func(a *Application) string { return a.ID },
	)
}

// listCache memoizes one full-list fetch and its id index. The first caller
// runs the fetch; every later caller reuses the result, so a query that walks
// the membership graph across many parents still fetches each collection only
// once.
//
// The fetch runs under sync.Once, so a fetch error is memoized too: every
// later call returns the same error without retrying. This is intentional for
// the short-lived scan sessions this provider runs in, where a mid-scan retry
// storm against an already-failing endpoint is worse than failing fast and
// consistently. Do not layer retry logic on top of this; a retry policy
// belongs in the HTTP client, not here.
type listCache[T any] struct {
	once sync.Once
	list []*T
	idx  map[string]*T
	err  error
}

func (lc *listCache[T]) load(fetch func() ([]*T, error), keyOf func(*T) string) ([]*T, map[string]*T, error) {
	lc.once.Do(func() {
		lc.list, lc.err = fetch()
		if lc.err != nil {
			return
		}
		lc.idx = make(map[string]*T, len(lc.list))
		for _, it := range lc.list {
			if k := keyOf(it); k != "" {
				lc.idx[k] = it
			}
		}
	})
	return lc.list, lc.idx, lc.err
}
