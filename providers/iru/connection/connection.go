// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/iru/connection/client"
)

const (
	OptionSubdomain = "subdomain"
)

// iruAPIDomain is the fixed Iru (Kandji) API host suffix. A tenant's API is
// served at https://<subdomain>.api.kandji.io, so the connection only needs
// the subdomain from the user.
const iruAPIDomain = "api.kandji.io"

// normalizeSubdomain reduces user input to the bare tenant subdomain label.
// It accepts a bare subdomain ("mondoo"), a full host ("mondoo.api.kandji.io"),
// or a pasted URL ("https://mondoo.api.kandji.io/") and returns "mondoo" in
// every case, so an operator who supplies the old-style API URL still works.
func normalizeSubdomain(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "."); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// apiURLFromSubdomain builds the tenant API base URL from a subdomain.
func apiURLFromSubdomain(subdomain string) string {
	return "https://" + subdomain + "." + iruAPIDomain
}

// IruConnection holds an authenticated Iru REST client and per-device
// caches populated as we walk the inventory.
type IruConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	Client *client.Client

	// Per-device caches. Each memoizes one fetch per device ID and lets
	// fetches for different devices run concurrently, so iterating
	// `iru.devices { … detail fields … }` across a fleet parallelizes the
	// detail/app/parameter calls instead of serializing every device behind a
	// single mutex held across the network round trip.
	//
	//   details backs most of the iru.device computed methods (filevault,
	//   hardware, volumes, …); deviceApps backs the installed-app listing; and
	//   deviceParams backs the compliance parameters. The profiles list is read
	//   straight off DeviceDetails.InstalledProfiles, so it needs no cache.
	details      keyedMemo[*client.DeviceDetails]
	deviceApps   keyedMemo[[]client.App]
	deviceParams keyedMemo[[]client.Parameter]

	// blueprintsMu / usersMu / libraryItemsMu memoize the tenant-wide listings
	// so the init functions for typed cross-references (device.blueprint,
	// device.user) can resolve a single ID without re-walking the API for
	// every reference.
	blueprintsMu     sync.Mutex
	blueprintsCached []client.Blueprint
	blueprintsErr    error
	blueprintsDone   bool

	usersMu     sync.Mutex
	usersCached []client.User
	usersErr    error
	usersDone   bool

	libraryItemsMu     sync.Mutex
	libraryItemsCached []client.LibraryItem
	libraryItemsErr    error
	libraryItemsDone   bool
}

// NewIruConnection validates the connection config, builds an Iru REST
// client, and returns a ready-to-use connection. It does not contact the
// API; the first request is issued lazily by resource accessors.
func NewIruConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*IruConnection, error) {
	conn := &IruConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	subdomain := normalizeSubdomain(conf.Options[OptionSubdomain])

	var token string
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			token = string(cred.Secret)
			break
		}
	}

	if subdomain == "" || token == "" {
		return nil, errors.New("missing required Iru credentials: subdomain and token")
	}
	// Persist the normalized subdomain so Identifier and detect read the
	// canonical label regardless of what form the user supplied.
	conf.Options[OptionSubdomain] = subdomain

	cl, err := client.New(apiURLFromSubdomain(subdomain), token)
	if err != nil {
		return nil, err
	}
	conn.Client = cl
	return conn, nil
}

func (c *IruConnection) Name() string { return "iru" }

func (c *IruConnection) Asset() *inventory.Asset { return c.asset }

// PlatformInfo returns the asset platform metadata for an Iru tenant.
func (c *IruConnection) PlatformInfo() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "iru"},
	}
	PlatformByName("iru").Apply(p)
	return p
}

// Identifier returns the stable platform ID for the tenant, derived from
// the tenant subdomain. It mirrors the Jamf provider's strategy.
func (c *IruConnection) Identifier() string {
	subdomain := normalizeSubdomain(c.Conf.Options[OptionSubdomain])
	return "//platformid.api.mondoo.app/runtime/iru/" + subdomain
}

// GetDeviceDetails returns the cached detail payload for a device,
// fetching it on first request. Safe for concurrent use.
func (c *IruConnection) GetDeviceDetails(id string) (*client.DeviceDetails, error) {
	return c.details.get(id, func() (*client.DeviceDetails, error) {
		return c.Client.GetDeviceDetails(id)
	})
}

// GetDeviceApps returns the cached installed-app list for a device,
// fetching it on first request. Safe for concurrent use.
func (c *IruConnection) GetDeviceApps(id string) ([]client.App, error) {
	return c.deviceApps.get(id, func() ([]client.App, error) {
		return c.Client.GetDeviceApps(id)
	})
}

// GetDeviceParameters returns the cached compliance-parameter list for a
// device, fetching it on first request. Safe for concurrent use.
func (c *IruConnection) GetDeviceParameters(id string) ([]client.Parameter, error) {
	return c.deviceParams.get(id, func() ([]client.Parameter, error) {
		return c.Client.GetDeviceParameters(id)
	})
}

// keyedMemo memoizes one value per string key, collapsing concurrent fetches
// for the same key into a single call while letting fetches for different keys
// proceed in parallel. singleflight forgets a key once its call returns, so a
// failed fetch is never cached and a later call retries, matching how the
// tenant-wide listings avoid poisoning their cache on a transient error.
type keyedMemo[V any] struct {
	mu    sync.Mutex
	cache map[string]V
	sf    singleflight.Group
}

func (m *keyedMemo[V]) get(key string, fetch func() (V, error)) (V, error) {
	m.mu.Lock()
	if v, ok := m.cache[key]; ok {
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()

	v, err, _ := m.sf.Do(key, func() (any, error) {
		// Re-check under the lock: a concurrent flight for this key may have
		// populated the cache between our fast-path miss and entering the call.
		m.mu.Lock()
		if val, ok := m.cache[key]; ok {
			m.mu.Unlock()
			return val, nil
		}
		m.mu.Unlock()

		val, err := fetch()
		if err != nil {
			// Return without caching so the key is forgotten and retried.
			return val, err
		}
		m.mu.Lock()
		if m.cache == nil {
			m.cache = make(map[string]V)
		}
		m.cache[key] = val
		m.mu.Unlock()
		return val, nil
	})
	if err != nil {
		var zero V
		return zero, err
	}
	return v.(V), nil
}

// ListBlueprints returns the tenant's blueprints, memoizing the first
// successful API response for the lifetime of the connection.
func (c *IruConnection) ListBlueprints() ([]client.Blueprint, error) {
	c.blueprintsMu.Lock()
	defer c.blueprintsMu.Unlock()
	if c.blueprintsDone {
		return c.blueprintsCached, c.blueprintsErr
	}
	c.blueprintsCached, c.blueprintsErr = c.Client.ListBlueprints()
	// Only mark done on success so a transient network error doesn't poison
	// the cache for the connection's lifetime; subsequent calls will retry.
	if c.blueprintsErr == nil {
		c.blueprintsDone = true
	}
	return c.blueprintsCached, c.blueprintsErr
}

// ListUsers returns the tenant's users, memoizing the first successful
// API response for the lifetime of the connection.
func (c *IruConnection) ListUsers() ([]client.User, error) {
	c.usersMu.Lock()
	defer c.usersMu.Unlock()
	if c.usersDone {
		return c.usersCached, c.usersErr
	}
	c.usersCached, c.usersErr = c.Client.ListUsers()
	if c.usersErr == nil {
		c.usersDone = true
	}
	return c.usersCached, c.usersErr
}

// ListLibraryItems returns the tenant's library items, memoizing the
// first successful API response for the lifetime of the connection.
func (c *IruConnection) ListLibraryItems() ([]client.LibraryItem, error) {
	c.libraryItemsMu.Lock()
	defer c.libraryItemsMu.Unlock()
	if c.libraryItemsDone {
		return c.libraryItemsCached, c.libraryItemsErr
	}
	c.libraryItemsCached, c.libraryItemsErr = c.Client.ListLibraryItems()
	if c.libraryItemsErr == nil {
		c.libraryItemsDone = true
	}
	return c.libraryItemsCached, c.libraryItemsErr
}
