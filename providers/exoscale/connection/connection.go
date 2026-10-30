// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	"github.com/hashicorp/go-retryablehttp"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// requestTimeout bounds a single Exoscale API request. The SDK's default
// HTTP client has no timeout, and the plugin runtime hands resources no
// context to carry a deadline, so without this a request that never answers
// hangs the scan. retryablehttp issues each retry as its own request, so this
// bounds an attempt rather than the whole retried operation.
var requestTimeout = 30 * time.Second

const PlatformIdExoscaleOrganization = "//platformid.api.mondoo.app/runtime/exoscale/organization/"

type ExoscaleConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client *v3.Client
	// zoneFilter restricts the zones queried; empty means every zone.
	zoneFilter []string
	// Filters narrows the listed discovery-target resources by label
	// (--filters), so discovery and queries see the same set.
	Filters DiscoveryFilters

	zonesOnce sync.Once
	zones     []v3.Zone
	zonesErr  error

	org *v3.Organization

	memoMu sync.Mutex
	memo   map[string]*memoEntry
}

type memoEntry struct {
	once sync.Once
	val  any
	err  error
}

func NewExoscaleConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ExoscaleConnection, error) {
	key, secret := GetCredentials(conf)
	if key == "" || secret == "" {
		return nil, fmt.Errorf("an Exoscale API key and secret are required. "+
			"Use the --%s and --%s flags or set the %s and %s environment variables",
			OPTION_API_KEY, OPTION_API_SECRET, EXOSCALE_API_KEY_VAR, EXOSCALE_API_SECRET_VAR)
	}

	client, err := v3.NewClient(
		credentials.NewStaticCredentials(key, secret),
		v3.ClientOptWithHTTPClient(newHTTPClient()),
		v3.ClientOptWithUserAgent("mql-exoscale"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Exoscale client: %w", err)
	}

	return &ExoscaleConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		zoneFilter: GetZones(conf),
		Filters:    DiscoveryFiltersFromOpts(conf.Options),
	}, nil
}

// newHTTPClient keeps the SDK's retrying client (429 and 5xx are retried with
// backoff) and adds a per-attempt timeout.
func newHTTPClient() *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = log.New(io.Discard, "", 0)
	rc.HTTPClient.Timeout = requestTimeout
	return rc.StandardClient()
}

// Verify confirms the credentials work and reads the organization, which
// anchors the asset's platform id.
func (c *ExoscaleConnection) Verify() error {
	org, err := c.client.GetOrganization(context.Background())
	if err != nil {
		if errors.Is(err, v3.ErrUnauthorized) || errors.Is(err, v3.ErrForbidden) {
			return fmt.Errorf("invalid Exoscale API credentials; verify the API key and secret: %w", err)
		}
		return fmt.Errorf("failed to verify Exoscale connection: %w", err)
	}
	c.org = org
	return nil
}

func (c *ExoscaleConnection) Name() string            { return "exoscale" }
func (c *ExoscaleConnection) Asset() *inventory.Asset { return c.asset }
func (c *ExoscaleConnection) Client() *v3.Client      { return c.client }
func (c *ExoscaleConnection) Org() *v3.Organization   { return c.org }

// ZoneClient returns a client bound to the zone's API endpoint. Organization
// wide resources (IAM, security groups, DNS, ...) answer on any endpoint and
// use Client() directly.
func (c *ExoscaleConnection) ZoneClient(z v3.Zone) *v3.Client {
	return c.client.WithEndpoint(z.APIEndpoint)
}

// Zones lists the zones to query, once per connection, narrowed to the
// --zones filter when one is set. A filter naming a zone that does not exist
// is an error rather than a silently smaller scan.
func (c *ExoscaleConnection) Zones() ([]v3.Zone, error) {
	c.zonesOnce.Do(func() {
		res, err := c.client.ListZones(context.Background())
		if err != nil {
			c.zonesErr = err
			return
		}
		c.zones, c.zonesErr = filterZones(res.Zones, c.zoneFilter)
	})
	return c.zones, c.zonesErr
}

func filterZones(all []v3.Zone, filter []string) ([]v3.Zone, error) {
	if len(filter) == 0 {
		return all, nil
	}
	out := make([]v3.Zone, 0, len(filter))
	for _, name := range filter {
		idx := slices.IndexFunc(all, func(z v3.Zone) bool { return string(z.Name) == name })
		if idx < 0 {
			known := make([]string, len(all))
			for i := range all {
				known[i] = string(all[i].Name)
			}
			return nil, fmt.Errorf("unknown Exoscale zone %q (available: %v)", name, known)
		}
		out = append(out, all[idx])
	}
	return out, nil
}

func (c *ExoscaleConnection) PlatformInfo() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"cloud", "exoscale", "organization"},
	}
	PlatformByName("exoscale-organization").Apply(p)
	return p
}

// Identifier is the platform id of the organization.
func (c *ExoscaleConnection) Identifier() string {
	if c.org == nil {
		return PlatformIdExoscaleOrganization
	}
	return PlatformIdExoscaleOrganization + string(c.org.ID)
}

// Memo runs fn once per key for the lifetime of the connection and returns
// its result to every caller. It serves lookups that cannot go through a
// listed collection, such as a public template referenced by many instances.
func (c *ExoscaleConnection) Memo(key string, fn func() (any, error)) (any, error) {
	c.memoMu.Lock()
	if c.memo == nil {
		c.memo = map[string]*memoEntry{}
	}
	e, ok := c.memo[key]
	if !ok {
		e = &memoEntry{}
		c.memo[key] = e
	}
	c.memoMu.Unlock()
	e.once.Do(func() { e.val, e.err = fn() })
	return e.val, e.err
}
