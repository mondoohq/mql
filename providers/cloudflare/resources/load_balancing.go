// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// loadBalancer and loadBalancerPool mirror the Cloudflare load-balancing API
// responses. We decode them via the client's generic Get so the typed pool
// references can be resolved in memory without depending on the (substantially
// different) cloudflare-go load-balancer types.
type loadBalancer struct {
	ID                        string              `json:"id"`
	Name                      string              `json:"name"`
	Description               string              `json:"description"`
	Enabled                   *bool               `json:"enabled"`
	Proxied                   bool                `json:"proxied"`
	TTL                       int64               `json:"ttl"`
	SteeringPolicy            string              `json:"steering_policy"`
	FallbackPool              string              `json:"fallback_pool"`
	DefaultPools              []string            `json:"default_pools"`
	RegionPools               map[string][]string `json:"region_pools"`
	PopPools                  map[string][]string `json:"pop_pools"`
	CountryPools              map[string][]string `json:"country_pools"`
	Persistence               string              `json:"session_affinity"`
	PersistenceTTL            int64               `json:"session_affinity_ttl"`
	SessionAffinityAttributes *struct {
		SameSite             string   `json:"samesite"`
		Secure               string   `json:"secure"`
		DrainDuration        int64    `json:"drain_duration"`
		ZeroDowntimeFailover string   `json:"zero_downtime_failover"`
		Headers              []string `json:"headers"`
		RequireAllHeaders    bool     `json:"require_all_headers"`
	} `json:"session_affinity_attributes"`
	CreatedOn  *time.Time `json:"created_on"`
	ModifiedOn *time.Time `json:"modified_on"`
}

type loadBalancerPool struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Enabled           bool   `json:"enabled"`
	MinimumOrigins    *int   `json:"minimum_origins"`
	Monitor           string `json:"monitor"`
	NotificationEmail string `json:"notification_email"`
	Origins           []struct {
		Name             string  `json:"name"`
		Address          string  `json:"address"`
		Enabled          bool    `json:"enabled"`
		Weight           float64 `json:"weight"`
		VirtualNetworkID string  `json:"virtual_network_id"`
	} `json:"origins"`
	CheckRegions []string   `json:"check_regions"`
	Latitude     *float64   `json:"latitude"`
	Longitude    *float64   `json:"longitude"`
	CreatedOn    *time.Time `json:"created_on"`
	ModifiedOn   *time.Time `json:"modified_on"`
}

type mqlCloudflareZoneLoadBalancerInternal struct {
	// lb caches the load balancer record so the pool accessors can read its
	// fallback/default/geo pool ID lists.
	lb loadBalancer
	// poolIndex maps every account pool ID to its record, so pool references
	// resolve in memory without a per-pool API call.
	poolIndex map[string]loadBalancerPool
}

func (c *mqlCloudflareZoneLoadBalancer) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// poolMapDict converts a region/pop/country pool map into a dict-safe map.
func poolMapDict(m map[string][]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		ids := make([]any, len(v))
		for i, id := range v {
			ids[i] = id
		}
		out[k] = ids
	}
	return out
}

func (c *mqlCloudflareZone) loadBalancers() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	lbs, err := cfGetPaged[loadBalancer](conn, fmt.Sprintf("zones/%s/load_balancers", c.Id.Data))
	if err != nil {
		// Load balancing is a paid add-on; treat a missing subscription as "no
		// load balancers" rather than failing the whole zone query.
		if isUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}
	if len(lbs) == 0 {
		return []any{}, nil
	}

	// Pools are account-scoped and shared across load balancers; fetch them
	// once so the typed pool accessors resolve in memory.
	poolIndex := map[string]loadBalancerPool{}
	if acc := c.GetAccount(); acc.Error != nil || acc.Data == nil {
		// Without the account ID the pool list cannot be fetched; warn so the
		// empty pool references are not mistaken for "no pools configured".
		log.Warn().Msg("cloudflare> could not resolve the zone's account; load balancer pool references will be empty")
	} else {
		pools, err := cfGetPaged[loadBalancerPool](conn, fmt.Sprintf("accounts/%s/load_balancers/pools", acc.Data.Id.Data))
		if err != nil && !isUnavailable(err) {
			return nil, err
		}
		for i := range pools {
			poolIndex[pools[i].ID] = pools[i]
		}
	}

	var result []any
	for i := range lbs {
		lb := lbs[i]

		saa := map[string]any{}
		if lb.SessionAffinityAttributes != nil {
			a := lb.SessionAffinityAttributes
			headers := make([]any, len(a.Headers))
			for j, h := range a.Headers {
				headers[j] = h
			}
			saa = map[string]any{
				"samesite":             a.SameSite,
				"secure":               a.Secure,
				"drainDuration":        a.DrainDuration,
				"zeroDowntimeFailover": a.ZeroDowntimeFailover,
				"headers":              headers,
				"requireAllHeaders":    a.RequireAllHeaders,
			}
		}

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.loadBalancer", map[string]*llx.RawData{
			"id":                        llx.StringData(lb.ID),
			"name":                      llx.StringData(lb.Name),
			"description":               llx.StringData(lb.Description),
			"enabled":                   llx.BoolDataPtr(lb.Enabled),
			"proxied":                   llx.BoolData(lb.Proxied),
			"ttl":                       llx.IntData(lb.TTL),
			"steeringPolicy":            llx.StringData(lb.SteeringPolicy),
			"regionPools":               llx.DictData(poolMapDict(lb.RegionPools)),
			"popPools":                  llx.DictData(poolMapDict(lb.PopPools)),
			"countryPools":              llx.DictData(poolMapDict(lb.CountryPools)),
			"sessionAffinity":           llx.StringData(lb.Persistence),
			"sessionAffinityTtl":        llx.IntData(lb.PersistenceTTL),
			"sessionAffinityAttributes": llx.DictData(saa),
			"createdOn":                 llx.TimeDataPtr(lb.CreatedOn),
			"modifiedOn":                llx.TimeDataPtr(lb.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}
		mqlLB := res.(*mqlCloudflareZoneLoadBalancer)
		mqlLB.lb = lb
		mqlLB.poolIndex = poolIndex
		result = append(result, mqlLB)
	}
	return result, nil
}

// --- pool typed references ---

func (c *mqlCloudflareZoneLoadBalancer) fallbackPool() (*mqlCloudflareLoadBalancerPool, error) {
	pool, ok := c.poolIndex[c.lb.FallbackPool]
	if !ok {
		c.FallbackPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlCloudflareLoadBalancerPool(c.MqlRuntime, pool)
}

func (c *mqlCloudflareZoneLoadBalancer) defaultPools() ([]any, error) {
	return c.resolvePools(c.lb.DefaultPools)
}

func (c *mqlCloudflareZoneLoadBalancer) pools() ([]any, error) {
	// Union of every pool ID the load balancer references, in a stable order:
	// default pools first, then the fallback, then the geo-steering maps.
	var ordered []string
	ordered = append(ordered, c.lb.DefaultPools...)
	if c.lb.FallbackPool != "" {
		ordered = append(ordered, c.lb.FallbackPool)
	}
	for _, m := range []map[string][]string{c.lb.RegionPools, c.lb.PopPools, c.lb.CountryPools} {
		for _, ids := range m {
			ordered = append(ordered, ids...)
		}
	}
	return c.resolvePools(ordered)
}

// resolvePools builds pool resources for the given IDs, skipping IDs that are
// not in the account pool index and deduplicating repeated IDs.
func (c *mqlCloudflareZoneLoadBalancer) resolvePools(ids []string) ([]any, error) {
	seen := map[string]struct{}{}
	result := []any{}
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		pool, ok := c.poolIndex[id]
		if !ok {
			continue
		}
		res, err := newMqlCloudflareLoadBalancerPool(c.MqlRuntime, pool)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (c *mqlCloudflareLoadBalancerPool) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func newMqlCloudflareLoadBalancerPool(runtime *plugin.Runtime, p loadBalancerPool) (*mqlCloudflareLoadBalancerPool, error) {
	origins := make([]any, len(p.Origins))
	for i, o := range p.Origins {
		origins[i] = map[string]any{
			"name":             o.Name,
			"address":          o.Address,
			"enabled":          o.Enabled,
			"weight":           o.Weight,
			"virtualNetworkId": o.VirtualNetworkID,
		}
	}

	var minOrigins int64
	if p.MinimumOrigins != nil {
		minOrigins = int64(*p.MinimumOrigins)
	}
	// Latitude/longitude are only set when proximity steering is configured;
	// leave them null otherwise rather than reporting a spurious (0, 0).
	latitude := llx.NilData
	if p.Latitude != nil {
		latitude = llx.FloatData(*p.Latitude)
	}
	longitude := llx.NilData
	if p.Longitude != nil {
		longitude = llx.FloatData(*p.Longitude)
	}

	res, err := NewResource(runtime, "cloudflare.loadBalancerPool", map[string]*llx.RawData{
		"id":                llx.StringData(p.ID),
		"name":              llx.StringData(p.Name),
		"description":       llx.StringData(p.Description),
		"enabled":           llx.BoolData(p.Enabled),
		"minimumOrigins":    llx.IntData(minOrigins),
		"monitorId":         llx.StringData(p.Monitor),
		"notificationEmail": llx.StringData(p.NotificationEmail),
		"origins":           llx.ArrayData(origins, types.Dict),
		"checkRegions":      llx.ArrayData(convert.SliceAnyToInterface(p.CheckRegions), types.String),
		"latitude":          latitude,
		"longitude":         longitude,
		"createdOn":         llx.TimeDataPtr(p.CreatedOn),
		"modifiedOn":        llx.TimeDataPtr(p.ModifiedOn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCloudflareLoadBalancerPool), nil
}
