// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// NetworkZone replaces okta.NetworkZone to handle the polymorphic API response.
//
// The Okta API returns different JSON shapes depending on zone type:
//   - IP zones:      gateways/proxies are [{type, value}], locations/asns are absent
//   - DYNAMIC zones: locations is [{country, region}], asns is ["string"]
//   - DYNAMIC_V2:    locations is {include: [...], exclude: [...]}, asns is {include: [...], exclude: [...]}
//
// The upstream SDK (v2) only handles DYNAMIC. DYNAMIC_V2 zones (including the
// system-default DefaultEnhancedDynamicZone) cause json.Unmarshal to fail because
// an object cannot be decoded into []*NetworkZoneLocation.
//
// We use json.RawMessage for all polymorphic fields and normalize them after decoding.
type NetworkZone struct {
	Links       any             `json:"_links,omitempty"`
	Asns        json.RawMessage `json:"asns,omitempty"`
	Created     *time.Time      `json:"created,omitempty"`
	Gateways    json.RawMessage `json:"gateways,omitempty"`
	Id          string          `json:"id,omitempty"`
	LastUpdated *time.Time      `json:"lastUpdated,omitempty"`
	Locations   json.RawMessage `json:"locations,omitempty"`
	Name        string          `json:"name,omitempty"`
	Proxies     json.RawMessage `json:"proxies,omitempty"`
	ProxyType   string          `json:"proxyType,omitempty"`
	Status      string          `json:"status,omitempty"`
	System      *bool           `json:"system,omitempty"`
	Type        string          `json:"type,omitempty"`
	Usage       string          `json:"usage,omitempty"`
}

// NormalizeArrayField decodes a polymorphic JSON field into []any.
// It handles two shapes:
//   - Array:  [item1, item2, ...]                    → returned as-is
//   - Object: {include: [...], exclude: [...]}       → returns the include array
//   - null / empty                                   → returns nil
func NormalizeArrayField(raw json.RawMessage) ([]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	// Try array first (IP and DYNAMIC zone types).
	var arr []any
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}

	// Fall back to include/exclude object (DYNAMIC_V2 zone type).
	var obj struct {
		Include []any `json:"include"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("cannot decode network zone field: expected array or {include, exclude} object, got: %s", truncateJSON(raw))
	}
	return obj.Include, nil
}

// NormalizeStringArrayField decodes a polymorphic JSON field into []string.
// Same shape handling as NormalizeArrayField but typed for string arrays (asns).
func NormalizeStringArrayField(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	// Try flat string array first (DYNAMIC zone type).
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}

	// Fall back to include/exclude object (DYNAMIC_V2 zone type).
	var obj struct {
		Include []string `json:"include"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("cannot decode network zone asns field: expected string array or {include, exclude} object, got: %s", truncateJSON(raw))
	}
	return obj.Include, nil
}

func truncateJSON(raw json.RawMessage) string {
	const maxLen = 120
	s := string(raw)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ListNetworkZones fetches all network zones, following Okta's
// `Link: <url>; rel="next"` pagination.
func (m *ApiExtension) ListNetworkZones(ctx context.Context, limit int) ([]*NetworkZone, error) {
	path := "/api/v1/zones"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	nextURL := m.url(path)

	var zones []*NetworkZone
	for nextURL != "" {
		var page []*NetworkZone
		resp, err := m.get(ctx, nextURL, &page)
		if err != nil {
			return nil, err
		}
		zones = append(zones, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return zones, nil
}

// GetNetworkZone fetches a single network zone by ID.
func (m *ApiExtension) GetNetworkZone(ctx context.Context, zoneId string) (*NetworkZone, error) {
	var zone *NetworkZone
	if _, err := m.get(ctx, m.url(fmt.Sprintf("/api/v1/zones/%v", zoneId)), &zone); err != nil {
		return nil, err
	}
	return zone, nil
}
