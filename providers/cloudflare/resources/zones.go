// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"errors"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/ssl"
	"github.com/cloudflare/cloudflare-go/v7/zones"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareZone) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func initCloudflareZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		resource, err := CreateResource(runtime, "cloudflare.zone", args)
		if err != nil {
			return nil, nil, err
		}
		return args, resource, nil
	}

	conn := runtime.Connection.(*connection.CloudflareConnection)

	if conn.Asset() == nil {
		return nil, nil, errors.New("no asset found")
	}

	for _, platformId := range conn.Asset().PlatformIds {
		if zoneId, ok := strings.CutPrefix(platformId, connection.PlatformIdCloudflareZone); ok {
			zone, ok := runtime.Resources.Get("cloudflare.zone\x00" + zoneId)
			if !ok {
				return nil, nil, errors.New("zone not found")
			}

			return args, zone, nil
		}
	}
	return nil, nil, errors.New("zone not found or asset not set")
}

func (c *mqlCloudflareZoneAccount) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZoneOwner) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// normalizeZoneName folds a zone or domain name to the form zone names are
// compared in: lower case, without surrounding space or a trailing root dot.
func normalizeZoneName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// indexZonesByName keys a zone list by normalized zone name.
func indexZonesByName(list []any) map[string]*mqlCloudflareZone {
	byName := make(map[string]*mqlCloudflareZone, len(list))
	for _, entry := range list {
		zone, ok := entry.(*mqlCloudflareZone)
		if !ok {
			continue
		}
		byName[normalizeZoneName(zone.Name.Data)] = zone
	}
	return byName
}

// listedZones returns the zones the connection can list, reusing the root zone
// list so resolving many names costs one list call in total.
func listedZones(runtime *plugin.Runtime) ([]any, error) {
	cf, err := CreateResource(runtime, "cloudflare", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := cf.(*mqlCloudflare).GetZones()
	if list.Error != nil {
		return nil, list.Error
	}
	return list.Data, nil
}

// listedZonesByName indexes the zones the connection can list by name.
func listedZonesByName(runtime *plugin.Runtime) (map[string]*mqlCloudflareZone, error) {
	list, err := listedZones(runtime)
	if err != nil {
		return nil, err
	}
	return indexZonesByName(list), nil
}

// zoneNamed finds the zone with the given name in a zone list. The same name
// can be added to more than one account, so a zone owned by accountID wins over
// one owned by another account. It returns nil when no zone has the name.
func zoneNamed(list []any, name, accountID string) *mqlCloudflareZone {
	key := normalizeZoneName(name)
	if key == "" {
		return nil
	}
	var fallback *mqlCloudflareZone
	for _, entry := range list {
		zone, ok := entry.(*mqlCloudflareZone)
		if !ok || normalizeZoneName(zone.Name.Data) != key {
			continue
		}
		if acc := zone.Account.Data; acc != nil && acc.Id.Data == accountID {
			return zone
		}
		if fallback == nil {
			fallback = zone
		}
	}
	return fallback
}

// zonesNamed resolves zone names against an index, in the order given,
// skipping duplicates and names with no zone in the index.
func zonesNamed(names []string, byName map[string]*mqlCloudflareZone) []any {
	out := make([]any, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		key := normalizeZoneName(name)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if zone, ok := byName[key]; ok {
			out = append(out, zone)
		}
	}
	return out
}

// zoneActivatedOn returns the zone's activation time, or null for a zone that
// has not been activated yet (the API reports activated_on as null).
func zoneActivatedOn(zone zones.Zone) *llx.RawData {
	return timeOrNil(zone.ActivatedOn)
}

// sslReadPermission is the API token permission the Universal SSL settings
// endpoint requires.
const sslReadPermission = "SSL and Certificates Read"

// universalSslEnabled reports whether Universal SSL is enabled for the zone.
// Every plan has this setting, so a refusal is returned as an error rather
// than read as "disabled".
func (c *mqlCloudflareZone) universalSslEnabled() (bool, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	settings, err := conn.Cf.SSL.Universal.Settings.Get(context.TODO(), ssl.UniversalSettingGetParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		return false, refusedErr(err, sslReadPermission)
	}
	return settings.Enabled, nil
}
