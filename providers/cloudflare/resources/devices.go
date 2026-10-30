// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareOneDevice) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// teamsDevice is the response shape of the legacy WARP device inventory endpoint
// (`/accounts/{id}/devices`). cloudflare-go marks its typed device list as
// deprecated in favor of newer, differently-shaped endpoints, so we read the
// legacy endpoint via the client's generic Get to preserve the MQL schema.
type teamsDevice struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	DeviceType       string `json:"device_type"`
	Model            string `json:"model"`
	Manufacturer     string `json:"manufacturer"`
	SerialNumber     string `json:"serial_number"`
	MacAddress       string `json:"mac_address"`
	IP               string `json:"ip"`
	OSVersion        string `json:"os_version"`
	OSDistroName     string `json:"os_distro_name"`
	OSDistroRevision string `json:"os_distro_revision"`
	Version          string `json:"version"`
	Deleted          bool   `json:"deleted"`
	Created          string `json:"created"`
	Updated          string `json:"updated"`
	LastSeen         string `json:"last_seen"`
	RevokedAt        string `json:"revoked_at"`
}

func (c *mqlCloudflareOne) devices() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[teamsDevice](conn, fmt.Sprintf("accounts/%s/devices", c.AccountID))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.device", map[string]*llx.RawData{
			"id":               llx.StringData(rec.ID),
			"name":             llx.StringData(rec.Name),
			"deviceType":       llx.StringData(rec.DeviceType),
			"model":            llx.StringData(rec.Model),
			"manufacturer":     llx.StringData(rec.Manufacturer),
			"serialNumber":     llx.StringData(rec.SerialNumber),
			"macAddress":       llx.StringData(rec.MacAddress),
			"ip":               llx.StringData(rec.IP),
			"osVersion":        llx.StringData(rec.OSVersion),
			"osDistroName":     llx.StringData(rec.OSDistroName),
			"osDistroRevision": llx.StringData(rec.OSDistroRevision),
			"version":          llx.StringData(rec.Version),
			"deleted":          llx.BoolData(rec.Deleted),
			"created":          timeOrNil(parseRFC3339(rec.Created)),
			"updated":          timeOrNil(parseRFC3339(rec.Updated)),
			"lastSeen":         timeOrNil(parseRFC3339(rec.LastSeen)),
			"revokedAt":        timeOrNil(parseRFC3339(rec.RevokedAt)),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}

func (c *mqlCloudflareOneDevicePostureRule) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) devicePostureRules() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.Devices.Posture.ListAutoPaging(context.TODO(), zero_trust.DevicePostureListParams{
		AccountID: cloudflare.F(c.AccountID),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.devicePostureRule", map[string]*llx.RawData{
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"type":        llx.StringData(string(rec.Type)),
			"description": llx.StringData(rec.Description),
			"schedule":    llx.StringData(rec.Schedule),
			"expiration":  llx.StringData(rec.Expiration),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

func (c *mqlCloudflareOneDevicePostureIntegration) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) devicePostureIntegrations() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.Devices.Posture.Integrations.ListAutoPaging(context.TODO(), zero_trust.DevicePostureIntegrationListParams{
		AccountID: cloudflare.F(c.AccountID),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.devicePostureIntegration", map[string]*llx.RawData{
			"id":       llx.StringData(rec.ID),
			"name":     llx.StringData(rec.Name),
			"type":     llx.StringData(string(rec.Type)),
			"interval": llx.StringData(rec.Interval),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

// parseRFC3339 parses an RFC3339 timestamp string, returning zero time for empty strings.
func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
