// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// contentScanningPayload is a custom scan expression, decoded via the client's
// generic Get.
type contentScanningPayload struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
}

type mqlCloudflareZoneContentScanningInternal struct {
	zoneID string
}

// contentScanning reports whether uploads passing through the zone are scanned
// for malicious content, and exposes the custom expressions that point the
// scanner at content objects.
func (c *mqlCloudflareZone) contentScanning() (*mqlCloudflareZoneContentScanning, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result struct {
			// The settings endpoint reports the status as an enabled/disabled
			// string and the change time as a date string, so both are
			// normalized here rather than mapped straight through.
			Value    string `json:"value"`
			Modified string `json:"modified"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/content-upload-scan/settings", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.ContentScanning.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.contentScanning", map[string]*llx.RawData{
		"__id":     llx.StringData("cloudflare.zone.contentScanning@" + c.Id.Data),
		"enabled":  llx.BoolData(strings.EqualFold(env.Result.Value, "enabled")),
		"modified": cfTimeString(env.Result.Modified),
	})
	if err != nil {
		return nil, err
	}

	scanning := res.(*mqlCloudflareZoneContentScanning)
	scanning.zoneID = c.Id.Data
	return scanning, nil
}

func (c *mqlCloudflareZoneContentScanning) payloads() ([]any, error) {
	if c.zoneID == "" {
		return []any{}, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	payloads, err := cfGetPaged[contentScanningPayload](conn, fmt.Sprintf("zones/%s/content-upload-scan/payloads", c.zoneID))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(payloads))
	for i := range payloads {
		p := payloads[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.contentScanning.payload", map[string]*llx.RawData{
			"__id":    llx.StringData("cloudflare.zone.contentScanning.payload@" + c.zoneID + "/" + p.ID),
			"id":      llx.StringData(p.ID),
			"payload": llx.StringData(p.Payload),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
