// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/custom_hostnames"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareZoneCustomHostname) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZone) customHostnames() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.CustomHostnames.ListAutoPaging(context.TODO(), custom_hostnames.CustomHostnameListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.customHostname", map[string]*llx.RawData{
			"id":                 llx.StringData(rec.ID),
			"hostname":           llx.StringData(rec.Hostname),
			"customOriginServer": llx.StringData(rec.CustomOriginServer),
			"customOriginSni":    llx.StringData(rec.CustomOriginSNI),
			"status":             llx.StringData(string(rec.Status)),
			"sslStatus":          llx.StringData(string(rec.SSL.Status)),
			"sslMethod":          llx.StringData(string(rec.SSL.Method)),
			"sslType":            llx.StringData(string(rec.SSL.Type)),
			"createdAt":          timeOrNil(rec.CreatedAt),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
