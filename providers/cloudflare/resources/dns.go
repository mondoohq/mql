// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

type mqlCloudflareDnsInternal struct {
	ZoneID string
}

// dnsRecord mirrors a zone DNS record. cloudflare-go models the record list
// as a polymorphic union (and exposes tags as an untyped value), so we decode
// the endpoint via the client's generic Get to keep the existing MQL schema.
type dnsRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Tags       []string  `json:"tags"`
	Proxied    bool      `json:"proxied"`
	Proxiable  bool      `json:"proxiable"`
	Comment    string    `json:"comment"`
	Type       string    `json:"type"`
	Content    string    `json:"content"`
	TTL        int64     `json:"ttl"`
	Priority   float64   `json:"priority"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
}

func (c *mqlCloudflareZone) dns() (*mqlCloudflareDns, error) {
	res, err := CreateResource(c.MqlRuntime, "cloudflare.dns", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.dns@" + c.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	dns := res.(*mqlCloudflareDns)
	dns.ZoneID = c.Id.Data

	return dns, nil
}

func (c *mqlCloudflareDnsRecord) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareDns) records() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[dnsRecord](conn, fmt.Sprintf("zones/%s/dns_records", c.ZoneID))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.dns.record", map[string]*llx.RawData{
			"id":        llx.StringData(rec.ID),
			"name":      llx.StringData(rec.Name),
			"tags":      llx.ArrayData(convert.SliceAnyToInterface(rec.Tags), types.String),
			"proxied":   llx.BoolData(rec.Proxied),
			"proxiable": llx.BoolData(rec.Proxiable),
			"comment":   llx.StringData(rec.Comment),

			"type":     llx.StringData(rec.Type),
			"content":  llx.StringData(rec.Content),
			"ttl":      llx.IntData(rec.TTL),
			"priority": llx.IntData(int64(rec.Priority)),

			"createdOn":  timeOrNil(rec.CreatedOn),
			"modifiedOn": timeOrNil(rec.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}
