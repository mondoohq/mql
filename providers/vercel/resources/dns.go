// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
)

// mqlVercelDomainInternal caches the team a domain belongs to so DNS records can
// be listed with the correct team scope.
type mqlVercelDomainInternal struct {
	teamID string
}

type dnsRecordRecord struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	TTL        *int64   `json:"ttl"`
	MxPriority *int64   `json:"mxPriority"`
	CreatedAt  flexTime `json:"createdAt"`
	UpdatedAt  flexTime `json:"updatedAt"`
}

func (d *mqlVercelDomain) records() ([]any, error) {
	conn := d.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[dnsRecordRecord](context.Background(), conn, "/v4/domains/"+d.Name.Data+"/records", connection.TeamQuery(d.teamID), "records")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			d.Records.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		record, err := CreateResource(d.MqlRuntime, "vercel.dnsRecord", map[string]*llx.RawData{
			"id":         llx.StringData(rec.ID),
			"name":       llx.StringData(rec.Name),
			"recordType": llx.StringData(rec.Type),
			"value":      llx.StringData(rec.Value),
			"ttl":        llx.IntDataPtr(rec.TTL),
			"mxPriority": llx.IntDataPtr(rec.MxPriority),
			"createdAt":  llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":  llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, record)
	}
	return res, nil
}

func (c *mqlVercelDnsRecord) id() (string, error) {
	return c.Id.Data, c.Id.Error
}
