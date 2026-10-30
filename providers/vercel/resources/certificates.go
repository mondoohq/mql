// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/types"
)

type certRecord struct {
	ID        string   `json:"id"`
	Cns       []string `json:"cns"`
	AutoRenew bool     `json:"autoRenew"`
	CreatedAt flexTime `json:"createdAt"`
	ExpiresAt flexTime `json:"expiresAt"`
}

func (c *mqlVercelTeam) certificates() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[certRecord](context.Background(), conn, "/v7/certs", connection.TeamQuery(c.Id.Data), "certs")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Certificates.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		cert, err := CreateResource(c.MqlRuntime, "vercel.certificate", map[string]*llx.RawData{
			"id":          llx.StringData(rec.ID),
			"commonNames": llx.ArrayData(strSliceToAny(rec.Cns), types.String),
			"autoRenew":   llx.BoolData(rec.AutoRenew),
			"createdAt":   llx.TimeDataPtr(rec.CreatedAt.Time()),
			"expiresAt":   llx.TimeDataPtr(rec.ExpiresAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, cert)
	}
	return res, nil
}

func (c *mqlVercelCertificate) id() (string, error) {
	return c.Id.Data, c.Id.Error
}
