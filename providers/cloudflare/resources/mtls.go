// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"errors"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/mtls_certificates"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareMtlsCertificate) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZone) mtlsCertificates() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	acc := c.GetAccount()
	if acc.Error != nil {
		return nil, acc.Error
	}
	if acc.Data == nil {
		return nil, errors.New("cloudflare zone has no associated account")
	}
	accountID := acc.Data.GetId().Data

	var result []any
	iter := conn.Cf.MTLSCertificates.ListAutoPaging(context.TODO(), mtls_certificates.MTLSCertificateListParams{
		AccountID: cloudflare.F(accountID),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.mtlsCertificate", map[string]*llx.RawData{
			"id":           llx.StringData(rec.ID),
			"name":         llx.StringData(rec.Name),
			"issuer":       llx.StringData(rec.Issuer),
			"signature":    llx.StringData(rec.Signature),
			"serialNumber": llx.StringData(rec.SerialNumber),
			"ca":           llx.BoolData(rec.CA),
			"uploadedOn":   llx.TimeData(rec.UploadedOn),
			"expiresAt":    llx.TimeData(rec.ExpiresOn),
			// cloudflare-go's mTLS certificate response no longer exposes a
			// separate "updated" timestamp, so this field is always null.
			"updatedAt": llx.NilData,
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
