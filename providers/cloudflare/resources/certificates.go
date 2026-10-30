// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/custom_certificates"
	"github.com/cloudflare/cloudflare-go/v7/origin_ca_certificates"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareZoneCustomCertificate) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZoneCertificatePack) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZone) customCertificates() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.CustomCertificates.ListAutoPaging(context.Background(), custom_certificates.CustomCertificateListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		cert := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.customCertificate", map[string]*llx.RawData{
			"id":           llx.StringData(cert.ID),
			"hosts":        llx.ArrayData(convert.SliceAnyToInterface(cert.Hosts), types.String),
			"issuer":       llx.StringData(cert.Issuer),
			"signature":    llx.StringData(cert.Signature),
			"status":       llx.StringData(string(cert.Status)),
			"bundleMethod": llx.StringData(string(cert.BundleMethod)),
			"expiresAt":    timeOrNil(cert.ExpiresOn),
			"uploadedAt":   timeOrNil(cert.UploadedOn),
			"modifiedAt":   timeOrNil(cert.ModifiedOn),
			"priority":     llx.IntData(int64(cert.Priority)),
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

// certificatePack mirrors a zone SSL certificate-pack list entry. We read the
// endpoint via the client's generic Get with `status=all` so pending/expired
// packs are included (matching the v0 behavior); the cloudflare-go typed
// list does not expose that filter.
type certificatePack struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Hosts                []string `json:"hosts"`
	Status               string   `json:"status"`
	ValidationMethod     string   `json:"validation_method"`
	ValidityDays         int64    `json:"validity_days"`
	CertificateAuthority string   `json:"certificate_authority"`
}

func (c *mqlCloudflareZone) certificatePacks() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	packs, err := cfGetPaged[certificatePack](conn, fmt.Sprintf("zones/%s/ssl/certificate_packs?status=all", c.Id.Data))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range packs {
		pack := packs[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.certificatePack", map[string]*llx.RawData{
			"id":                   llx.StringData(pack.ID),
			"type":                 llx.StringData(pack.Type),
			"hosts":                llx.ArrayData(convert.SliceAnyToInterface(pack.Hosts), types.String),
			"status":               llx.StringData(pack.Status),
			"validationMethod":     llx.StringData(pack.ValidationMethod),
			"validityDays":         llx.IntData(pack.ValidityDays),
			"certificateAuthority": llx.StringData(pack.CertificateAuthority),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}

func (c *mqlCloudflareZoneOriginCACertificate) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZone) originCACertificates() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.OriginCACertificates.ListAutoPaging(context.TODO(), origin_ca_certificates.OriginCACertificateListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		cert := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.originCACertificate", map[string]*llx.RawData{
			"id":              llx.StringData(cert.ID),
			"hostnames":       llx.ArrayData(convert.SliceAnyToInterface(cert.Hostnames), types.String),
			"requestType":     llx.StringData(string(cert.RequestType)),
			"requestValidity": llx.IntData(int64(cert.RequestedValidity)),
			"expiresAt":       timeOrNil(parseRFC3339(cert.ExpiresOn)),
			// cloudflare-go's origin CA certificate list response no longer
			// exposes a revocation timestamp, so this field is always null.
			"revokedAt": llx.NilData,
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
