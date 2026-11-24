// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/custom_hostnames"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareZoneCustomHostname) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// customHostnameSSLArgs maps a custom hostname's SSL block onto resource
// fields. A value the API omitted, including every value of an absent SSL
// block, reads as null; the existing sslStatus, sslMethod and sslType fields
// keep reading empty in that case.
func customHostnameSSLArgs(s custom_hostnames.CustomHostnameListResponseSSL) map[string]*llx.RawData {
	ciphers := llx.NilData
	if !s.Settings.JSON.Ciphers.IsNull() {
		ciphers = llx.ArrayData(convert.SliceAnyToInterface(s.Settings.Ciphers), types.String)
	}
	return map[string]*llx.RawData{
		"sslStatus": llx.StringData(string(s.Status)),
		"sslMethod": llx.StringData(string(s.Method)),
		"sslType":   llx.StringData(string(s.Type)),

		"sslMinTlsVersion":        tokenStringOrNil(string(s.Settings.MinTLSVersion), s.Settings.JSON.MinTLSVersion.IsNull()),
		"sslCiphers":              ciphers,
		"sslTls13":                tokenStringOrNil(string(s.Settings.TLS1_3), s.Settings.JSON.TLS1_3.IsNull()),
		"sslExpiresOn":            timeOrNil(s.ExpiresOn),
		"sslIssuer":               tokenStringOrNil(s.Issuer, s.JSON.Issuer.IsNull()),
		"sslCertificateAuthority": tokenStringOrNil(string(s.CertificateAuthority), s.JSON.CertificateAuthority.IsNull()),
		"sslWildcard":             boolOrNil(s.Wildcard, s.JSON.Wildcard.IsNull()),
	}
}

func (c *mqlCloudflareZone) customHostnames() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.CustomHostnames.ListAutoPaging(context.TODO(), custom_hostnames.CustomHostnameListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		rec := iter.Current()

		args := customHostnameSSLArgs(rec.SSL)
		args["id"] = llx.StringData(rec.ID)
		args["hostname"] = llx.StringData(rec.Hostname)
		args["customOriginServer"] = llx.StringData(rec.CustomOriginServer)
		args["customOriginSni"] = llx.StringData(rec.CustomOriginSNI)
		args["status"] = llx.StringData(string(rec.Status))
		args["createdAt"] = timeOrNil(rec.CreatedAt)

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.customHostname", args)
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
