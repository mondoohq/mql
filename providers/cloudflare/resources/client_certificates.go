// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// clientCertificate mirrors a zone client certificate, decoded via the client's
// generic Get. The endpoint reports issued_on and expires_on as strings rather
// than timestamps and nests the issuing authority, so we decode our own shape
// and flatten it.
type clientCertificate struct {
	ID                   string `json:"id"`
	CommonName           string `json:"common_name"`
	Status               string `json:"status"`
	IssuedOn             string `json:"issued_on"`
	ExpiresOn            string `json:"expires_on"`
	ValidityDays         int64  `json:"validity_days"`
	FingerprintSha256    string `json:"fingerprint_sha256"`
	SerialNumber         string `json:"serial_number"`
	Signature            string `json:"signature"`
	Ski                  string `json:"ski"`
	Country              string `json:"country"`
	State                string `json:"state"`
	Location             string `json:"location"`
	Organization         string `json:"organization"`
	OrganizationalUnit   string `json:"organizational_unit"`
	CertificateAuthority struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"certificate_authority"`
}

// clientCertificates lists the certificates Cloudflare's managed CA issued for
// mTLS authentication of clients connecting to the zone. The certificate PEM,
// private key, and signing request the endpoint also returns are deliberately
// not exposed.
func (c *mqlCloudflareZone) clientCertificates() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	certs, err := cfGetPaged[clientCertificate](conn, fmt.Sprintf("zones/%s/client_certificates", c.Id.Data))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(certs))
	for i := range certs {
		cert := certs[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.clientCertificate", map[string]*llx.RawData{
			"__id":                     llx.StringData("cloudflare.zone.clientCertificate@" + c.Id.Data + "/" + cert.ID),
			"id":                       llx.StringData(cert.ID),
			"commonName":               llx.StringData(cert.CommonName),
			"status":                   llx.StringData(cert.Status),
			"issuedOn":                 cfTimeString(cert.IssuedOn),
			"expiresOn":                cfTimeString(cert.ExpiresOn),
			"validityDays":             llx.IntData(cert.ValidityDays),
			"fingerprintSha256":        llx.StringData(cert.FingerprintSha256),
			"serialNumber":             llx.StringData(cert.SerialNumber),
			"signature":                llx.StringData(cert.Signature),
			"ski":                      llx.StringData(cert.Ski),
			"certificateAuthorityId":   llx.StringData(cert.CertificateAuthority.ID),
			"certificateAuthorityName": llx.StringData(cert.CertificateAuthority.Name),
			"country":                  llx.StringData(cert.Country),
			"state":                    llx.StringData(cert.State),
			"location":                 llx.StringData(cert.Location),
			"organization":             llx.StringData(cert.Organization),
			"organizationalUnit":       llx.StringData(cert.OrganizationalUnit),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
