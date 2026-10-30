// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// aopZoneCertificate is a zone-level authenticated origin pull certificate,
// decoded via the client's generic Get.
type aopZoneCertificate struct {
	ID         string     `json:"id"`
	Enabled    bool       `json:"enabled"`
	Issuer     string     `json:"issuer"`
	Signature  string     `json:"signature"`
	Status     string     `json:"status"`
	ExpiresOn  *time.Time `json:"expires_on"`
	UploadedOn *time.Time `json:"uploaded_on"`
}

// aopHostname is a per-hostname authenticated origin pull binding, decoded via
// the client's generic Get.
type aopHostname struct {
	Hostname       string     `json:"hostname"`
	Enabled        *bool      `json:"enabled"`
	CertID         string     `json:"cert_id"`
	CertStatus     string     `json:"cert_status"`
	Status         string     `json:"status"`
	Issuer         string     `json:"issuer"`
	SerialNumber   string     `json:"serial_number"`
	Signature      string     `json:"signature"`
	ExpiresOn      *time.Time `json:"expires_on"`
	CertUploadedOn *time.Time `json:"cert_uploaded_on"`
	CertUpdatedAt  *time.Time `json:"cert_updated_at"`
	CreatedAt      *time.Time `json:"created_at"`
	UpdatedAt      *time.Time `json:"updated_at"`
}

// aopHostnameCertificate is a certificate available for binding to individual
// origin hostnames, decoded via the client's generic Get.
type aopHostnameCertificate struct {
	ID           string     `json:"id"`
	Issuer       string     `json:"issuer"`
	SerialNumber string     `json:"serial_number"`
	Signature    string     `json:"signature"`
	Status       string     `json:"status"`
	ExpiresOn    *time.Time `json:"expires_on"`
	UploadedOn   *time.Time `json:"uploaded_on"`
}

type mqlCloudflareZoneAuthenticatedOriginPullsInternal struct {
	zoneID string
}

type mqlCloudflareZoneAuthenticatedOriginPullsHostnameInternal struct {
	certID string
	// parent resolves the bound certificate through the parent's
	// hostnameCertificates list, which the runtime caches after the first
	// call. Fetching each certificate by ID instead would issue one request
	// per hostname.
	parent *mqlCloudflareZoneAuthenticatedOriginPulls
}

// authenticatedOriginPulls reports whether Cloudflare presents a client
// certificate to the zone's origin, and exposes the certificates and
// per-hostname bindings that back it.
func (c *mqlCloudflareZone) authenticatedOriginPulls() (*mqlCloudflareZoneAuthenticatedOriginPulls, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result struct {
			Enabled bool `json:"enabled"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/origin_tls_client_auth/settings", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.AuthenticatedOriginPulls.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.authenticatedOriginPulls", map[string]*llx.RawData{
		"__id":    llx.StringData("cloudflare.zone.authenticatedOriginPulls@" + c.Id.Data),
		"enabled": llx.BoolData(env.Result.Enabled),
	})
	if err != nil {
		return nil, err
	}

	aop := res.(*mqlCloudflareZoneAuthenticatedOriginPulls)
	aop.zoneID = c.Id.Data
	return aop, nil
}

func (c *mqlCloudflareZoneAuthenticatedOriginPulls) certificates() ([]any, error) {
	if c.zoneID == "" {
		return []any{}, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	certs, err := cfGetPaged[aopZoneCertificate](conn, fmt.Sprintf("zones/%s/origin_tls_client_auth", c.zoneID))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(certs))
	for i := range certs {
		cert := certs[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.authenticatedOriginPulls.certificate", map[string]*llx.RawData{
			"__id":       llx.StringData("cloudflare.zone.authenticatedOriginPulls.certificate@" + c.zoneID + "/" + cert.ID),
			"id":         llx.StringData(cert.ID),
			"enabled":    llx.BoolData(cert.Enabled),
			"issuer":     llx.StringData(cert.Issuer),
			"signature":  llx.StringData(cert.Signature),
			"status":     llx.StringData(cert.Status),
			"expiresOn":  llx.TimeDataPtr(cert.ExpiresOn),
			"uploadedOn": llx.TimeDataPtr(cert.UploadedOn),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

func (c *mqlCloudflareZoneAuthenticatedOriginPulls) hostnames() ([]any, error) {
	if c.zoneID == "" {
		return []any{}, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	hostnames, err := cfGetPaged[aopHostname](conn, fmt.Sprintf("zones/%s/origin_tls_client_auth/hostnames", c.zoneID))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(hostnames))
	for i := range hostnames {
		h := hostnames[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.authenticatedOriginPulls.hostname", map[string]*llx.RawData{
			"__id":           llx.StringData("cloudflare.zone.authenticatedOriginPulls.hostname@" + c.zoneID + "/" + h.Hostname),
			"hostname":       llx.StringData(h.Hostname),
			"enabled":        llx.BoolDataPtr(h.Enabled),
			"status":         llx.StringData(h.Status),
			"certStatus":     llx.StringData(h.CertStatus),
			"issuer":         llx.StringData(h.Issuer),
			"serialNumber":   llx.StringData(h.SerialNumber),
			"signature":      llx.StringData(h.Signature),
			"expiresOn":      llx.TimeDataPtr(h.ExpiresOn),
			"certUploadedOn": llx.TimeDataPtr(h.CertUploadedOn),
			"certUpdatedAt":  llx.TimeDataPtr(h.CertUpdatedAt),
			"createdAt":      llx.TimeDataPtr(h.CreatedAt),
			"updatedAt":      llx.TimeDataPtr(h.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		mqlHostname := res.(*mqlCloudflareZoneAuthenticatedOriginPullsHostname)
		mqlHostname.certID = h.CertID
		mqlHostname.parent = c
		results = append(results, mqlHostname)
	}
	return results, nil
}

func (c *mqlCloudflareZoneAuthenticatedOriginPulls) hostnameCertificates() ([]any, error) {
	if c.zoneID == "" {
		return []any{}, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	certs, err := cfGetPaged[aopHostnameCertificate](conn, fmt.Sprintf("zones/%s/origin_tls_client_auth/hostnames/certificates", c.zoneID))
	if err != nil {
		return degradedList(err)
	}

	results := make([]any, 0, len(certs))
	for i := range certs {
		cert := certs[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.authenticatedOriginPulls.hostnameCertificate", map[string]*llx.RawData{
			"__id":         llx.StringData("cloudflare.zone.authenticatedOriginPulls.hostnameCertificate@" + c.zoneID + "/" + cert.ID),
			"id":           llx.StringData(cert.ID),
			"issuer":       llx.StringData(cert.Issuer),
			"serialNumber": llx.StringData(cert.SerialNumber),
			"signature":    llx.StringData(cert.Signature),
			"status":       llx.StringData(cert.Status),
			"expiresOn":    llx.TimeDataPtr(cert.ExpiresOn),
			"uploadedOn":   llx.TimeDataPtr(cert.UploadedOn),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

// certificate resolves the certificate bound to this hostname out of the
// parent's hostnameCertificates list. A hostname with no binding, or one whose
// certificate the zone no longer lists, reads as null.
func (c *mqlCloudflareZoneAuthenticatedOriginPullsHostname) certificate() (*mqlCloudflareZoneAuthenticatedOriginPullsHostnameCertificate, error) {
	if c.certID == "" || c.parent == nil {
		c.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	certs := c.parent.GetHostnameCertificates()
	if certs.Error != nil {
		return nil, certs.Error
	}

	for _, entry := range certs.Data {
		cert, ok := entry.(*mqlCloudflareZoneAuthenticatedOriginPullsHostnameCertificate)
		if !ok {
			continue
		}
		if cert.Id.Data == c.certID {
			return cert, nil
		}
	}

	c.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
