// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOriginCACertificates(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc("/certificates", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, testZoneID, r.URL.Query().Get("zone_id"))
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("origin_ca_certificates"))
	})

	result, err := zone.originCACertificates()
	require.NoError(t, err)
	require.Len(t, result, 2)

	// Synthetic: an active certificate; the API omits revoked_at, so revokedAt is null, not year 1.
	cert := result[0].(*mqlCloudflareZoneOriginCACertificate)
	assert.Equal(t, "origincert-001", cert.Id.Data)
	assert.Equal(t, "origin-rsa", cert.RequestType.Data)
	assert.Equal(t, int64(5475), cert.RequestValidity.Data)
	assert.Len(t, cert.Hostnames.Data, 2)
	assert.False(t, cert.ExpiresAt.Data.IsZero())
	assert.Nil(t, cert.RevokedAt.Data)

	// Synthetic: a revoked certificate; no live account showed one.
	revoked := result[1].(*mqlCloudflareZoneOriginCACertificate)
	assert.Equal(t, "origincert-002", revoked.Id.Data)
	require.NotNil(t, revoked.RevokedAt.Data)
	assert.Equal(t, time.Date(2026, 10, 15, 8, 30, 0, 0, time.UTC), revoked.RevokedAt.Data.UTC())
}

func TestCustomCertificates(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/custom_certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("custom_certificates"))
	})

	result, err := zone.customCertificates()
	require.NoError(t, err)
	require.Len(t, result, 2)

	c1 := result[0].(*mqlCloudflareZoneCustomCertificate)
	assert.Equal(t, "cust-cert-001", c1.Id.Data)
	assert.Equal(t, []any{"www.example.com", "example.com"}, c1.Hosts.Data)
	assert.Equal(t, "DigiCert Inc", c1.Issuer.Data)
	assert.Equal(t, "SHA256WithRSAEncryption", c1.Signature.Data)
	assert.Equal(t, "active", c1.Status.Data)
	assert.Equal(t, "ubiquitous", c1.BundleMethod.Data)
	assert.Equal(t, int64(10), c1.Priority.Data)
	assert.False(t, c1.ExpiresAt.Data.IsZero())

	c2 := result[1].(*mqlCloudflareZoneCustomCertificate)
	assert.Equal(t, "expired", c2.Status.Data, "fixture has an expired cert that must surface as such")
}

func TestCertificatePacks(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/ssl/certificate_packs", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		// The v0 SDK adds ?status=all — verify the test handler sees it
		assert.Equal(t, "all", r.URL.Query().Get("status"))
		jsonResponse(w, loadFixture("certificate_packs"))
	})

	result, err := zone.certificatePacks()
	require.NoError(t, err)
	require.Len(t, result, 2)

	p1 := result[0].(*mqlCloudflareZoneCertificatePack)
	assert.Equal(t, "pack-001", p1.Id.Data)
	assert.Equal(t, "advanced", p1.Type.Data)
	assert.Equal(t, []any{"example.com", "*.example.com"}, p1.Hosts.Data)
	assert.Equal(t, "active", p1.Status.Data)
	assert.Equal(t, "txt", p1.ValidationMethod.Data)
	assert.Equal(t, int64(90), p1.ValidityDays.Data)
	assert.Equal(t, "lets_encrypt", p1.CertificateAuthority.Data)

	p2 := result[1].(*mqlCloudflareZoneCertificatePack)
	assert.Equal(t, "pack-002", p2.Id.Data)
	assert.Equal(t, "pending_validation", p2.Status.Data)
	assert.Equal(t, "google", p2.CertificateAuthority.Data)
}

func TestMtlsCertificates(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/mtls_certificates", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("mtls_certificates"))
	})

	result, err := zone.mtlsCertificates()
	require.NoError(t, err)
	require.Len(t, result, 1)

	cert := result[0].(*mqlCloudflareMtlsCertificate)
	assert.Equal(t, "mtls-001", cert.Id.Data)
	assert.Equal(t, "API Client Cert", cert.Name.Data)
	assert.Equal(t, "CN=My CA", cert.Issuer.Data)
	assert.Equal(t, "SHA256WithRSA", cert.Signature.Data)
	assert.Equal(t, "1234567890ABCDEF", cert.SerialNumber.Data)
	assert.True(t, cert.Ca.Data)
	assert.False(t, cert.ExpiresAt.Data.IsZero())
}

func TestCustomHostnames(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/custom_hostnames", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("custom_hostnames"))
	})

	result, err := zone.customHostnames()
	require.NoError(t, err)
	require.Len(t, result, 1)

	ch := result[0].(*mqlCloudflareZoneCustomHostname)
	assert.Equal(t, "ch-001", ch.Id.Data)
	assert.Equal(t, "app.customer.com", ch.Hostname.Data)
	assert.Equal(t, "origin.example.com", ch.CustomOriginServer.Data)
	assert.Equal(t, "active", ch.Status.Data)
	assert.Equal(t, "active", ch.SslStatus.Data)
	assert.Equal(t, "http", ch.SslMethod.Data)
	assert.Equal(t, "dv", ch.SslType.Data)
}

func TestCustomHostnames_nilSSL(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/custom_hostnames", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, `{
			"success": true,
			"result": [{
				"id": "ch-002",
				"hostname": "nossl.example.com",
				"status": "pending",
				"created_at": "2024-01-01T00:00:00Z"
			}],
			"result_info": {"page":1,"per_page":25,"total_pages":1,"count":1,"total_count":1}
		}`)
	})

	result, err := zone.customHostnames()
	require.NoError(t, err)
	require.Len(t, result, 1)

	ch := result[0].(*mqlCloudflareZoneCustomHostname)
	assert.Equal(t, "", ch.SslStatus.Data)
	assert.Equal(t, "", ch.SslMethod.Data)
	assert.Equal(t, "", ch.SslType.Data)
}
