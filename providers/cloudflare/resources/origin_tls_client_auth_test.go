// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func handleAOPSettings(env *testEnv, enabled bool) {
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/settings", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, fmt.Sprintf(`{"success":true,"result":{"enabled":%t}}`, enabled))
	})
}

func TestAuthenticatedOriginPullsSettings(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleAOPSettings(env, true)

	aop, err := zone.authenticatedOriginPulls()
	require.NoError(t, err)
	require.NotNil(t, aop)
	assert.True(t, aop.Enabled.Data)
}

func TestAuthenticatedOriginPullsUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/settings", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	aop, err := zone.authenticatedOriginPulls()
	require.NoError(t, err, "Forbidden must surface as null, not error")
	assert.Nil(t, aop)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, zone.AuthenticatedOriginPulls.State)
}

func TestAuthenticatedOriginPullsZoneCertificates(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleAOPSettings(env, true)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{
			"id":"023e105f4ecef8ad9ca31a8372d0c353",
			"enabled":true,
			"issuer":"GlobalSign",
			"signature":"SHA256WithRSA",
			"status":"active",
			"expires_on":"2033-02-20T20:54:00Z",
			"uploaded_on":"2023-02-20T20:54:00Z"
		}],"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	aop, err := zone.authenticatedOriginPulls()
	require.NoError(t, err)

	certs, err := aop.certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	cert := certs[0].(*mqlCloudflareZoneAuthenticatedOriginPullsCertificate)
	assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", cert.Id.Data)
	assert.True(t, cert.Enabled.Data)
	assert.Equal(t, "GlobalSign", cert.Issuer.Data)
	assert.Equal(t, "active", cert.Status.Data)
	require.NotNil(t, cert.ExpiresOn.Data)
	assert.Equal(t, 2033, cert.ExpiresOn.Data.Year())
}

// The per-hostname binding resolves its certificate through the parent's
// cached hostnameCertificates list. This asserts both that the reference
// resolves and that N hostnames cost a single certificate-list request rather
// than one request each.
func TestAuthenticatedOriginPullsHostnameCertificateResolves(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleAOPSettings(env, true)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/hostnames", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"hostname":"app.example.com","enabled":true,"cert_id":"cert-1","status":"active","cert_status":"active","issuer":"GlobalSign","serial_number":"123","signature":"SHA256WithRSA","expires_on":"2033-02-20T20:54:00Z"},
			{"hostname":"api.example.com","enabled":false,"cert_id":"cert-2","status":"active","cert_status":"active"},
			{"hostname":"unbound.example.com","enabled":false,"cert_id":""}
		],"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	var certListCalls atomic.Int32
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/hostnames/certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		certListCalls.Add(1)
		jsonResponse(w, `{"success":true,"result":[
			{"id":"cert-1","issuer":"GlobalSign","serial_number":"123","signature":"SHA256WithRSA","status":"active","expires_on":"2033-02-20T20:54:00Z"},
			{"id":"cert-2","issuer":"DigiCert","serial_number":"456","signature":"SHA256WithRSA","status":"active"}
		],"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	aop, err := zone.authenticatedOriginPulls()
	require.NoError(t, err)

	hostnames, err := aop.hostnames()
	require.NoError(t, err)
	require.Len(t, hostnames, 3)

	first := hostnames[0].(*mqlCloudflareZoneAuthenticatedOriginPullsHostname)
	assert.Equal(t, "app.example.com", first.Hostname.Data)
	assert.True(t, first.Enabled.Data)

	cert, err := first.certificate()
	require.NoError(t, err)
	require.NotNil(t, cert, "a bound hostname must resolve its certificate")
	assert.Equal(t, "cert-1", cert.Id.Data)
	assert.Equal(t, "GlobalSign", cert.Issuer.Data)

	// A hostname can be opted out while the zone-wide setting is on.
	second := hostnames[1].(*mqlCloudflareZoneAuthenticatedOriginPullsHostname)
	assert.False(t, second.Enabled.Data)
	secondCert, err := second.certificate()
	require.NoError(t, err)
	require.NotNil(t, secondCert)
	assert.Equal(t, "DigiCert", secondCert.Issuer.Data)

	// A hostname with no binding reads as null rather than erroring.
	third := hostnames[2].(*mqlCloudflareZoneAuthenticatedOriginPullsHostname)
	thirdCert, err := third.certificate()
	require.NoError(t, err)
	assert.Nil(t, thirdCert)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, third.Certificate.State)

	assert.Equal(t, int32(1), certListCalls.Load(),
		"resolving every hostname's certificate must reuse one cached list request")
}

// A certificate ID the zone no longer lists must read as null, not error.
func TestAuthenticatedOriginPullsDanglingCertificate(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleAOPSettings(env, true)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/hostnames", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{"hostname":"app.example.com","cert_id":"missing"}],
			"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/hostnames/certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[],"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	aop, err := zone.authenticatedOriginPulls()
	require.NoError(t, err)

	hostnames, err := aop.hostnames()
	require.NoError(t, err)
	require.Len(t, hostnames, 1)

	h := hostnames[0].(*mqlCloudflareZoneAuthenticatedOriginPullsHostname)
	cert, err := h.certificate()
	require.NoError(t, err)
	assert.Nil(t, cert)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, h.Certificate.State)
}

// A null `enabled` voids the association per the Cloudflare API, so it must not
// collapse into false.
func TestAuthenticatedOriginPullsNullEnabled(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleAOPSettings(env, true)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/origin_tls_client_auth/hostnames", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{"hostname":"app.example.com","enabled":null,"cert_id":"cert-1"}],
			"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	aop, err := zone.authenticatedOriginPulls()
	require.NoError(t, err)

	hostnames, err := aop.hostnames()
	require.NoError(t, err)
	require.Len(t, hostnames, 1)

	h := hostnames[0].(*mqlCloudflareZoneAuthenticatedOriginPullsHostname)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, h.Enabled.State,
		"a null association must stay null so it is distinguishable from an explicit opt-out")
}
