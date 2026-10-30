// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientCertificates(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/client_certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, `{"success":true,"errors":[],"messages":[],
			"result":[{
				"id":"023e105f4ecef8ad9ca31a8372d0c353",
				"common_name":"Cloudflare",
				"status":"active",
				"issued_on":"2023-02-20T20:54:00Z",
				"expires_on":"2033-02-20T20:54:00Z",
				"validity_days":3650,
				"fingerprint_sha256":"256c24690243359fb8cf139a125bd05ebf1d968b71e4caf330718e9f5c8a0ea8",
				"serial_number":"3627708base64",
				"signature":"SHA256WithRSA",
				"ski":"8e375af1389a069a0f921f8cc8e1eb12d784b949",
				"country":"US",
				"state":"Texas",
				"location":"Austin",
				"organization":"Cloudflare",
				"organizational_unit":"Sales",
				"certificate":"-----BEGIN CERTIFICATE-----MIIDmDCC-----END CERTIFICATE-----",
				"csr":"-----BEGIN CERTIFICATE REQUEST-----MIICY-----END CERTIFICATE REQUEST-----",
				"certificate_authority":{"id":"gcp","name":"Google"}
			}],
			"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	certs, err := zone.clientCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	cert := certs[0].(*mqlCloudflareZoneClientCertificate)
	assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", cert.Id.Data)
	assert.Equal(t, "Cloudflare", cert.CommonName.Data)
	assert.Equal(t, "active", cert.Status.Data)
	assert.Equal(t, int64(3650), cert.ValidityDays.Data)
	assert.Equal(t, "256c24690243359fb8cf139a125bd05ebf1d968b71e4caf330718e9f5c8a0ea8", cert.FingerprintSha256.Data)
	assert.Equal(t, "SHA256WithRSA", cert.Signature.Data)
	assert.Equal(t, "Texas", cert.State.Data)
	assert.Equal(t, "Sales", cert.OrganizationalUnit.Data)

	// The nested certificate authority is flattened rather than exposed as a
	// two-field sub-resource.
	assert.Equal(t, "gcp", cert.CertificateAuthorityId.Data)
	assert.Equal(t, "Google", cert.CertificateAuthorityName.Data)

	// This endpoint reports issued_on/expires_on as JSON strings, so the values
	// only reach the schema as real timestamps if they were parsed.
	require.NotNil(t, cert.ExpiresOn.Data)
	assert.Equal(t, 2033, cert.ExpiresOn.Data.Year())
	require.NotNil(t, cert.IssuedOn.Data)
	assert.Equal(t, 2023, cert.IssuedOn.Data.Year())
}

// An unparseable date must surface as null rather than the zero time, so a
// policy checking "expires within 30 days" doesn't fire on every certificate.
func TestClientCertificatesUnparseableDate(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/client_certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{"id":"abc","expires_on":"whenever","issued_on":""}],
			"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	certs, err := zone.clientCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	cert := certs[0].(*mqlCloudflareZoneClientCertificate)
	assert.Nil(t, cert.ExpiresOn.Data, "unparseable date must be null, not the zero time")
	assert.Nil(t, cert.IssuedOn.Data, "missing date must be null, not the zero time")
}

// Client certificates are gated behind a paid plan and require a token with
// SSL/certificate read, so an unavailable response must read as an empty list.
func TestClientCertificatesUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/client_certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	certs, err := zone.clientCertificates()
	require.NoError(t, err, "Forbidden must degrade to an empty list, not error")
	assert.Empty(t, certs)
}

// The certificate PEM and signing request the endpoint returns must never reach
// the schema. The decode target has no field for either, so they are dropped
// before anything can map them; this pins that so adding a field later has to
// be a deliberate act.
func TestClientCertificateOmitsCertificateMaterial(t *testing.T) {
	const response = `{"success":true,"result":[{
		"id":"abc",
		"common_name":"Cloudflare",
		"csr":"-----BEGIN CERTIFICATE REQUEST-----SENSITIVE-CSR-----END CERTIFICATE REQUEST-----",
		"certificate":"-----BEGIN CERTIFICATE-----SENSITIVE-PEM-----END CERTIFICATE-----"
	}],"result_info":{"page":1,"per_page":100,"total_pages":1}}`

	var decoded struct {
		Result []clientCertificate `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(response), &decoded))
	require.Len(t, decoded.Result, 1)
	assert.Equal(t, "Cloudflare", decoded.Result[0].CommonName, "the fixture decoded into the real shape")

	marshaled, err := json.Marshal(decoded.Result[0])
	require.NoError(t, err)
	assert.NotContains(t, string(marshaled), "SENSITIVE-CSR", "the signing request must not be carried into the resource")
	assert.NotContains(t, string(marshaled), "SENSITIVE-PEM", "the certificate PEM must not be carried into the resource")
}

// Guard the parser against a layout regression on the one format the
// certificate endpoint has historically used besides RFC 3339.
func TestClientCertificatesGoRenderedDate(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/client_certificates", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[{"id":"abc","expires_on":"2033-02-20 20:54:00 +0000 UTC"}],
			"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	certs, err := zone.clientCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	cert := certs[0].(*mqlCloudflareZoneClientCertificate)
	require.NotNil(t, cert.ExpiresOn.Data)
	assert.True(t, cert.ExpiresOn.Data.Equal(time.Date(2033, 2, 20, 20, 54, 0, 0, time.UTC)))
}
