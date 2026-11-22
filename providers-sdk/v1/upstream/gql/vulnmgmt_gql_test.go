// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gql

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

// compactReportClient returns a client whose server answers every query with body.
func compactReportClient(t *testing.T, body string) *MondooClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	c, err := NewClient(&upstream.UpstreamConfig{
		ApiEndpoint: srv.URL,
		Creds: &upstream.ServiceAccountCredentials{
			Mrn: "//agents.api.mondoo.app/spaces/x/serviceaccounts/y", PrivateKey: pemKey,
		},
	}, upstream.DefaultHttpClient())
	require.NoError(t, err)
	return c
}

func TestGetVulnCompactReport(t *testing.T) {
	c := compactReportClient(t, `{"data":{"assetVulnerabilityCompactReport":{
		"__typename":"AssetVulnerabilityCompactReport",
		"assetMrn":"//asset","advisories":[],"cves":[],"packages":[],
		"stats":{"score":{"value":98},"advisories":{"total":3}}}}}`)

	report, err := c.GetVulnCompactReport("//asset")
	require.NoError(t, err)
	assert.Equal(t, "//asset", report.AssetMrn)
	assert.Equal(t, 98, report.Stats.Score.Value)
}

// The other members of the response union mean "no report", and must not come
// back as a report with zero findings.
func TestGetVulnCompactReportOtherUnionMembers(t *testing.T) {
	for name, body := range map[string]string{
		"not found":     `{"data":{"assetVulnerabilityCompactReport":{"__typename":"NotFoundError"}}}`,
		"not supported": `{"data":{"assetVulnerabilityCompactReport":{"__typename":"NotSupported"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			report, err := compactReportClient(t, body).GetVulnCompactReport("//asset")
			assert.NoError(t, err)
			assert.Nil(t, report)
		})
	}

	t.Run("unknown member", func(t *testing.T) {
		report, err := compactReportClient(t, `{"data":{"assetVulnerabilityCompactReport":{"__typename":"SomethingNew"}}}`).GetVulnCompactReport("//asset")
		assert.Error(t, err)
		assert.Nil(t, report)
	})
}
