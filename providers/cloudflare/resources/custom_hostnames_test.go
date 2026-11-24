// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/custom_hostnames"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeCustomHostnameSSL(t *testing.T, raw string) custom_hostnames.CustomHostnameListResponseSSL {
	t.Helper()
	var rec custom_hostnames.CustomHostnameListResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &rec))
	return rec.SSL
}

func TestCustomHostnameSSLArgs(t *testing.T) {
	// Synthetic: an issued wildcard certificate with explicit TLS settings; no
	// live account was checked.
	t.Run("issued", func(t *testing.T) {
		args := customHostnameSSLArgs(decodeCustomHostnameSSL(t, `{"id":"ch-1","hostname":"app.customer.com",
			"ssl":{"status":"active","method":"http","type":"dv","wildcard":false,
			  "issuer":"GoogleTrustServices","certificate_authority":"google",
			  "expires_on":"2027-01-02T03:04:05Z",
			  "settings":{"min_tls_version":"1.2","tls_1_3":"on","ciphers":["ECDHE-RSA-AES128-GCM-SHA256"]}}}`))

		assert.Equal(t, "1.2", args["sslMinTlsVersion"].Value)
		assert.Equal(t, "on", args["sslTls13"].Value)
		assert.Equal(t, []any{"ECDHE-RSA-AES128-GCM-SHA256"}, args["sslCiphers"].Value)
		assert.Equal(t, "GoogleTrustServices", args["sslIssuer"].Value)
		assert.Equal(t, "google", args["sslCertificateAuthority"].Value)
		require.NotNil(t, args["sslWildcard"].Value, "an explicit false must not read as null")
		assert.Equal(t, false, args["sslWildcard"].Value)
		expires, ok := args["sslExpiresOn"].Value.(*time.Time)
		require.True(t, ok)
		assert.Equal(t, time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), expires.UTC())
		assert.Equal(t, "active", args["sslStatus"].Value)
	})

	// Synthetic: a pending hostname whose SSL block carries no certificate and
	// no settings; no live account was checked.
	t.Run("pending without settings", func(t *testing.T) {
		args := customHostnameSSLArgs(decodeCustomHostnameSSL(t, `{"id":"ch-2","hostname":"new.customer.com",
			"ssl":{"status":"pending_validation","method":"txt","type":"dv"}}`))

		for _, key := range []string{"sslMinTlsVersion", "sslTls13", "sslCiphers", "sslIssuer",
			"sslCertificateAuthority", "sslWildcard", "sslExpiresOn"} {
			assert.Nil(t, args[key].Value, key)
		}
		assert.Equal(t, "pending_validation", args["sslStatus"].Value)
	})

	// Synthetic: a hostname record without an SSL block; no live account was
	// checked.
	t.Run("no ssl block", func(t *testing.T) {
		args := customHostnameSSLArgs(decodeCustomHostnameSSL(t, `{"id":"ch-3","hostname":"nossl.customer.com"}`))

		for _, key := range []string{"sslMinTlsVersion", "sslCiphers", "sslWildcard", "sslExpiresOn"} {
			assert.Nil(t, args[key].Value, key)
		}
		assert.Equal(t, "", args["sslStatus"].Value)
	})
}
