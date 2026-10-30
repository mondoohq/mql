// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/shadowscatcher/shodan/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/shodan/connection"
)

func TestParseShodanTime(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string // RFC3339Nano of the expected time, or "" for nil
	}{
		{"empty", "", ""},
		{"rfc3339", "2024-05-01T12:00:00Z", "2024-05-01T12:00:00Z"},
		{"rfc3339 nano", "2024-05-01T12:00:00.123456789Z", "2024-05-01T12:00:00.123456789Z"},
		// The format Shodan actually emits for host/banner/DNS times: no timezone.
		{"microseconds no tz", "2024-05-01T12:00:00.283713", "2024-05-01T12:00:00.283713Z"},
		{"seconds no tz", "2024-05-01T12:00:00", "2024-05-01T12:00:00Z"},
		// The format certificate issued/expires arrive in, which differs from
		// the host and DNS timestamps above.
		{"asn1 generalized time", "20260720180833Z", "2026-07-20T18:08:33Z"},
		{"asn1 generalized time end of year", "20261221192001Z", "2026-12-21T19:20:01Z"},
		{"garbage", "not-a-time", ""},
		{"date only unsupported", "2024-05-01", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseShodanTime(tc.raw)
			if tc.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			want, err := time.Parse(time.RFC3339Nano, tc.want)
			require.NoError(t, err)
			assert.True(t, got.Equal(want), "got %s, want %s", got, want)
		})
	}
}

func TestParseCVSS(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    float64
		wantHas bool
	}{
		{"nil", nil, -1, false},
		{"float", 9.8, 9.8, true},
		{"zero float", 0.0, 0, true},
		{"string number", "7.5", 7.5, true},
		{"string with whitespace", "  4.3 ", 4.3, true},
		{"empty string", "", -1, false},
		{"partial parse rejected", "9.8 high", -1, false},
		{"non-numeric string", "critical", -1, false},
		{"unexpected type", []string{"9.8"}, -1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, has := parseCVSS(tc.raw)
			assert.Equal(t, tc.wantHas, has)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClassifyCVSS(t *testing.T) {
	tests := []struct {
		score float64
		has   bool
		want  string
	}{
		{0, false, "unknown"},
		{9.8, true, "critical"},
		{9.0, true, "critical"},
		{8.9, true, "high"},
		{7.0, true, "high"},
		{6.9, true, "medium"},
		{4.0, true, "medium"},
		{3.9, true, "low"},
		{0.1, true, "low"},
		{0, true, "none"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyCVSS(tc.score, tc.has))
		})
	}
}

func TestIsWeakCipher(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
		bits   int
		want   bool
	}{
		{"empty", "", 0, false},
		{"modern aes-gcm", "TLS_AES_256_GCM_SHA384", 256, false},
		{"ecdhe strong", "ECDHE-RSA-AES128-GCM-SHA256", 128, false},
		{"rc4", "ECDHE-RSA-RC4-SHA", 128, true},
		{"3des", "DES-CBC3-SHA", 168, true},
		{"null cipher", "TLS_RSA_WITH_NULL_SHA", 0, true},
		{"export", "EXP-RC2-CBC-MD5", 40, true},
		{"md5 mac", "AES128-MD5", 128, true},
		{"short key strong name", "SOME-CIPHER", 64, true},
		{"case insensitive", "ecdhe-rsa-des-cbc3-sha", 168, true},
		// PSK is a key-exchange mechanism, not a broken primitive.
		{"psk not weak", "TLS_PSK_WITH_AES_128_GCM_SHA256", 128, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isWeakCipher(tc.cipher, tc.bits))
		})
	}
}

func TestIsEmptySslCert(t *testing.T) {
	assert.True(t, isEmptySslCert(nil))
	assert.True(t, isEmptySslCert(&models.SslCert{}))

	withCN := &models.SslCert{}
	withCN.Subject.CN = "example.com"
	assert.False(t, isEmptySslCert(withCN))

	withFingerprint := &models.SslCert{}
	withFingerprint.Fingerprint.SHA256 = "abc123"
	assert.False(t, isEmptySslCert(withFingerprint))

	withExpires := &models.SslCert{Expires: "2025-01-01T00:00:00"}
	assert.False(t, isEmptySslCert(withExpires))
}

func TestCidrIPs(t *testing.T) {
	t.Run("slash 24 strips network and broadcast", func(t *testing.T) {
		ips, err := cidrIPs("192.168.1.0/24")
		require.NoError(t, err)
		require.Len(t, ips, 254)
		assert.Equal(t, "192.168.1.1", ips[0].String())
		assert.Equal(t, "192.168.1.254", ips[len(ips)-1].String())
	})

	t.Run("single host /32", func(t *testing.T) {
		ips, err := cidrIPs("10.0.0.5/32")
		require.NoError(t, err)
		require.Len(t, ips, 1)
		assert.Equal(t, "10.0.0.5", ips[0].String())
	})

	t.Run("host address masked to network", func(t *testing.T) {
		ips, err := cidrIPs("10.0.0.5/24")
		require.NoError(t, err)
		require.Len(t, ips, 254)
		assert.Equal(t, "10.0.0.1", ips[0].String())
	})

	t.Run("large IPv4 range rejected", func(t *testing.T) {
		_, err := cidrIPs("10.0.0.0/8")
		assert.Error(t, err)
	})

	t.Run("IPv6 range rejected", func(t *testing.T) {
		_, err := cidrIPs("2001:db8::/64")
		assert.Error(t, err)
	})

	t.Run("single IPv6 host allowed", func(t *testing.T) {
		ips, err := cidrIPs("2001:db8::1/128")
		require.NoError(t, err)
		require.Len(t, ips, 1)
	})

	t.Run("invalid cidr", func(t *testing.T) {
		_, err := cidrIPs("not-a-cidr")
		assert.Error(t, err)
	})
}

func TestResolveNetworks(t *testing.T) {
	// Mixes a single IP, a small CIDR, an oversized CIDR (skipped), and garbage
	// (skipped). Only valid, in-bounds addresses should survive.
	addrs := resolveNetworks([]string{
		"1.2.3.4",
		"192.168.0.0/30", // 4 addresses -> 2 usable after trimming
		"10.0.0.0/8",     // too large, skipped
		"garbage",        // skipped
	})

	got := map[string]bool{}
	for _, a := range addrs {
		got[a.String()] = true
	}
	assert.True(t, got["1.2.3.4"])
	assert.True(t, got["192.168.0.1"])
	assert.True(t, got["192.168.0.2"])
	assert.False(t, got["10.0.0.1"], "oversized range must be skipped")
}

func TestHandleTargets(t *testing.T) {
	// "all" expands to the concrete host discovery target.
	assert.Equal(t, []string{connection.DiscoveryHosts},
		handleTargets([]string{connection.DiscoveryAll}))

	// Other target lists pass through unchanged.
	assert.Equal(t, []string{connection.DiscoveryAuto},
		handleTargets([]string{connection.DiscoveryAuto}))
	assert.Equal(t, []string{connection.DiscoveryHosts},
		handleTargets([]string{connection.DiscoveryHosts}))
}
