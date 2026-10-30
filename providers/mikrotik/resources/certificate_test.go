// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRouterOSTime(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Time
	}{
		// RouterOS 7 reports ISO-style dates
		{"2027-01-24 10:00:00", time.Date(2027, 1, 24, 10, 0, 0, 0, time.UTC)},
		// RouterOS 6 reports the abbreviated-month form
		{"jan/24/2027 10:00:00", time.Date(2027, 1, 24, 10, 0, 0, 0, time.UTC)},
		{"dec/31/2024 23:59:59", time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"2027-01-24T10:00:00Z", time.Date(2027, 1, 24, 10, 0, 0, 0, time.UTC)},
		{" 2027-01-24 10:00:00 ", time.Date(2027, 1, 24, 10, 0, 0, 0, time.UTC)},
	} {
		got := parseRouterOSTime(tc.in)
		require.NotNil(t, got, "parseRouterOSTime(%q)", tc.in)
		assert.True(t, tc.want.Equal(*got), "parseRouterOSTime(%q) = %v, want %v", tc.in, *got, tc.want)
	}

	// an absent or unreadable date must stay null: coercing it to the zero
	// time would report the year 1 as a real certificate date
	for _, in := range []string{"", "   ", "never", "2027-13-45 99:99:99"} {
		assert.Nil(t, parseRouterOSTime(in), "parseRouterOSTime(%q)", in)
	}
}

func TestCommonNameOf(t *testing.T) {
	assert.Equal(t, "Example CA", commonNameOf("C=US,O=Example,CN=Example CA"))
	assert.Equal(t, "router.example.com", commonNameOf("CN=router.example.com"))
	assert.Equal(t, "router.example.com", commonNameOf(" O=Example , CN= router.example.com "))
	assert.Equal(t, "", commonNameOf("O=Example"))
	assert.Equal(t, "", commonNameOf(""))
}

func TestCertificateExpired(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	past := certificateExpired("2026-08-22 12:00:00", now)
	require.NotNil(t, past)
	assert.True(t, *past)

	future := certificateExpired("2027-01-24 10:00:00", now)
	require.NotNil(t, future)
	assert.False(t, *future)

	// a device that reports no readable expiry leaves the answer unknown
	// rather than claiming the certificate is still valid
	assert.Nil(t, certificateExpired("", now))
	assert.Nil(t, certificateExpired("never", now))
}

func TestCertificateSelfSigned(t *testing.T) {
	self := certificateSelfSigned("CN=router.example.com", "router.example.com")
	require.NotNil(t, self)
	assert.True(t, *self)

	issued := certificateSelfSigned("C=US,O=Example,CN=Example CA", "router.example.com")
	require.NotNil(t, issued)
	assert.False(t, *issued)

	// without both halves of the comparison the answer is unknown
	assert.Nil(t, certificateSelfSigned("", "router.example.com"))
	assert.Nil(t, certificateSelfSigned("CN=Example CA", ""))
	assert.Nil(t, certificateSelfSigned("O=Example", "router.example.com"))
}

func TestCertificateArgs(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	row := map[string]string{
		".id":              "*1",
		"name":             "webfig",
		"common-name":      "router.example.com",
		"subject-alt-name": "DNS:router.example.com",
		"issuer":           "CN=router.example.com",
		"serial-number":    "4B1F2C",
		"fingerprint":      "aa11bb22",
		"key-type":         "rsa",
		"key-size":         "1024",
		"digest-algorithm": "sha1",
		"key-usage":        "digital-signature,key-encipherment,tls-server",
		"invalid-before":   "2025-01-24 10:00:00",
		"invalid-after":    "2026-01-24 10:00:00",
		"expires-after":    "0s",
		"private-key":      "true",
		"trusted":          "no",
		"crl":              "false",
		"akid":             "",
		"skid":             "cc33",
	}
	args := certificateArgs(row, now)

	assert.Equal(t, "mikrotik.certificate/*1", args["__id"].Value)
	assert.Equal(t, "webfig", args["name"].Value)
	assert.Equal(t, "router.example.com", args["commonName"].Value)
	assert.Equal(t, int64(1024), args["keySize"].Value)
	assert.Equal(t, "sha1", args["digestAlgorithm"].Value)
	assert.Equal(t, []any{"digital-signature", "key-encipherment", "tls-server"}, args["keyUsage"].Value)
	assert.Equal(t, true, args["expired"].Value)
	assert.Equal(t, true, args["selfSigned"].Value)
	assert.Equal(t, true, args["hasPrivateKey"].Value)
	assert.Equal(t, false, args["trusted"].Value)

	// the private key material is never carried into the resource
	for _, banned := range []string{"privateKey", "key", "secret"} {
		assert.NotContains(t, args, banned)
	}

	before, ok := args["invalidBefore"].Value.(*time.Time)
	require.True(t, ok)
	assert.True(t, time.Date(2025, 1, 24, 10, 0, 0, 0, time.UTC).Equal(*before))
}

func TestCertificateArgsAbsentAttributes(t *testing.T) {
	// a certificate row that carries only a name must not gain a validity
	// window, a key size, or a confident "not expired"
	args := certificateArgs(map[string]string{"name": "unsigned"}, time.Now())

	assert.Equal(t, "mikrotik.certificate/unsigned", args["__id"].Value)
	assert.Nil(t, args["keySize"].Value)
	assert.Nil(t, args["invalidBefore"].Value)
	assert.Nil(t, args["invalidAfter"].Value)
	assert.Nil(t, args["expired"].Value)
	assert.Nil(t, args["selfSigned"].Value)
	assert.Nil(t, args["hasPrivateKey"].Value)
	assert.Nil(t, args["trusted"].Value)
	assert.Nil(t, args["keyUsage"].Value)
}

func TestCertificateRefName(t *testing.T) {
	// RouterOS writes "none" into a certificate property with nothing bound
	assert.Equal(t, "", certificateRefName("none"))
	assert.Equal(t, "", certificateRefName(""))
	assert.Equal(t, "", certificateRefName("   "))
	assert.Equal(t, "webfig", certificateRefName("webfig"))
	assert.Equal(t, "webfig", certificateRefName(" webfig "))
}

func TestSshArgs(t *testing.T) {
	row := map[string]string{
		"forwarding-enabled":          "no",
		"always-allow-password-login": "false",
		"host-key-size":               "2048",
		"host-key-type":               "rsa",
		"strong-crypto":               "false",
		"allow-none-crypto":           "false",
	}
	args := sshArgs(row)

	assert.Equal(t, "mikrotik.ssh", args["__id"].Value)
	// the RouterOS default: strong crypto off, which leaves SHA1, CBC, and
	// 1024-bit Diffie-Hellman acceptable
	assert.Equal(t, false, args["strongCrypto"].Value)
	assert.Equal(t, false, args["allowNoneCrypto"].Value)
	assert.Equal(t, int64(2048), args["hostKeySize"].Value)
	assert.Equal(t, "rsa", args["hostKeyType"].Value)
	// forwarding-enabled is an enum on RouterOS, not a flag
	assert.Equal(t, "no", args["forwardingEnabled"].Value)
	// this RouterOS version does not expose cipher selection here
	assert.Nil(t, args["ciphers"].Value)
}

func TestSshArgsHardened(t *testing.T) {
	row := map[string]string{
		"forwarding-enabled":          "both",
		"always-allow-password-login": "yes",
		"host-key-size":               "4096",
		"host-key-type":               "ed25519",
		"strong-crypto":               "yes",
		"allow-none-crypto":           "yes",
		"ciphers":                     "chacha20-poly1305,aes256-gcm,aes128-ctr",
	}
	args := sshArgs(row)

	assert.Equal(t, true, args["strongCrypto"].Value)
	// allow-none-crypto permits an entirely unencrypted session
	assert.Equal(t, true, args["allowNoneCrypto"].Value)
	assert.Equal(t, true, args["alwaysAllowPasswordLogin"].Value)
	assert.Equal(t, "both", args["forwardingEnabled"].Value)
	assert.Equal(t, []any{"chacha20-poly1305", "aes256-gcm", "aes128-ctr"}, args["ciphers"].Value)
}

func TestSshArgsAbsentMenu(t *testing.T) {
	// nothing may read as a hardened setting when the device reported nothing
	args := sshArgs(map[string]string{})

	assert.Nil(t, args["strongCrypto"].Value)
	assert.Nil(t, args["allowNoneCrypto"].Value)
	assert.Nil(t, args["alwaysAllowPasswordLogin"].Value)
	assert.Nil(t, args["hostKeySize"].Value)
	assert.Nil(t, args["ciphers"].Value)
	assert.Equal(t, "", args["hostKeyType"].Value)
}
