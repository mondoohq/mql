// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/java"
)

type wantEntry struct {
	trusted bool
	// SHA-256 fingerprint as `keytool -list -v` prints it
	sha256 string
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func normalizeFingerprint(keytool string) string {
	return strings.ReplaceAll(keytool, ":", "")
}

// The fixtures were written by keytool from the JDK named in the file name,
// and the expectations are what `keytool -list -v` reports for the same file:
// the alias, trustedCertEntry versus PrivateKeyEntry, and the certificate's
// SHA-256 fingerprint. JDK 8 encrypts the certificates with RC2-40 and the key
// with 3DES; JDK 11 and later use PBES2 with AES-256.
func TestParsePKCS12ReadsKeytoolAliasesAndTrust(t *testing.T) {
	const amazonRootCA1 = "8E:CD:E6:88:4F:3D:87:B1:12:5B:A3:1A:C3:FC:B1:3D:70:16:DE:7F:57:CC:90:4F:E1:CB:97:C6:AE:98:19:6E"
	const isrgRootX1 = "96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6"
	const usertrustRSA = "E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2"

	trustStore := map[string]wantEntry{
		"amazon_root_ca_1":                      {trusted: true, sha256: amazonRootCA1},
		"isrg_root_x1":                          {trusted: true, sha256: isrgRootX1},
		"usertrust_rsa_certification_authority": {trusted: true, sha256: usertrustRSA},
	}

	tests := []struct {
		file string
		want map[string]wantEntry
	}{
		{
			// a private key entry beside a trusted certificate entry
			file: "testdata/jdk8-mixed.p12",
			want: map[string]wantEntry{
				"amazon1": {trusted: true, sha256: amazonRootCA1},
				"server":  {trusted: false, sha256: "FC:A1:7B:5A:0C:8A:13:C1:CD:D3:A4:52:1B:E3:19:94:ED:1C:2B:A4:09:1E:F3:58:39:4E:A5:09:E3:A7:A6:4A"},
			},
		},
		{
			file: "testdata/jdk25-mixed.p12",
			want: map[string]wantEntry{
				"amazon1": {trusted: true, sha256: amazonRootCA1},
				"server":  {trusted: false, sha256: "C2:B2:CB:E2:C7:D7:F8:14:21:77:B0:64:6D:3D:AF:25:20:7A:9A:A4:92:DB:9C:E5:7E:C4:5D:E4:B8:1E:A0:50"},
			},
		},
		{file: "testdata/jdk8-trust.p12", want: trustStore},
		{file: "testdata/jdk11-trust.p12", want: trustStore},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)

			ks, err := java.Parse(data, "changeit")
			require.NoError(t, err)
			assert.Equal(t, java.FormatPKCS12, ks.Format)

			got := map[string]wantEntry{}
			for _, entry := range ks.Entries {
				require.Len(t, entry.Certs, 1)
				_, err := x509.ParseCertificate(entry.Certs[0])
				require.NoError(t, err)
				_, dup := got[entry.Alias]
				require.False(t, dup, "alias %q reported twice", entry.Alias)
				got[entry.Alias] = wantEntry{trusted: entry.Trusted, sha256: fingerprint(entry.Certs[0])}
			}

			want := map[string]wantEntry{}
			for alias, w := range tt.want {
				want[alias] = wantEntry{trusted: w.trusted, sha256: normalizeFingerprint(w.sha256)}
			}
			assert.Equal(t, want, got)
		})
	}
}

// A keystore OpenSSL writes for a key and its chain: the leaf carries a
// localKeyId and friendlyName, the issuing CA carries no attributes at all.
// The CA is part of the key's chain, which is how Java reads the store, not a
// trust anchor the store vouches for.
func TestParsePKCS12ChainCertificateIsNotATrustAnchor(t *testing.T) {
	data, err := os.ReadFile("testdata/openssl-chain.p12")
	require.NoError(t, err)

	ks, err := java.Parse(data, "changeit")
	require.NoError(t, err)
	require.Len(t, ks.Entries, 2)

	subjects := map[string]java.Entry{}
	for _, entry := range ks.Entries {
		cert, err := x509.ParseCertificate(entry.Certs[0])
		require.NoError(t, err)
		subjects[cert.Subject.CommonName] = entry
	}

	leaf := subjects["leaf.example.com"]
	assert.Equal(t, "leaf", leaf.Alias)
	assert.False(t, leaf.Trusted)

	ca := subjects["Example Chain CA"]
	assert.Equal(t, "", ca.Alias)
	assert.False(t, ca.Trusted, "a chain certificate in a store holding a key is not a trust anchor")
}

// The trusted-certificate fixture keytool wrote for the existing trust store
// test now keeps its alias as well.
func TestParsePKCS12TrustStoreKeepsTheAlias(t *testing.T) {
	data, err := os.ReadFile("testdata/truststore.p12")
	require.NoError(t, err)

	ks, err := java.Parse(data, "changeit")
	require.NoError(t, err)
	require.Len(t, ks.Entries, 1)
	assert.Equal(t, "trusted-one", ks.Entries[0].Alias)
	assert.True(t, ks.Entries[0].Trusted)
}
