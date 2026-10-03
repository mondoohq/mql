// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java_test

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/java"
)

// `openssl pkcs12 -export -nokeys -in ca.crt -passout pass:changeit` writes a
// CA bundle: one certificate bag, no attributes, no key, in a single
// authenticated safe. Every go-pkcs12 entry point rejects that shape under the
// right password, and the error reported was the last default password's,
// "no password worked: decryption password incorrect", for a store whose
// password is changeit. Fails if a shape rejection under a verified password
// is again treated as a wrong password.
func TestParsePKCS12NoKeysBundle(t *testing.T) {
	data, err := os.ReadFile("testdata/openssl-nokeys-bundle.p12")
	require.NoError(t, err)

	for _, password := range []string{"changeit", ""} {
		ks, err := java.Parse(data, password)
		require.NoError(t, err, "password %q", password)
		assert.Equal(t, java.FormatPKCS12, ks.Format)
		require.Len(t, ks.Entries, 1)
		// a store without a key is a CA bundle, its certificates trust anchors
		assert.True(t, ks.Entries[0].Trusted)
		cert, err := x509.ParseCertificate(ks.Entries[0].Certs[0])
		require.NoError(t, err)
		assert.Equal(t, "g09 Root CA", cert.Subject.CommonName)
	}
}

// The key-only store is still an error, now one that says what is wrong with
// the store rather than blaming the password.
func TestParsePKCS12KeyOnlyIsNotAPasswordError(t *testing.T) {
	data, err := os.ReadFile("testdata/keyonly.p12")
	require.NoError(t, err)

	_, err = java.Parse(data, "changeit")
	require.Error(t, err)
	assert.ErrorIs(t, err, java.ErrUnsupportedPKCS12)
	assert.NotErrorIs(t, err, java.ErrPasswordRequired)
}
