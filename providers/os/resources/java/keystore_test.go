// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java_test

import (
	"crypto/x509"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/java"
)

// testdata/keystore.jks was written by keytool: one private-key entry with a
// self-signed certificate, and two trusted certificate entries. Generating it
// with the real tool rather than by hand is the point — it fails if the format
// is read wrongly, which a fixture written to match the parser would not.
func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/keystore.jks")
	require.NoError(t, err)
	return data
}

func TestParseJKS(t *testing.T) {
	ks, err := java.Parse(fixture(t), "")
	require.NoError(t, err, "a JKS store is readable without a password")
	assert.Equal(t, java.FormatJKS, ks.Format)
	require.Len(t, ks.Entries, 3)

	byAlias := map[string]java.Entry{}
	for _, e := range ks.Entries {
		byAlias[e.Alias] = e
	}

	t.Run("trusted certificate entries", func(t *testing.T) {
		for _, alias := range []string{"trusted-ca-1", "trusted-ca-2"} {
			entry, ok := byAlias[alias]
			require.True(t, ok, "alias %q", alias)
			assert.True(t, entry.Trusted)
			require.Len(t, entry.Certs, 1, "a trusted entry holds exactly one certificate")
			assert.False(t, entry.CreatedAt.IsZero(), "keytool records a creation date")
		}
	})

	t.Run("a private key entry carries its chain, never the key", func(t *testing.T) {
		entry, ok := byAlias["server"]
		require.True(t, ok)
		assert.False(t, entry.Trusted, "a key entry is not a trusted certificate")
		require.Len(t, entry.Certs, 1, "the self-signed chain")
		// There is no field for key material at all, which is the guarantee:
		// it cannot be exposed by accident later.
	})

	t.Run("every certificate is valid DER", func(t *testing.T) {
		subjects := map[string]string{}
		for _, e := range ks.Entries {
			for _, der := range e.Certs {
				cert, err := x509.ParseCertificate(der)
				require.NoError(t, err, "alias %q", e.Alias)
				subjects[e.Alias] = cert.Subject.String()
			}
		}
		assert.Contains(t, subjects["trusted-ca-1"], "CN=Example Root CA 1")
		assert.Contains(t, subjects["server"], "CN=server.example")
	})

	// The organizational unit is what a certificate-authority audit reads, so
	// assert it survives the round trip rather than only the common name.
	t.Run("organizational unit is readable", func(t *testing.T) {
		entry := byAlias["trusted-ca-1"]
		cert, err := x509.ParseCertificate(entry.Certs[0])
		require.NoError(t, err)
		assert.Equal(t, []string{"Certification Authority"}, cert.Subject.OrganizationalUnit)
	})
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want string
		err  bool
	}{
		{"jks", []byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2}, java.FormatJKS, false},
		{"jceks", []byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2}, java.FormatJCEKS, false},
		{"pkcs12 opens an ASN.1 SEQUENCE", []byte{0x30, 0x82, 0x0A, 0x00}, java.FormatPKCS12, false},
		{"not a keystore", []byte{'h', 'e', 'l', 'l'}, "", true},
		{"too short", []byte{0xFE, 0xED}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := java.DetectFormat(tc.head)
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A store that claims more entries than it holds must fail, not return the
// entries it managed to read. A short trust store still satisfies every
// assertion made about the certificates that were read.
func TestParseJKSRejectsATruncatedStore(t *testing.T) {
	data := fixture(t)

	t.Run("body cut short", func(t *testing.T) {
		_, err := java.Parse(data[:len(data)/2], "")
		assert.Error(t, err)
	})

	t.Run("entry count inflated", func(t *testing.T) {
		tampered := make([]byte, len(data))
		copy(tampered, data)
		// bytes 8..12 hold the entry count
		binary.BigEndian.PutUint32(tampered[8:12], 99)
		_, err := java.Parse(tampered, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "entry")
	})

	t.Run("entry count deflated leaves trailing bytes", func(t *testing.T) {
		tampered := make([]byte, len(data))
		copy(tampered, data)
		binary.BigEndian.PutUint32(tampered[8:12], 1)
		_, err := java.Parse(tampered, "")
		require.Error(t, err, "the digest check catches a store that parses but is not fully read")
		assert.Contains(t, err.Error(), "malformed")
	})
}

// A corrupt length field must not become a huge allocation.
func TestParseJKSRejectsImplausibleLengths(t *testing.T) {
	store := func(t *testing.T, mutate func([]byte)) []byte {
		t.Helper()
		data := make([]byte, len(fixture(t)))
		copy(data, fixture(t))
		mutate(data)
		return data
	}

	t.Run("entry count", func(t *testing.T) {
		data := store(t, func(b []byte) { binary.BigEndian.PutUint32(b[8:12], 1<<30) })
		_, err := java.Parse(data, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to read")
	})
}

func TestParseRejectsGarbage(t *testing.T) {
	_, err := java.Parse([]byte("this is not a keystore at all"), "")
	assert.Error(t, err)
}

// keytool has written a SHA-256 integrity MAC for years, and PKCS#12 has been
// the default format for the stores it creates since JDK 9, so this is the
// shape of most keystores made this decade. golang.org/x/crypto/pkcs12 verifies
// only SHA-1 MACs and cannot open any of them.
func TestParsePKCS12WithASHA256MAC(t *testing.T) {
	data, err := os.ReadFile("testdata/keystore-sha256mac.p12")
	require.NoError(t, err)

	ks, err := java.Parse(data, "changeit")
	require.NoError(t, err, "a SHA-256 MAC is not a reason to refuse a store")
	assert.Equal(t, java.FormatPKCS12, ks.Format)
	require.NotEmpty(t, ks.Entries)

	for _, entry := range ks.Entries {
		require.NotEmpty(t, entry.Certs)
		for _, der := range entry.Certs {
			_, err := x509.ParseCertificate(der)
			require.NoError(t, err, "every entry carries valid DER")
		}
	}
}

// A store keytool writes with a private key. Read through ToPEM, which is the
// only entry point that carries friendlyName, so the alias survives.
func TestParsePKCS12KeystoreKeepsTheAlias(t *testing.T) {
	data, err := os.ReadFile("testdata/ks-modern.p12")
	require.NoError(t, err)

	ks, err := java.Parse(data, "changeit")
	require.NoError(t, err)
	require.NotEmpty(t, ks.Entries)

	aliases := map[string]bool{}
	for _, entry := range ks.Entries {
		aliases[entry.Alias] = true
		assert.False(t, entry.Trusted,
			"a certificate that belongs to a private key's chain is not a trust anchor")
	}
	assert.True(t, aliases["mykey"], "the alias keytool recorded is readable, got %v", aliases)
}

// A store of trust anchors, which is the shape ToPEM refuses because keytool
// marks each certificate with an attribute it does not know.
func TestParsePKCS12TrustStore(t *testing.T) {
	data, err := os.ReadFile("testdata/truststore.p12")
	require.NoError(t, err)

	ks, err := java.Parse(data, "changeit")
	require.NoError(t, err)
	require.Len(t, ks.Entries, 1)
	assert.True(t, ks.Entries[0].Trusted, "every certificate in a trust store is a trust anchor")
	_, err = x509.ParseCertificate(ks.Entries[0].Certs[0])
	require.NoError(t, err)
}

// The property the reader has to keep whatever it is built on: an unreadable
// store and a wrong password stay distinguishable, so nobody goes looking for a
// credential that was never the problem, and an unreadable store is never
// reported as an empty one.
func TestParsePKCS12WrongPasswordIsNotAnUnsupportedStore(t *testing.T) {
	// A store whose password is not one of the documented defaults: Parse falls
	// back to those, so a store protected with "changeit" opens no matter what
	// the caller passes and cannot show this property.
	data, err := os.ReadFile("testdata/ks-custompass.p12")
	require.NoError(t, err)

	_, err = java.Parse(data, "definitely-not-the-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, java.ErrPasswordRequired)
	assert.NotErrorIs(t, err, java.ErrUnsupportedPKCS12,
		"a wrong password is not an unimplemented feature")

	// and the right one opens it
	ks, err := java.Parse(data, "s3cr3t-store-pw")
	require.NoError(t, err)
	assert.NotEmpty(t, ks.Entries)
}

// A store that holds a private key and no certificate. It must not come back as
// a keystore with no entries: an empty store satisfies every assertion made
// about its contents, so "nothing to read here" and "nothing in here" have to
// stay apart.
//
// The fixture is what `openssl pkcs12 -export -nocerts` writes, which is a
// single authenticated safe. Every entry point rejects that shape, so the
// reader reports it rather than returning an empty keystore.
func TestParsePKCS12WithNoCertificatesIsNotAnEmptyStore(t *testing.T) {
	data, err := os.ReadFile("testdata/keyonly.p12")
	require.NoError(t, err)

	ks, err := java.Parse(data, "changeit")
	require.Error(t, err, "a store whose certificates cannot be read is not an empty store")
	assert.Nil(t, ks)
}

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
