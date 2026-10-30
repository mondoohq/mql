// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedPEM builds a self-signed certificate with the given public/private
// key pair and returns its PEM encoding.
func selfSignedPEM(t *testing.T, pub, priv any, cn string) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseCertificatePEM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("rsa 2048 self-signed", func(t *testing.T) {
		got := parseCertificatePEM(selfSignedPEM(t, &rsaKey.PublicKey, rsaKey, "rsa.example.com"))
		assert.Equal(t, "RSA", got.keyAlgorithm)
		assert.Equal(t, int64(2048), got.keyBits)
		assert.Equal(t, "SHA256-RSA", got.signatureAlgorithm)
		assert.Equal(t, "CN=rsa.example.com", got.subject)
		assert.Equal(t, "CN=rsa.example.com", got.issuer)
		assert.Equal(t, "4242", got.serialNumber)
		assert.True(t, got.isCa)
		assert.True(t, got.selfSigned)
	})

	t.Run("ecdsa p256 self-signed", func(t *testing.T) {
		got := parseCertificatePEM(selfSignedPEM(t, &ecKey.PublicKey, ecKey, "ec.example.com"))
		assert.Equal(t, "ECDSA", got.keyAlgorithm)
		assert.Equal(t, int64(256), got.keyBits)
		assert.True(t, got.selfSigned)
	})

	t.Run("ed25519 self-signed", func(t *testing.T) {
		got := parseCertificatePEM(selfSignedPEM(t, edPub, edPriv, "ed.example.com"))
		assert.Equal(t, "Ed25519", got.keyAlgorithm)
		assert.Equal(t, int64(256), got.keyBits)
		assert.Equal(t, "Ed25519", got.signatureAlgorithm)
	})

	// Synthetic: an ML-DSA-65 certificate, which crypto/x509 parses from Go 1.27;
	// no target showed one.
	t.Run("ml-dsa-65 self-signed", func(t *testing.T) {
		pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		got := parseCertificatePEM(selfSignedPEM(t, pqKey.Public(), pqKey, "pq.example.com"))
		assert.Equal(t, "ML-DSA", got.keyAlgorithm)
		assert.Equal(t, int64(15616), got.keyBits)
		assert.Equal(t, "ML-DSA-65", got.signatureAlgorithm)
		assert.True(t, got.selfSigned)
	})

	t.Run("ca-signed leaf is not self-signed", func(t *testing.T) {
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Unix(0, 0),
			NotAfter:              time.Unix(1<<31, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(caDER)
		require.NoError(t, err)

		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "leaf.example.com"},
			NotBefore:    time.Unix(0, 0),
			NotAfter:     time.Unix(1<<31, 0),
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
		require.NoError(t, err)
		leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

		got := parseCertificatePEM(leafPEM)
		assert.Equal(t, "CN=leaf.example.com", got.subject)
		assert.Equal(t, "CN=Test CA", got.issuer)
		assert.False(t, got.selfSigned)
		assert.False(t, got.isCa)
	})

	t.Run("self-issued but cross-signed is not self-signed", func(t *testing.T) {
		ownKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		// tmpl and parent share a subject name, so the issued cert has
		// issuer == subject, but it is signed with otherKey rather than ownKey.
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(7),
			Subject:               pkix.Name{CommonName: "shared.example.com"},
			NotBefore:             time.Unix(0, 0),
			NotAfter:              time.Unix(1<<31, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		parent := &x509.Certificate{
			SerialNumber:          big.NewInt(8),
			Subject:               pkix.Name{CommonName: "shared.example.com"},
			NotBefore:             time.Unix(0, 0),
			NotAfter:              time.Unix(1<<31, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &ownKey.PublicKey, otherKey)
		require.NoError(t, err)
		got := parseCertificatePEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
		// Issuer and subject names match, but the signature is from otherKey,
		// so it must not be reported as self-signed.
		assert.Equal(t, got.issuer, got.subject)
		assert.False(t, got.selfSigned)
	})

	t.Run("empty body", func(t *testing.T) {
		assert.Equal(t, parsedCertificate{}, parseCertificatePEM(""))
	})

	t.Run("non-PEM garbage", func(t *testing.T) {
		assert.Equal(t, parsedCertificate{}, parseCertificatePEM("not a certificate"))
	})

	t.Run("valid PEM wrapping non-certificate DER", func(t *testing.T) {
		junk := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
		assert.Equal(t, parsedCertificate{}, parseCertificatePEM(junk))
	})
}
