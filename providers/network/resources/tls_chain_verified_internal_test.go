// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issue creates a certificate from tmpl, signed by parent (self-signed when
// parent is nil), and returns it with its key.
func issue(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func TestChainVerifiedIsChainTrustOnly(t *testing.T) {
	ca := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: name},
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	root, rootKey := issue(t, ca(1, "Test Root"), nil, nil)
	inter, interKey := issue(t, ca(2, "Test Intermediate"), root, rootKey)
	leaf, _ := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "apexconnect.example.com"},
		DNSNames:     []string{"apexconnect.example.com"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, inter, interKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	chain := []*x509.Certificate{leaf, inter}

	// A host that serves a trusted certificate issued for another name: the
	// chain is trusted, and only the name check fails. Before, the chain check
	// failed as well, because it verified the host name too.
	assert.True(t, chainVerified(chain, roots), "a trusted chain is verified whatever host served it")
	assert.False(t, certMatchesDomain(leaf, "dev.workflow.example.com"))

	assert.False(t, chainVerified(chain, x509.NewCertPool()), "a chain to an unknown root is not verified")
	assert.False(t, chainVerified([]*x509.Certificate{leaf}, roots), "a missing intermediate breaks the chain")
	assert.False(t, chainVerified(nil, roots))
}
