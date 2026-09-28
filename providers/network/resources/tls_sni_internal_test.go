// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tlsCert builds a self-signed server certificate with its key.
func tlsCert(t *testing.T, commonName string, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A server that presents one certificate for SNI "localhost" and another to
// clients without SNI: nonSniCertificates is the second (#11130).
func TestGatherTlsCertificatesWithoutSNI(t *testing.T) {
	sni := tlsCert(t, "sni.example", 1)
	def := tlsCert(t, "default.example", 2)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "localhost" {
				return &sni, nil
			}
			return &def, nil
		},
	})
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// The host is a name, as in a scan of https://localhost:<port>: a dial
	// that derives ServerName from it sends SNI in both handshakes.
	certs, nonSni, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "sni.example", certs[0].Subject.CommonName)
	require.Len(t, nonSni, 1)
	assert.Equal(t, "default.example", nonSni[0].Subject.CommonName)
}
