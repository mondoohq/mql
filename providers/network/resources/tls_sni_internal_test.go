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
	"errors"
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

// serveTLS answers TLS handshakes on a local port with the certificate
// getCert picks, and returns the port.
func serveTLS(t *testing.T, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: getCert})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
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
	return port
}

// A server that presents one certificate for SNI "localhost" and another to
// clients without SNI: nonSniCertificates is the second (#11130).
func TestGatherTlsCertificatesWithoutSNI(t *testing.T) {
	sni := tlsCert(t, "sni.example", 1)
	def := tlsCert(t, "default.example", 2)
	port := serveTLS(t, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "localhost" {
			return &sni, nil
		}
		return &def, nil
	})

	// The host is a name, as in a scan of https://localhost:<port>: a dial
	// that derives ServerName from it sends SNI in both handshakes.
	certs, nonSni, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "sni.example", certs[0].Subject.CommonName)
	require.Len(t, nonSni, 1)
	assert.Equal(t, "default.example", nonSni[0].Subject.CommonName)
}

// A server that presents the same certificate with and without SNI does serve
// it without SNI, so the non-SNI chain reports it rather than coming back
// empty.
func TestGatherTlsCertificatesReportsAnIdenticalNonSniChain(t *testing.T) {
	same := tlsCert(t, "same.example", 1)
	port := serveTLS(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &same, nil
	})

	certs, nonSni, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Len(t, nonSni, 1)
	assert.Equal(t, "same.example", nonSni[0].Subject.CommonName)
}

// A server that requires SNI rejects the non-SNI handshake. That must not
// fail the SNI chain with it, and the non-SNI chain is unknown (nil), not
// empty.
func TestGatherTlsCertificatesEndpointRequiresSNI(t *testing.T) {
	sni := tlsCert(t, "sni.example", 1)
	port := serveTLS(t, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			return nil, errors.New("this endpoint requires SNI")
		}
		return &sni, nil
	})

	certs, nonSni, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "sni.example", certs[0].Subject.CommonName)
	assert.Nil(t, nonSni)
}
