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
	certs, nonSni, nonSniErr, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.NoError(t, nonSniErr)
	require.Len(t, certs, 1)
	assert.Equal(t, "sni.example", certs[0].Subject.CommonName)
	require.Len(t, nonSni, 1)
	assert.Equal(t, "default.example", nonSni[0].Subject.CommonName)
}

// serveTLS accepts TLS connections on a local port until the test ends and
// returns the port.
func serveTLS(t *testing.T, conf *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
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

// A server that answers a client without SNI with a TLS alert, as Cloudflare
// does, presents no certificate to such clients. The SNI certificates are
// still reported, and there are no non-SNI certificates, rather than an error
// that would also hide the SNI certificates.
func TestGatherTlsCertificatesServerRefusesNoSNI(t *testing.T) {
	sni := tlsCert(t, "sni.example", 1)
	port := serveTLS(t, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				return nil, errors.New("no SNI")
			}
			return &sni, nil
		},
	})

	certs, nonSni, nonSniErr, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.NoError(t, nonSniErr)
	require.Len(t, certs, 1)
	assert.Equal(t, "sni.example", certs[0].Subject.CommonName)
	assert.Empty(t, nonSni)
}

// A handshake without SNI that fails for another reason, here a dropped
// connection, is an error for the non-SNI certificates only.
func TestGatherTlsCertificatesNoSNIHandshakeFails(t *testing.T) {
	sni := tlsCert(t, "sni.example", 1)
	port := serveTLS(t, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName == "" {
				hello.Conn.Close()
				return nil, errors.New("no SNI")
			}
			return nil, nil
		},
		Certificates: []tls.Certificate{sni},
	})

	certs, nonSni, nonSniErr, err := gatherTlsCertificates("tcp", "localhost", port, "localhost")
	require.NoError(t, err)
	require.Error(t, nonSniErr)
	require.Len(t, certs, 1)
	assert.Equal(t, "sni.example", certs[0].Subject.CommonName)
	assert.Nil(t, nonSni)
}
