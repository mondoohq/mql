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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sniRecorder is a TLS endpoint that records the server name each handshake
// asked for and answers with a certificate named after it, so a probe's SNI can
// be read back off the certificate it receives.
type sniRecorder struct {
	addr        string
	lastSNI     atomic.Pointer[string]
	requireSNI  atomic.Bool
	defaultName string
}

func newSNIRecorder(t *testing.T, defaultName string) *sniRecorder {
	t.Helper()

	rec := &sniRecorder{defaultName: defaultName}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	rec.addr = listener.Addr().String()

	config := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Record what the handshake actually asked for, in its own
			// variable: storing a pointer to one that is then reassigned would
			// report the substituted default instead of the empty name.
			observed := hello.ServerName
			rec.lastSNI.Store(&observed)

			name := hello.ServerName
			if name == "" {
				if rec.requireSNI.Load() {
					return nil, assertRequiresSNI
				}
				name = rec.defaultName
			}
			return selfSignedFor(name)
		},
	}

	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				conn := tls.Server(raw, config)
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_ = conn.Handshake()
				_ = conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })

	return rec
}

var assertRequiresSNI = &sniRequiredError{}

type sniRequiredError struct{}

func (*sniRequiredError) Error() string { return "this endpoint requires SNI" }

func selfSignedFor(commonName string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func splitAddr(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return host, port
}

func TestDialTLSWithoutSNISendsNoServerName(t *testing.T) {
	// tls.DialWithDialer clones the config and fills ServerName in from the
	// dial address whenever it is empty, so the "without SNI" probe was sending
	// SNI for the host being dialed and the two chains always came back
	// identical.
	rec := newSNIRecorder(t, "default.example")

	conn, err := dialTLSWithoutSNI(&net.Dialer{Timeout: 5 * time.Second}, "tcp", rec.addr)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, rec.lastSNI.Load())
	assert.Equal(t, "", *rec.lastSNI.Load(), "no server_name extension should be sent")

	certs := conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, certs)
	assert.Equal(t, "default.example", certs[0].Subject.CommonName)
}

func TestGatherTlsCertificatesReportsTheFullNonSniChain(t *testing.T) {
	// The two chains differ here, which is the case that matters: a default
	// virtual host answering an address with an unrelated certificate.
	rec := newSNIRecorder(t, "default.example")
	host, port := splitAddr(t, rec.addr)

	sniCerts, nonSniCerts, err := gatherTlsCertificates("tcp", host, port, "asked-for.example")
	require.NoError(t, err)

	require.NotEmpty(t, sniCerts)
	assert.Equal(t, "asked-for.example", sniCerts[0].Subject.CommonName)

	require.NotEmpty(t, nonSniCerts, "the non-SNI chain must be reported, not diffed away")
	assert.Equal(t, "default.example", nonSniCerts[0].Subject.CommonName)
}

func TestGatherTlsCertificatesReportsAnIdenticalNonSniChain(t *testing.T) {
	// The endpoint serves the same certificate either way. It genuinely does
	// serve that certificate without SNI, so reporting nothing here would say
	// the opposite.
	rec := newSNIRecorder(t, "same.example")
	host, port := splitAddr(t, rec.addr)

	sniCerts, nonSniCerts, err := gatherTlsCertificates("tcp", host, port, "same.example")
	require.NoError(t, err)

	require.NotEmpty(t, sniCerts)
	require.NotEmpty(t, nonSniCerts)
	assert.Equal(t, "same.example", nonSniCerts[0].Subject.CommonName)
}

func TestGatherTlsCertificatesSurvivesAnEndpointThatRequiresSNI(t *testing.T) {
	// The non-SNI handshake fails. That must not take the SNI chain down with
	// it: before, an error from the second connection failed both.
	rec := newSNIRecorder(t, "default.example")
	rec.requireSNI.Store(true)
	host, port := splitAddr(t, rec.addr)

	sniCerts, nonSniCerts, err := gatherTlsCertificates("tcp", host, port, "asked-for.example")
	require.NoError(t, err, "a server that requires SNI is an answer, not a scan failure")

	require.NotEmpty(t, sniCerts)
	assert.Equal(t, "asked-for.example", sniCerts[0].Subject.CommonName)
	assert.Nil(t, nonSniCerts, "unknown, rather than an empty chain")
}
