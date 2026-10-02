// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package certificates

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"
)

var cipherSuites = map[string]uint16{
	// TLS 1.0 - 1.2 cipher suites.
	"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

	// TLS 1.3 cipher suites.
	"TLS_AES_128_GCM_SHA256": tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384": tls.TLS_AES_256_GCM_SHA384,
}

var userTempl string //nolint:unused

var TimeoutSeconds = 3

func cipherSuite(suite string) ([]uint16, error) {
	if suite == "" {
		return nil, nil
	}

	cs := []uint16{cipherSuites[suite]}
	if cs[0] == 0 {
		return nil, fmt.Errorf("%s is unsupported cipher suite or tls1.3 cipher suite", suite)
	}
	return cs, nil
}

func tlsVersion(suite string) uint16 {
	if suite != "" {
		return tls.VersionTLS12
	}
	// Currently TLS 1.3
	return 0
}

var gatherPeerCertificates = func(host, port string, ciphersuite string, insecureskipverify bool) ([]*x509.Certificate, error) {
	d := &net.Dialer{
		Timeout: time.Duration(TimeoutSeconds) * time.Second,
	}

	cs, err := cipherSuite(ciphersuite)
	if err != nil {
		return nil, err
	}

	conn, err := tls.DialWithDialer(d, "tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: insecureskipverify,
		CipherSuites:       cs,
		MaxVersion:         tlsVersion(ciphersuite),
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// addr := conn.RemoteAddr()
	// ip, _, _ := net.SplitHostPort(addr.String())
	cert := conn.ConnectionState().PeerCertificates

	return cert, nil
}

func Fetch(hostport string) ([]*x509.Certificate, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}

	return gatherPeerCertificates(host, port, "", true)
}

// SerialToHumanString prints a certificate serial number as colon-separated
// hex. big.Int.Bytes drops the sign and yields nothing for zero, so a negative
// serial would print as a different, positive one and a zero serial as empty.
// The sign is kept as a leading "-" and zero prints as "00", as OpenSSL does.
func SerialToHumanString(n *big.Int) string {
	if n == nil {
		return ""
	}
	switch n.Sign() {
	case 0:
		return "00"
	case -1:
		return "-" + HexEncodeToHumanString(n.Bytes())
	}
	return HexEncodeToHumanString(n.Bytes())
}

func HexEncodeToHumanString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return string(buf[:len(buf)-1])
}

func Sha1Hash(cert *x509.Certificate) []byte {
	h := sha1.New()
	if cert != nil {
		h.Write(cert.Raw)
	}
	return h.Sum(nil)
}

func Sha256Hash(cert *x509.Certificate) []byte {
	h := sha256.New()
	if cert != nil {
		h.Write(cert.Raw)
	}
	return h.Sum(nil)
}

func Md5Hash(cert *x509.Certificate) []byte {
	h := md5.New()
	if cert != nil {
		h.Write(cert.Raw)
	}
	return h.Sum(nil)
}

func Fingerprints(cert *x509.Certificate) map[string]any {
	return map[string]any{
		"sha1":   hex.EncodeToString(Sha1Hash(cert)),
		"sha256": hex.EncodeToString(Sha256Hash(cert)),
		"md5":    hex.EncodeToString(Md5Hash(cert)),
	}
}
