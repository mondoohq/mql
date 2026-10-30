// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"
)

// applicationURI identifies this client to an OPC UA server. It has to match
// the URI subject alternative name of the certificate presented on the secure
// channel, otherwise the server rejects the channel.
const applicationURI = "urn:mondoo:mql:opcua"

// applicationName is the human readable client name sent in the session
// description.
const applicationName = "Mondoo MQL OPC UA client"

// ephemeralCertificate builds a short lived self-signed client certificate.
//
// Every security policy other than None requires the client to present an
// application instance certificate on the secure channel. Without one a
// hardened server cannot be reached at all, so we generate a throwaway
// certificate when the user did not supply one with `--cert-file`. A server
// that only trusts known client certificates still needs the explicit flags,
// but a server that accepts unknown clients becomes scannable with no setup.
//
// The key never leaves the process: it is created per connection, kept in
// memory, and discarded when the connection closes.
func ephemeralCertificate() (certDER []byte, key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}

	uri, err := url.Parse(applicationURI)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   applicationName,
			Organization: []string{"Mondoo"},
		},
		// tolerate a small clock skew between client and server
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		// A client certificate signs nothing but its own handshake, so it gets
		// neither KeyUsageCertSign nor the server EKU. Some servers reject an
		// over-privileged client certificate outright.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}

	certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return certDER, key, nil
}
