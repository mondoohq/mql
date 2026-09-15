// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// ParseCertsFromPEM parses every certificate block in a PEM stream. Blocks the
// x509 parser rejects are skipped so that a single bad certificate does not
// discard the rest of the bundle. It returns an error only when no certificate
// could be parsed at all.
func ParseCertsFromPEM(r io.Reader) ([]*x509.Certificate, error) {
	certs, _, err := ParseCertsFromPEMPartial(r)
	return certs, err
}

// ParseCertsFromPEMPartial behaves like ParseCertsFromPEM and additionally
// returns how many certificate blocks were skipped because they failed to
// parse. Trust stores in the wild carry roots that Go rejects, e.g. the EC-ACC
// root in the CentOS 7 bundle whose serial number is negative, and callers need
// to be able to tell a complete read from a partial one.
func ParseCertsFromPEMPartial(r io.Reader) ([]*x509.Certificate, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}

	certs := []*x509.Certificate{}
	blocks := 0
	skipped := 0

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		// only PEM blocks without headers hold a DER certificate
		if block.Type != CertificateBlockType || len(block.Headers) != 0 {
			continue
		}

		blocks++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			skipped++
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		if blocks == 0 {
			return nil, skipped, errors.New("data does not contain any certificate")
		}
		return nil, skipped, fmt.Errorf("data does not contain any parsable certificate, %d block(s) failed to parse", skipped)
	}

	return certs, skipped, nil
}

func EncodeCertAsPEM(cert *x509.Certificate) ([]byte, error) {
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: CertificateBlockType, Bytes: cert.Raw}); err != nil {
		return nil, err
	}
	return certBuffer.Bytes(), nil
}

const (
	// CertificateBlockType is a possible value for pem.Block.Type.
	CertificateBlockType = "CERTIFICATE"
)
