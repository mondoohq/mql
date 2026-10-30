// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Debian 9 and 10 still trust EC-ACC, whose serial number is negative. Go 1.23
// and later refuse to parse it unless x509negativeserial=1 is set, which drops
// the root from os.rootCertificates, parse.certificates and java.truststores.
// The setting comes from the //go:debug line in main.go; without it this fails
// with "x509: negative serial number".
func TestParsesNegativeSerialCertificate(t *testing.T) {
	data, err := os.ReadFile("resources/certificates/testdata/negative-serial.crt")
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, "EC-ACC", cert.Subject.CommonName)
	require.Equal(t, -1, cert.SerialNumber.Sign())
}
