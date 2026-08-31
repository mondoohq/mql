// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

func TestExtensionValueToReadableFormat(t *testing.T) {
	// ASN.1-encoded DNS name "example.com" for the SAN extension.
	sanValue, err := asn1.Marshal([]asn1.RawValue{
		{
			Tag:   asn1.TagIA5String, // TagIA5String is commonly used for DNS names
			Bytes: []byte("example.com"),
		},
	})
	if err != nil {
		t.Fatalf("Error marshaling test SAN value: %v", err)
	}

	testCases := []struct {
		name        string
		extension   pkix.Extension
		want        string
		expectError bool
	}{
		{
			name: "SubjectKeyIdentifier",
			extension: pkix.Extension{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
				Value: []byte{0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF},
			},
			want:        "DE:AD:BE:EF",
			expectError: false,
		},
		{
			name: "SubjectAlternativeName",
			extension: pkix.Extension{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
				Value: sanValue,
			},
			want:        "example.com",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtensionValueToReadableFormat(tc.extension)
			if (err != nil) != tc.expectError {
				t.Errorf("ExtensionValueToReadableFormat() for test '%v' unexpected error = %v", tc.name, err)
				return
			}
			if got != tc.want {
				t.Errorf("ExtensionValueToReadableFormat() for test '%v' = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func certificatesResource(t *testing.T, pem string) *mqlCertificates {
	t.Helper()
	return &mqlCertificates{
		Pem: plugin.TValue[string]{Data: pem, State: plugin.StateIsSet},
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

// A bundle holding one certificate the parser rejects has to report that one
// skipped block instead of failing, otherwise a policy asserting on the trust
// store sees an error where 17 readable roots exist.
func TestCertificatesUnparseableCountsSkippedBlocks(t *testing.T) {
	good := readTestFile(t, "./certificates/testdata/ca-bundle.crt")
	bad := readTestFile(t, "./certificates/testdata/negative-serial.crt")

	c := certificatesResource(t, good+bad)
	skipped, err := c.unparseable()
	require.NoError(t, err)
	assert.Equal(t, int64(1), skipped)
}

// A clean bundle must report nothing skipped, so unparseable stays usable as
// the "the store was read completely" assertion.
func TestCertificatesUnparseableIsZeroForCleanBundle(t *testing.T) {
	c := certificatesResource(t, readTestFile(t, "./certificates/testdata/ca-bundle.crt"))

	skipped, err := c.unparseable()
	require.NoError(t, err)
	assert.Equal(t, int64(0), skipped)
}

// When nothing in the bundle parses, list must error rather than return an
// empty slice. An empty trust store reads as "no roots configured", which is a
// worse answer than a failure.
func TestCertificatesListErrorsWhenNothingParses(t *testing.T) {
	c := certificatesResource(t, readTestFile(t, "./certificates/testdata/negative-serial.crt"))

	list, err := c.list()
	require.Error(t, err)
	assert.Empty(t, list)

	skipped, err := c.unparseable()
	require.Error(t, err)
	assert.Equal(t, int64(0), skipped)
}
