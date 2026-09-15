// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package certificates

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificates(t *testing.T) {
	file := "./testdata/ca-bundle.crt"

	f, err := os.Open(file)
	require.NoError(t, err)

	certs, err := ParseCertsFromPEM(f)
	require.NoError(t, err)

	assert.Equal(t, 17, len(certs))
}

// mixedBundle is the 17-certificate good bundle with the real negative-serial
// EC-ACC root appended, mirroring the centos:7 trust store where a single
// unparseable root sat among 135 good ones.
func mixedBundle(t *testing.T) []byte {
	t.Helper()
	good, err := os.ReadFile("./testdata/ca-bundle.crt")
	require.NoError(t, err)
	bad, err := os.ReadFile("./testdata/negative-serial.crt")
	require.NoError(t, err)
	return append(good, bad...)
}

// One certificate the x509 parser rejects must not take the rest of the bundle
// with it: before this was fixed the whole list errored out with "x509:
// negative serial number" and every root-CA audit saw an empty trust store.
func TestParseCertsFromPEMPartial_SkipsUnparseableBlock(t *testing.T) {
	certs, skipped, err := ParseCertsFromPEMPartial(bytes.NewReader(mixedBundle(t)))
	require.NoError(t, err)
	assert.Equal(t, 17, len(certs))
	assert.Equal(t, 1, skipped)
}

// The lenient path has to stay lenient through the public entry point too.
func TestParseCertsFromPEM_SkipsUnparseableBlock(t *testing.T) {
	certs, err := ParseCertsFromPEM(bytes.NewReader(mixedBundle(t)))
	require.NoError(t, err)
	assert.Equal(t, 17, len(certs))
}

// A bundle in which nothing parses must still be an error. Returning an empty
// list would read as "no roots configured", which is a worse answer than a
// failure.
func TestParseCertsFromPEMPartial_AllBlocksBadIsAnError(t *testing.T) {
	bad, err := os.ReadFile("./testdata/negative-serial.crt")
	require.NoError(t, err)

	certs, skipped, err := ParseCertsFromPEMPartial(bytes.NewReader(bad))
	require.Error(t, err)
	assert.Empty(t, certs)
	assert.Equal(t, 1, skipped)
}

// Input carrying no certificate block at all is an error, not an empty store.
func TestParseCertsFromPEMPartial_NoCertificateBlocks(t *testing.T) {
	certs, skipped, err := ParseCertsFromPEMPartial(strings.NewReader("not a certificate at all"))
	require.Error(t, err)
	assert.Empty(t, certs)
	assert.Equal(t, 0, skipped)
}

// A clean bundle is unaffected by the skip logic.
func TestParseCertsFromPEMPartial_AllGood(t *testing.T) {
	f, err := os.Open("./testdata/ca-bundle.crt")
	require.NoError(t, err)
	defer f.Close()

	certs, skipped, err := ParseCertsFromPEMPartial(f)
	require.NoError(t, err)
	assert.Equal(t, 17, len(certs))
	assert.Equal(t, 0, skipped)
}
