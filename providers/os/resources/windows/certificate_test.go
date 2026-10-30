// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// derFixture is a real, self-signed DER certificate, base64 encoded. It is a
// throwaway generated for this test, not one taken from a live store, so the
// fixture carries no host's trust decisions.
//
// It is a genuine certificate rather than arbitrary bytes so that Pem's output
// can be handed to crypto/x509 and actually parse. A fixture of random bytes
// would let a broken line-wrapping change pass.
const derFixture = `MIIBjDCCATGgAwIBAgIUPW/qN6XcmF05Hewgb1nO9Qj+zDEwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQbXFsLXRlc3QtZml4dHVyZTAeFw0yNjA5MTExODA0MTJaFw0zNjA5MDgxODA0MTJaMBsxGTAXBgNVBAMMEG1xbC10ZXN0LWZpeHR1cmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATM4KDNWkZxeA0kkB4Z9Mkze1SBDOENeAKdCC8gV0PYPXkaAFaOT7aeKBzr48WZW1VgClt+b2nGxCBksKObMt1no1MwUTAdBgNVHQ4EFgQUwb6o6KjwUfuRAIBqBBAfUevQ1bUwHwYDVR0jBBgwFoAUwb6o6KjwUfuRAIBqBBAfUevQ1bUwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAjj9oc8hRpCrFY4WlhqOtltwCoV4pR6XFaJZ9/FbBLCoCIQDI33eVInLxgX0beTkpfNllk0+8qPnmQqtqwogQP4+9Cw==`

func TestParseCertificates(t *testing.T) {
	in := `[
 {"Location":"LocalMachine","Store":"Root","Thumbprint":"DF3C24F9BFD666761B268073FE06D1CC8D4F82A4","HasPrivateKey":false,"Der":"` + derFixture + `"},
 {"Location":"LocalMachine","Store":"My","Thumbprint":"A1B2C3D4E5F60718293A4B5C6D7E8F9001122334","HasPrivateKey":true,"Der":"` + derFixture + `"},
 {"Location":"CurrentUser","Store":"Disallowed","Thumbprint":"FFEEDDCCBBAA99887766554433221100AABBCCDD","HasPrivateKey":false,"Der":""}
]`
	certs, err := ParseCertificates(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, certs, 3)

	// Every field read by value: a mistyped struct tag yields the zero value
	// rather than an error, so only comparing the value catches it.
	assert.Equal(t, "LocalMachine", certs[0].Location)
	assert.Equal(t, "Root", certs[0].Store)
	assert.Equal(t, "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4", certs[0].Thumbprint)

	// hasPrivateKey distinguishes a certificate the host can sign with from one
	// it merely trusts, so it must not read false for both.
	assert.False(t, certs[0].HasPrivateKey)
	assert.True(t, certs[1].HasPrivateKey, "a store entry holding a private key must read true")
}

func TestParseCertificatesEmpty(t *testing.T) {
	// A target whose stores could not be opened is a normal state, not an error.
	for _, in := range []string{"", "   ", "null", "[]"} {
		certs, err := ParseCertificates(strings.NewReader(in))
		require.NoError(t, err, "input %q", in)
		assert.Empty(t, certs, "input %q", in)
	}
}

func TestParseCertificatesMalformed(t *testing.T) {
	_, err := ParseCertificates(strings.NewReader(`{"Location":`))
	assert.Error(t, err)
}

// TestCertificateID pins the property that keeps the resource cache honest.
//
// The same certificate in two stores must not produce the same id. It would
// collide in the cache, and CreateResource returns the cached first instance
// for a repeated id, so the Disallowed entry below would silently report
// itself as living in Root.
func TestCertificateID(t *testing.T) {
	const tp = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
	root := Certificate{Location: "LocalMachine", Store: "Root", Thumbprint: tp}
	disallowed := Certificate{Location: "LocalMachine", Store: "Disallowed", Thumbprint: tp}
	user := Certificate{Location: "CurrentUser", Store: "Root", Thumbprint: tp}

	assert.NotEqual(t, root.ID(), disallowed.ID(), "same certificate in two stores must not share an id")
	assert.NotEqual(t, root.ID(), user.ID(), "same certificate in two locations must not share an id")
	assert.Equal(t, "LocalMachine/Root/"+tp, root.ID())
}

func TestCertificatePem(t *testing.T) {
	c := Certificate{Der: derFixture}
	got := c.Pem()

	require.True(t, strings.HasPrefix(got, "-----BEGIN CERTIFICATE-----\n"))
	require.True(t, strings.HasSuffix(got, "-----END CERTIFICATE-----\n"))

	// The body must be wrapped at 64 characters, which is what RFC 7468
	// requires of a generator.
	body := strings.Split(strings.TrimSpace(got), "\n")
	body = body[1 : len(body)-1]
	for i, line := range body[:len(body)-1] {
		assert.Len(t, line, 64, "body line %d is not wrapped at 64", i)
	}

	// The output must actually decode, which is what a downstream parser does
	// with it. A wrapping bug that still looks like PEM fails here.
	block, _ := pem.Decode([]byte(got))
	require.NotNil(t, block, "Pem output did not decode as PEM")
	assert.Equal(t, "CERTIFICATE", block.Type)

	raw, err := base64.StdEncoding.DecodeString(derFixture)
	require.NoError(t, err)
	assert.Equal(t, raw, block.Bytes, "PEM body did not round trip to the original DER")
}

func TestCertificatePemRejectsUnusableBytes(t *testing.T) {
	// An entry with no bytes, or bytes that are not base64, yields no PEM
	// rather than a PEM wrapper around garbage. The resource reports the store
	// entry with a null certificate, which keeps the entry visible.
	assert.Empty(t, Certificate{Der: ""}.Pem())
	assert.Empty(t, Certificate{Der: "   "}.Pem())
	assert.Empty(t, Certificate{Der: "not!valid!base64!"}.Pem())
}

// TestCertificatePemParsesAsX509 proves the wrapping is usable by the parser
// the resource actually hands it to, rather than only looking like PEM.
func TestCertificatePemParsesAsX509(t *testing.T) {
	block, _ := pem.Decode([]byte(Certificate{Der: derFixture}.Pem()))
	require.NotNil(t, block)

	_, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "the fixture must be a real certificate for this test to mean anything")
}
