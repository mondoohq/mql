// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OCI omits SslConfiguration entirely when a listener or backend set carries no
// TLS, and omits the cookie configuration when session persistence is off. Both
// absences have to land on the failing side of an audit: a null would satisfy
// `sslVerifyPeerCertificate == true` under MQL's three-valued logic, so "not
// configured" would read as "verified".

func TestLbSslFieldsFromNilReportsNotConfigured(t *testing.T) {
	out := lbSslFieldsFrom(nil)

	assert.False(t, out.verifyPeerCertificate, "absent TLS must not report peer verification")
	assert.False(t, out.hasSessionResumption)
	assert.Empty(t, out.protocols)
	assert.Equal(t, "", out.cipherSuiteName)
	assert.Equal(t, "", out.serverOrderPreference)
	assert.Equal(t, "", out.certificateName)
	assert.Nil(t, out.verifyDepth, "verifyDepth stays null so it is not read as depth 0")
	assert.Empty(t, out.certificateIDs)
	assert.Empty(t, out.trustedCaIDs)
}

func TestLbSslFieldsFromPopulated(t *testing.T) {
	out := lbSslFieldsFrom(&loadbalancer.SslConfiguration{
		VerifyDepth:                    new(3),
		VerifyPeerCertificate:          new(true),
		HasSessionResumption:           new(true),
		CipherSuiteName:                new("oci-modern-ssl-cipher-suite-v1"),
		Protocols:                      []string{"TLSv1.2", "TLSv1.3"},
		CertificateName:                new("example_bundle"),
		ServerOrderPreference:          loadbalancer.SslConfigurationServerOrderPreferenceEnabled,
		CertificateIds:                 []string{"ocid1.certificate.oc1..cert"},
		TrustedCertificateAuthorityIds: []string{"ocid1.certificateauthority.oc1..ca"},
	})

	assert.True(t, out.verifyPeerCertificate)
	assert.True(t, out.hasSessionResumption)
	assert.Equal(t, []any{"TLSv1.2", "TLSv1.3"}, out.protocols)
	assert.Equal(t, "oci-modern-ssl-cipher-suite-v1", out.cipherSuiteName)
	assert.Equal(t, "ENABLED", out.serverOrderPreference)
	assert.Equal(t, "example_bundle", out.certificateName)
	require.NotNil(t, out.verifyDepth)
	assert.Equal(t, 3, *out.verifyDepth)
	assert.Equal(t, []any{"ocid1.certificate.oc1..cert"}, out.certificateIDs)
	assert.Equal(t, []any{"ocid1.certificateauthority.oc1..ca"}, out.trustedCaIDs)
}

// A TLS configuration that leaves the optional flags unset must not invent
// values for them: OCI treats an absent verifyPeerCertificate as "off", which
// is the direction an audit needs to see.
func TestLbSslFieldsFromOptionalFlagsAbsent(t *testing.T) {
	out := lbSslFieldsFrom(&loadbalancer.SslConfiguration{
		Protocols: []string{"TLSv1.2"},
	})

	assert.False(t, out.verifyPeerCertificate)
	assert.False(t, out.hasSessionResumption)
	assert.Nil(t, out.verifyDepth)
	assert.Equal(t, []any{"TLSv1.2"}, out.protocols)
}

func TestLbCookieFieldsFromNilReportsNotConfigured(t *testing.T) {
	out := lbCookieFieldsFrom(nil)

	assert.Equal(t, "", out.name)
	assert.False(t, out.isSecure, "absent cookie config must not report the Secure attribute")
	assert.False(t, out.isHttpOnly, "absent cookie config must not report the HttpOnly attribute")
	assert.False(t, out.disableFallback)
	assert.Equal(t, "", out.domain)
	assert.Equal(t, "", out.path)
	assert.Nil(t, out.maxAgeInSeconds, "an absent Max-Age stays null rather than becoming 0 seconds")
}

func TestLbCookieFieldsFromPopulated(t *testing.T) {
	out := lbCookieFieldsFrom(&loadbalancer.LbCookieSessionPersistenceConfigurationDetails{
		CookieName:      new("X-Oracle-OCI-route"),
		DisableFallback: new(true),
		Domain:          new("example.com"),
		Path:            new("/app"),
		MaxAgeInSeconds: new(3600),
		IsSecure:        new(true),
		IsHttpOnly:      new(true),
	})

	assert.Equal(t, "X-Oracle-OCI-route", out.name)
	assert.True(t, out.disableFallback)
	assert.Equal(t, "example.com", out.domain)
	assert.Equal(t, "/app", out.path)
	require.NotNil(t, out.maxAgeInSeconds)
	assert.Equal(t, 3600, *out.maxAgeInSeconds)
	assert.True(t, out.isSecure)
	assert.True(t, out.isHttpOnly)
}

// A cookie the load balancer inserts without Secure or HttpOnly is the finding
// these fields exist to surface, so pin that shape explicitly.
func TestLbCookieFieldsFromInsecureCookie(t *testing.T) {
	out := lbCookieFieldsFrom(&loadbalancer.LbCookieSessionPersistenceConfigurationDetails{
		CookieName: new("session"),
	})

	assert.Equal(t, "session", out.name)
	assert.False(t, out.isSecure)
	assert.False(t, out.isHttpOnly)
}
