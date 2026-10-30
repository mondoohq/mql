// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/x509"
	"testing"

	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNewClientOptions(t *testing.T) {
	conf := &inventory.Config{
		Type: "opcua",
		Options: map[string]string{
			OptionEndpoint:       "opc.tcp://server:4840",
			OptionSecurityPolicy: "Basic256Sha256",
			OptionSecurityMode:   "SignAndEncrypt",
			OptionCertFile:       "/tmp/client.der",
			OptionKeyFile:        "/tmp/client.key",
		},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("operator", "secret"),
		},
	}

	opts, err := newClientOptions(conf)
	require.NoError(t, err)
	assert.Equal(t, "opc.tcp://server:4840", opts.endpoint)
	assert.Equal(t, "Basic256Sha256", opts.securityPolicy)
	assert.Equal(t, "SignAndEncrypt", opts.securityMode)
	assert.Equal(t, "/tmp/client.der", opts.certFile)
	assert.Equal(t, "/tmp/client.key", opts.keyFile)
	assert.Equal(t, "operator", opts.username)
	assert.Equal(t, "secret", opts.password)
	assert.Equal(t, ua.UserTokenTypeUserName, opts.tokenType())
}

func TestNewClientOptions_DefaultsToAnonymousAndAutomaticSecurity(t *testing.T) {
	opts, err := newClientOptions(&inventory.Config{
		Type:    "opcua",
		Options: map[string]string{OptionEndpoint: "opc.tcp://server:4840"},
	})
	require.NoError(t, err)
	assert.Empty(t, opts.securityPolicy)
	assert.Empty(t, opts.securityMode)
	assert.Equal(t, ua.UserTokenTypeAnonymous, opts.tokenType())
}

func TestNewClientOptions_Errors(t *testing.T) {
	tests := []struct {
		name    string
		conf    *inventory.Config
		wantErr string
	}{
		{
			name:    "no options at all",
			conf:    &inventory.Config{Type: "opcua"},
			wantErr: "requires an endpoint",
		},
		{
			name:    "empty endpoint",
			conf:    &inventory.Config{Type: "opcua", Options: map[string]string{OptionEndpoint: ""}},
			wantErr: "requires an endpoint",
		},
		{
			name: "certificate without key",
			conf: &inventory.Config{Type: "opcua", Options: map[string]string{
				OptionEndpoint: "opc.tcp://server:4840",
				OptionCertFile: "/tmp/client.der",
			}},
			wantErr: "cert-file",
		},
		{
			name: "key without certificate",
			conf: &inventory.Config{Type: "opcua", Options: map[string]string{
				OptionEndpoint: "opc.tcp://server:4840",
				OptionKeyFile:  "/tmp/client.key",
			}},
			wantErr: "key-file",
		},
		{
			name: "unknown security policy",
			conf: &inventory.Config{Type: "opcua", Options: map[string]string{
				OptionEndpoint:       "opc.tcp://server:4840",
				OptionSecurityPolicy: "Basic999",
			}},
			wantErr: "unsupported security policy",
		},
		{
			name: "unknown security mode",
			conf: &inventory.Config{Type: "opcua", Options: map[string]string{
				OptionEndpoint:     "opc.tcp://server:4840",
				OptionSecurityMode: "encrypt",
			}},
			wantErr: "unsupported security mode",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newClientOptions(test.conf)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantErr)
		})
	}
}

// A username with no password is a valid configuration for servers that
// authenticate against an empty secret, and must not fall back to anonymous.
func TestNewClientOptions_UsernameWithoutPassword(t *testing.T) {
	opts, err := newClientOptions(&inventory.Config{
		Type:        "opcua",
		Options:     map[string]string{OptionEndpoint: "opc.tcp://server:4840"},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("operator", "")},
	})
	require.NoError(t, err)
	assert.Equal(t, ua.UserTokenTypeUserName, opts.tokenType())
	assert.Empty(t, opts.password)
}

func TestNewClientOptions_SkipsNilAndNonPasswordCredentials(t *testing.T) {
	opts, err := newClientOptions(&inventory.Config{
		Type:    "opcua",
		Options: map[string]string{OptionEndpoint: "opc.tcp://server:4840"},
		Credentials: []*vault.Credential{
			nil,
			{Type: vault.CredentialType_ssh_agent, User: "ignored"},
			vault.NewPasswordCredential("operator", "secret"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "operator", opts.username)
}

// The certificate is what makes a secured channel possible at all, so it has to
// carry the application URI the session announces.
func TestEphemeralCertificate(t *testing.T) {
	certDER, key, err := ephemeralCertificate()
	require.NoError(t, err)
	require.NotNil(t, key)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	assert.Equal(t, applicationURI, cert.URIs[0].String())
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageKeyEncipherment)
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.True(t, cert.NotBefore.Before(cert.NotAfter))

	// each connection gets its own key
	otherDER, _, err := ephemeralCertificate()
	require.NoError(t, err)
	assert.NotEqual(t, certDER, otherDER)
}
