// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// connOpts returns the Options map from the single connection ParseCLI builds,
// failing the test if the response shape is unexpected.
func connOpts(t *testing.T, res *plugin.ParseCLIRes) map[string]string {
	t.Helper()
	require.NotNil(t, res)
	require.NotNil(t, res.Asset)
	require.Len(t, res.Asset.Connections, 1)
	return res.Asset.Connections[0].Options
}

// connCreds returns the credentials from the single connection ParseCLI builds.
func connCreds(t *testing.T, res *plugin.ParseCLIRes) []*vault.Credential {
	t.Helper()
	require.NotNil(t, res)
	require.NotNil(t, res.Asset)
	require.Len(t, res.Asset.Connections, 1)
	return res.Asset.Connections[0].Credentials
}

// TestParseCLINilFlags is a regression test: the flags map only carries keys the
// running command actually set, so any flag the user omitted resolves to a nil
// *llx.Primitive. ParseCLI used to dereference every flag unconditionally, so
// `mql run ms365 --tenant-id ... --client-id ... --certificate-path ...`
// panicked on the first flag the user had not passed (`organization`) before
// reaching any resource.
func TestParseCLINilFlags(t *testing.T) {
	s := Init()

	t.Run("empty flags map does not panic", func(t *testing.T) {
		var res *plugin.ParseCLIRes
		var err error
		require.NotPanics(t, func() {
			res, err = s.ParseCLI(&plugin.ParseCLIReq{
				Flags: map[string]*llx.Primitive{},
			})
		})
		require.NoError(t, err)
		opts := connOpts(t, res)
		// unset flags map to empty strings, not a crash
		assert.Empty(t, opts[connection.OptionTenantID])
		assert.Empty(t, opts[connection.OptionClientID])
		assert.Empty(t, opts[connection.OptionOrganization])
		assert.Empty(t, opts[connection.OptionSharepointUrl])
		// an unset auth-method is omitted entirely rather than set to ""
		assert.NotContains(t, opts, connection.OptionAuthMethod)
		assert.Empty(t, connCreds(t, res))
	})

	t.Run("explicitly nil primitives do not panic", func(t *testing.T) {
		var err error
		require.NotPanics(t, func() {
			_, err = s.ParseCLI(&plugin.ParseCLIReq{
				Flags: map[string]*llx.Primitive{
					"tenant-id":          nil,
					"client-id":          nil,
					"client-secret":      nil,
					"certificate-path":   nil,
					"certificate-secret": nil,
					"organization":       nil,
					"sharepoint-url":     nil,
					"auth-method":        nil,
				},
			})
		})
		require.NoError(t, err)
	})

	t.Run("partial flags: only the auth flags a user typically passes", func(t *testing.T) {
		var res *plugin.ParseCLIRes
		var err error
		require.NotPanics(t, func() {
			res, err = s.ParseCLI(&plugin.ParseCLIReq{
				Flags: map[string]*llx.Primitive{
					"tenant-id":        llx.StringPrimitive("tid"),
					"client-id":        llx.StringPrimitive("cid"),
					"certificate-path": llx.StringPrimitive("/tmp/cert.pem"),
				},
			})
		})
		require.NoError(t, err)
		opts := connOpts(t, res)
		assert.Equal(t, "tid", opts[connection.OptionTenantID])
		assert.Equal(t, "cid", opts[connection.OptionClientID])
		assert.Empty(t, opts[connection.OptionOrganization])

		creds := connCreds(t, res)
		require.Len(t, creds, 1)
		assert.Equal(t, vault.CredentialType_pkcs12, creds[0].Type)
		assert.Equal(t, "/tmp/cert.pem", creds[0].PrivateKeyPath)
		assert.Empty(t, creds[0].Password)
	})
}

// TestParseCLICredentials pins which credential a given flag combination
// produces: a client secret wins over a certificate, and neither yields none.
func TestParseCLICredentials(t *testing.T) {
	s := Init()

	t.Run("client secret takes precedence over certificate", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"client-secret":    llx.StringPrimitive("shhh"),
				"certificate-path": llx.StringPrimitive("/tmp/cert.pem"),
			},
		})
		require.NoError(t, err)
		creds := connCreds(t, res)
		require.Len(t, creds, 1)
		assert.Equal(t, vault.CredentialType_password, creds[0].Type)
		assert.Equal(t, []byte("shhh"), creds[0].Secret)
	})

	t.Run("certificate with passphrase", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"certificate-path":   llx.StringPrimitive("/tmp/cert.pfx"),
				"certificate-secret": llx.StringPrimitive("pass"),
			},
		})
		require.NoError(t, err)
		creds := connCreds(t, res)
		require.Len(t, creds, 1)
		assert.Equal(t, vault.CredentialType_pkcs12, creds[0].Type)
		assert.Equal(t, "/tmp/cert.pfx", creds[0].PrivateKeyPath)
		assert.Equal(t, "pass", creds[0].Password)
	})

	t.Run("no auth flags yields no credentials", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"tenant-id": llx.StringPrimitive("tid"),
			},
		})
		require.NoError(t, err)
		assert.Empty(t, connCreds(t, res))
	})
}

// TestParseCLIAuthMethod pins that auth-method is only forwarded when non-empty,
// so an unset flag leaves the connection's default probe order intact rather
// than pinning it to "".
func TestParseCLIAuthMethod(t *testing.T) {
	s := Init()

	t.Run("set", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"auth-method": llx.StringPrimitive("cli,env"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "cli,env", connOpts(t, res)[connection.OptionAuthMethod])
	})

	t.Run("empty string is omitted", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"auth-method": llx.StringPrimitive(""),
			},
		})
		require.NoError(t, err)
		assert.NotContains(t, connOpts(t, res), connection.OptionAuthMethod)
	})
}
