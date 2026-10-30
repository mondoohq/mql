// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// TestSplitScopes covers the scope list accepted on the CLI. Okta writes scopes
// space-separated, but a flag reads more naturally comma-separated, so both
// have to survive the trip.
func TestSplitScopes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "comma separated",
			raw:  "okta.users.read,okta.groups.read",
			want: []string{"okta.users.read", "okta.groups.read"},
		},
		{
			name: "space separated",
			raw:  "okta.users.read okta.groups.read",
			want: []string{"okta.users.read", "okta.groups.read"},
		},
		{
			name: "comma with padding",
			raw:  " okta.users.read , okta.groups.read ",
			want: []string{"okta.users.read", "okta.groups.read"},
		},
		{
			name: "single scope",
			raw:  "okta.users.read",
			want: []string{"okta.users.read"},
		},
		{
			name: "empty",
			raw:  "",
			want: []string{},
		},
		{
			name: "separators only",
			raw:  " , , ",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitScopes(tt.raw))
		})
	}
}

// TestSswsAuthorizer pins the API token scheme. Okta rejects a token sent as a
// bearer, so the scheme is not interchangeable with the service app's.
func TestSswsAuthorizer(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://dev-12345.okta.com/api/v1/users", nil)
	require.NoError(t, err)

	require.NoError(t, sswsAuthorizer("abc123")(req))
	assert.Equal(t, "SSWS abc123", req.Header.Get("Authorization"))
}

// TestNewOktaConnectionRejectsIncompleteServiceApp proves each missing piece of
// the service app configuration is reported on its own terms. Okta answers all
// of them with the same opaque 401, so the check has to happen here.
func TestNewOktaConnectionRejectsIncompleteServiceApp(t *testing.T) {
	// Every case here is rejected before the key reaches the SDK, so the
	// credential only has to be non-empty. A placeholder rather than a
	// PEM-shaped literal keeps secret scanners from flagging the fixture.
	const placeholderKey = "test-private-key-material"

	tests := []struct {
		name    string
		options map[string]string
		wantErr string
	}{
		{
			name:    "missing client id",
			options: map[string]string{"organization": "dev-12345.okta.com", "private-key-id": "kid1", "scopes": "okta.users.read"},
			wantErr: "client id",
		},
		{
			name:    "missing private key id",
			options: map[string]string{"organization": "dev-12345.okta.com", "client-id": "0oa1", "scopes": "okta.users.read"},
			wantErr: "registered public key",
		},
		{
			name:    "missing scopes",
			options: map[string]string{"organization": "dev-12345.okta.com", "client-id": "0oa1", "private-key-id": "kid1"},
			wantErr: "scopes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &inventory.Config{
				Type:        "okta",
				Options:     tt.options,
				Credentials: []*vault.Credential{vault.NewPrivateKeyCredential("", []byte(placeholderKey), "")},
			}

			_, err := NewOktaConnection(0, &inventory.Asset{}, conf)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestNewOktaConnectionRequiresCredentials guards the case where neither
// authentication method was configured, which otherwise reaches Okta as an
// unauthenticated request.
func TestNewOktaConnectionRequiresCredentials(t *testing.T) {
	conf := &inventory.Config{
		Type:    "okta",
		Options: map[string]string{"organization": "dev-12345.okta.com"},
	}

	_, err := NewOktaConnection(0, &inventory.Asset{}, conf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--token")
	assert.Contains(t, err.Error(), "--private-key")
}

// TestNewOktaConnectionTokenModeAuthorizesRawRequests proves the raw HTTP path
// gets the same credential the generated SDK uses. Without it every hand-rolled
// endpoint would send an unauthenticated request.
func TestNewOktaConnectionTokenModeAuthorizesRawRequests(t *testing.T) {
	conf := &inventory.Config{
		Type:        "okta",
		Options:     map[string]string{"organization": "dev-12345.okta.com"},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "abc123")},
	}

	conn, err := NewOktaConnection(0, &inventory.Asset{}, conf)
	require.NoError(t, err)

	ext := conn.ApiExtension()
	require.NotNil(t, ext.Authorize, "the raw path must carry the connection's credential")
	assert.Equal(t, "dev-12345.okta.com", ext.Host)
	// The client holds no per-call state, so every caller shares one instance.
	assert.Same(t, ext, conn.ApiExtension())

	req, err := http.NewRequest(http.MethodGet, "https://dev-12345.okta.com/api/v1/zones", nil)
	require.NoError(t, err)
	require.NoError(t, ext.Authorize(req))
	assert.Equal(t, "SSWS abc123", req.Header.Get("Authorization"))
}
