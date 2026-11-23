// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/oauthlogin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

const sessionConfigYAML = `api_endpoint: http://127.0.0.1:8989
mrn: //captain.api.mondoo.app/users/u1
scope_mrn: //captain.api.mondoo.app/spaces/old-space
token: old-login-token
auth:
  method: oauth
  issuer: http://127.0.0.1:8989
  endpoint: http://127.0.0.1:8989
  valid_until: "2099-01-01T00:00:00Z"
  user_email: jane@example.com
  user_name: Jane
  user_mrn: //captain.api.mondoo.app/users/u1
  scope_name: prod
  scope_kind: space
  org_name: acme
`

// A registration token login over an interactive login session replaces the
// session completely.
func TestApplyRegistrationConfig_ReplacesSession(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	path := filepath.Join(t.TempDir(), "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte(sessionConfigYAML), 0o644))
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())

	const newSpace = "//captain.api.mondoo.app/spaces/new-space"
	applyRegistrationConfig("//agents.api.mondoo.app/spaces/new-space/agents/a1", &upstream.ServiceAccountCredentials{
		Mrn:         "//agents.api.mondoo.app/spaces/new-space/serviceaccounts/sa1",
		ParentMrn:   newSpace, //nolint:staticcheck // a registration answers with parent_mrn
		PrivateKey:  "new-key",
		Certificate: "new-cert",
		ApiEndpoint: "https://us.api.mondoo.com",
	})
	require.NoError(t, config.StoreConfig())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, yaml.Unmarshal(data, &stored))
	assert.NotContains(t, stored, "auth", "the session's auth block is removed:\n%s", data)
	assert.NotContains(t, stored, "scope_mrn", "a stale scope_mrn would win over the new space:\n%s", data)
	assert.NotContains(t, stored, "token", "the login's token would be sent instead of the client's key:\n%s", data)
	assert.Equal(t, newSpace, stored["space_mrn"])
	assert.Equal(t, "//agents.api.mondoo.app/spaces/new-space/agents/a1", stored["agent_mrn"])
	assert.Equal(t, "new-key", stored["private_key"])

	// The config as the CLI reads it.
	viper.Reset()
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	opts, err := config.Read()
	require.NoError(t, err)
	assert.Equal(t, newSpace, opts.GetScopeMrn())
	assert.False(t, opts.IsOAuthSession())

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
}

const registeredClientConfigYAML = `agent_mrn: //agents.api.mondoo.app/spaces/old-space/agents/a1
api_endpoint: https://us.api.mondoo.com
mrn: //agents.api.mondoo.app/spaces/old-space/serviceaccounts/sa1
space_mrn: //captain.api.mondoo.app/spaces/old-space
parent_mrn: //captain.api.mondoo.app/spaces/old-space
token: old-registration-token
private_key: old-key
certificate: old-cert
`

// An interactive login over a registered client's config replaces the
// registered client completely.
func TestApplySessionConfig_ReplacesRegisteredClient(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	path := filepath.Join(t.TempDir(), "mondoo.yml")
	require.NoError(t, os.WriteFile(path, []byte(registeredClientConfigYAML), 0o644))
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())

	const newSpace = "//captain.api.mondoo.app/spaces/new-space"
	const user = "//captain.api.mondoo.app/users/u1"
	cred := applySessionConfig(&oauthlogin.Result{
		Credential: oauthlogin.Credential{
			Mrn:         user,
			SpaceMrn:    newSpace,
			ScopeMrn:    newSpace,
			Token:       "new-login-token",
			ApiEndpoint: "https://us.api.mondoo.com",
		},
		Endpoint: "https://us.api.mondoo.com",
		Issuer:   "https://us.api.mondoo.com",
	})
	// what the login command pings the server with: the token, and no key
	assert.Equal(t, "new-login-token", cred.Token)
	assert.Empty(t, cred.PrivateKey)
	assert.Equal(t, user, cred.Mrn)
	require.NoError(t, config.StoreConfig())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, yaml.Unmarshal(data, &stored))
	for _, key := range []string{"agent_mrn", "parent_mrn", "space_mrn", "private_key", "certificate"} {
		assert.NotContains(t, stored, key, "the registered client's %s is removed:\n%s", key, data)
	}
	assert.Equal(t, newSpace, stored["scope_mrn"])
	assert.Equal(t, "new-login-token", stored["token"], "the old token is replaced")
	assert.Equal(t, user, stored["mrn"])

	viper.Reset()
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	opts, err := config.Read()
	require.NoError(t, err)
	assert.True(t, opts.IsOAuthSession())
	assert.Equal(t, newSpace, opts.GetScopeMrn())

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
}
