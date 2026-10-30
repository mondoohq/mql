// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cassandraconf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/cassandraconf"
	"go.mondoo.com/mql/providers/os/resources/yamlconf"
)

func TestParseConfEmpty(t *testing.T) {
	for _, content := range []string{"", "   \n\n", "# just a comment\n"} {
		c, err := cassandraconf.ParseConf(content)
		require.NoError(t, err)
		assert.Empty(t, c.Params)

		// A server running entirely on defaults still reports them, and the
		// defaults that matter here are the permissive ones.
		assert.Equal(t, "AllowAllAuthenticator", cassandraconf.Authenticator(c.Params))
		assert.False(t, cassandraconf.AuthenticationEnabled(c.Params))
		assert.False(t, cassandraconf.AuthorizationEnabled(c.Params))
		assert.Equal(t, "none", cassandraconf.InternodeEncryption(c.Params))
	}
}

func TestParseConfRejectsNonMapping(t *testing.T) {
	for _, content := range []string{"just a scalar", "- a\n- b\n"} {
		_, err := cassandraconf.ParseConf(content)
		assert.Error(t, err, "content %q should not parse as a config", content)
	}
}

func TestParseConfInvalidYAML(t *testing.T) {
	_, err := cassandraconf.ParseConf("authenticator: PasswordAuthenticator\n  authorizer: bad indent\n")
	assert.Error(t, err)
}

// The 5.0 mapping form has to read the same as the historical scalar form,
// otherwise a cluster that uses it reports as running the permissive default.
func TestClassNameAcceptsScalarAndMappingForms(t *testing.T) {
	scalar, err := cassandraconf.ParseConf("authenticator: PasswordAuthenticator\n")
	require.NoError(t, err)

	mapping, err := cassandraconf.ParseConf(`
authenticator:
  class_name: PasswordAuthenticator
  parameters:
    - validity: 2000ms
`)
	require.NoError(t, err)

	for name, params := range map[string]map[string]any{
		"scalar":  scalar.Params,
		"mapping": mapping.Params,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "PasswordAuthenticator", cassandraconf.Authenticator(params))
			assert.True(t, cassandraconf.AuthenticationEnabled(params))
		})
	}
}

// The shipped file writes the short class name, but a fully qualified one is
// equally valid and must not read as "something other than AllowAll".
func TestAuthEnabledMatchesFullyQualifiedClassNames(t *testing.T) {
	c, err := cassandraconf.ParseConf(`
authenticator: org.apache.cassandra.auth.AllowAllAuthenticator
authorizer: org.apache.cassandra.auth.AllowAllAuthorizer
network_authorizer: org.apache.cassandra.auth.AllowAllNetworkAuthorizer
`)
	require.NoError(t, err)

	assert.False(t, cassandraconf.AuthenticationEnabled(c.Params))
	assert.False(t, cassandraconf.AuthorizationEnabled(c.Params))
	assert.False(t, cassandraconf.NetworkAuthorizationEnabled(c.Params))

	// ...and the reverse: a real authenticator reads as enabled either way.
	hardened, err := cassandraconf.ParseConf(`
authenticator: org.apache.cassandra.auth.PasswordAuthenticator
authorizer: CassandraAuthorizer
`)
	require.NoError(t, err)
	assert.True(t, cassandraconf.AuthenticationEnabled(hardened.Params))
	assert.True(t, cassandraconf.AuthorizationEnabled(hardened.Params))
}

func TestSeedsFromNestedProviderBlock(t *testing.T) {
	c, err := cassandraconf.ParseConf(`
seed_provider:
  - class_name: org.apache.cassandra.locator.SimpleSeedProvider
    parameters:
      - seeds: "10.0.0.1:7000,10.0.0.2:7000"
`)
	require.NoError(t, err)

	assert.Equal(t, "org.apache.cassandra.locator.SimpleSeedProvider", cassandraconf.SeedProviderClass(c.Params))
	assert.Equal(t, []string{"10.0.0.1:7000", "10.0.0.2:7000"}, cassandraconf.Seeds(c.Params))
}

func TestSeedsAbsent(t *testing.T) {
	c, err := cassandraconf.ParseConf("cluster_name: Test Cluster\n")
	require.NoError(t, err)
	assert.Nil(t, cassandraconf.Seeds(c.Params))
	assert.Empty(t, cassandraconf.SeedProviderClass(c.Params))
}

// `optional` defaults to the opposite of `enabled`, so a flat false default
// would describe a transitional deployment as refusing plaintext when it
// accepts it.
func TestClientEncryptionOptionalConditionalDefault(t *testing.T) {
	disabled, err := cassandraconf.ParseConf("client_encryption_options:\n  enabled: false\n")
	require.NoError(t, err)
	assert.True(t, cassandraconf.ClientEncryptionOptional(disabled.Params))

	enabled, err := cassandraconf.ParseConf("client_encryption_options:\n  enabled: true\n")
	require.NoError(t, err)
	assert.False(t, cassandraconf.ClientEncryptionOptional(enabled.Params))

	// An explicit value always wins over the conditional default.
	transitional, err := cassandraconf.ParseConf("client_encryption_options:\n  enabled: true\n  optional: true\n")
	require.NoError(t, err)
	assert.True(t, cassandraconf.ClientEncryptionOptional(transitional.Params))
}

func TestServerEncryptionOptionalConditionalDefault(t *testing.T) {
	none, err := cassandraconf.ParseConf("server_encryption_options:\n  internode_encryption: none\n")
	require.NoError(t, err)
	assert.True(t, cassandraconf.ServerEncryptionOptional(none.Params))

	all, err := cassandraconf.ParseConf("server_encryption_options:\n  internode_encryption: all\n")
	require.NoError(t, err)
	assert.False(t, cassandraconf.ServerEncryptionOptional(all.Params))
}

func TestAuditAndTDEPluginClasses(t *testing.T) {
	c, err := cassandraconf.ParseConf(`
audit_logging_options:
  enabled: true
  logger:
    - class_name: BinAuditLogger
  excluded_keyspaces: system, system_schema
transparent_data_encryption_options:
  enabled: true
  cipher: AES/CBC/PKCS5Padding
  key_alias: testing:1
  key_provider:
    - class_name: org.apache.cassandra.security.JKSKeyProvider
      parameters:
        - keystore: conf/.keystore
`)
	require.NoError(t, err)

	assert.Equal(t, "BinAuditLogger", cassandraconf.AuditLoggerClass(c.Params))
	assert.Equal(t, "org.apache.cassandra.security.JKSKeyProvider", cassandraconf.TDEKeyProviderClass(c.Params))
	assert.True(t, yamlconf.Bool(c.Params, false, "audit_logging_options", "enabled"))
	assert.Equal(t, []string{"system", "system_schema"},
		yamlconf.List(c.Params, "audit_logging_options", "excluded_keyspaces"))
}

func TestParseProperties(t *testing.T) {
	props := cassandraconf.ParseProperties(`
# Cassandra rack and datacenter
dc=dc1
rack = rack1
! another comment style
prefer_local:true
dc_suffix=
`)

	assert.Equal(t, map[string]string{
		"dc":           "dc1",
		"rack":         "rack1",
		"prefer_local": "true",
		"dc_suffix":    "",
	}, props)
}

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		output   string
		expected string
	}{
		{"5.0.2\n", "5.0.2"},
		{"4.1.7\n", "4.1.7"},
		{"5.0\n", "5.0"},
		{"5.1-SNAPSHOT\n", "5.1"},
		{"Picked up JAVA_TOOL_OPTIONS: -Dfoo=bar\n5.0.2\n", "5.0.2"},
		{"", ""},
		{"command not found\n", ""},
	} {
		assert.Equal(t, tc.expected, cassandraconf.ParseVersion(tc.output), "output %q", tc.output)
	}
}
