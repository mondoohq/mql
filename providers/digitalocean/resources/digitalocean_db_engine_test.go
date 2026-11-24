// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: the pg_parameters list shape from godo's AdvancedPostgresConfig; no live account was checked.
func TestAdvancedPgEngineConfig(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"pg_parameters":[
			{"name":"log_min_duration_statement","value":"1000","description":"x","requires_restart":false,"default_value":"-1"},
			{"name":"ssl_min_protocol_version","value":"TLSv1.2"},
			{"name":"","value":"orphan"},
			{"name":"replication_password","value":"hunter2"}
		]}}`},
	})
	r := dbWithEngine(rt, "advanced_pg")

	out, err := r.engineConfig()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"log_min_duration_statement": "1000",
		"ssl_min_protocol_version":   "TLSv1.2",
	}, out, "parameters are keyed by name with their string value; nameless and secret-shaped entries are dropped")

	// A PostgreSQL cluster carries no MySQL settings.
	_, err = r.slowQueryLogEnabled()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.SlowQueryLogEnabled.State)
}

// Synthetic: the mysql_parameters list shape from godo's AdvancedMySQLConfig, with MySQL's ON/OFF spelling; no live account was checked.
func TestAdvancedMysqlTypedSettings(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"mysql_parameters":[
			{"name":"slow_query_log","value":"ON"},
			{"name":"sql_require_primary_key","value":"OFF"}
		]}}`},
	})
	r := dbWithEngine(rt, "advanced_mysql")

	slow, err := r.slowQueryLogEnabled()
	require.NoError(t, err)
	assert.True(t, slow)

	pk, err := r.requirePrimaryKey()
	require.NoError(t, err)
	assert.False(t, pk)
	assert.Equal(t, plugin.State(0), r.RequirePrimaryKey.State, "a read OFF must not be null")

	cfg, err := r.engineConfig()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"slow_query_log": "ON", "sql_require_primary_key": "OFF"}, cfg)
}

// Synthetic: a parameter that is not reported, or holds a value that is not a boolean, stays null; no live account was checked.
func TestAdvancedMysqlUnreadableSettingIsNull(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"mysql_parameters":[{"name":"slow_query_log","value":"FILE"}]}}`},
	})
	r := dbWithEngine(rt, "advanced_mysql")

	_, err := r.slowQueryLogEnabled()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.SlowQueryLogEnabled.State)

	_, err = r.requirePrimaryKey()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.RequirePrimaryKey.State)
}

// Synthetic: a 200 without a config key decodes to nil alongside a nil error; no live account was checked.
func TestAdvancedEngineConfigMissingIsNull(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{}`},
	})
	r := dbWithEngine(rt, "advanced_pg")
	out, err := r.engineConfig()
	require.NoError(t, err)
	assert.Nil(t, out)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.EngineConfig.State)
}

func TestAdvancedParamBool(t *testing.T) {
	params := map[string]string{
		"on": "ON", "off": "off", "one": "1", "zero": "0", "t": "true", "f": "FALSE", "padded": " ON ",
		"other": "FILE", "empty": "",
	}
	// Synthetic: MySQL and PostgreSQL spellings of a boolean; no live account was checked.
	for name, want := range map[string]bool{"on": true, "off": false, "one": true, "zero": false, "t": true, "f": false, "padded": true} {
		got := advancedParamBool(params, name)
		require.NotNil(t, got, name)
		assert.Equal(t, want, *got, name)
	}
	// Synthetic: anything else, and an absent parameter, is not a boolean; no live account was checked.
	for _, name := range []string{"other", "empty", "absent"} {
		assert.Nil(t, advancedParamBool(params, name), name)
	}
}
