// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// confNotFound builds the state file() leaves behind when no postgresql.conf
// exists anywhere on the host: File marked set+null.
func confNotFound() *mqlPostgresqlConf {
	s := &mqlPostgresqlConf{}
	s.File = plugin.TValue[*mqlFile]{State: plugin.StateIsSet | plugin.StateIsNull}
	return s
}

// confPresent builds the state for a config file that exists but omits every
// directive. PostgreSQL's documented defaults DO apply here, so the accessors
// must keep returning them.
func confPresent() *mqlPostgresqlConf {
	s := &mqlPostgresqlConf{}
	s.File = plugin.TValue[*mqlFile]{Data: &mqlFile{}, State: plugin.StateIsSet}
	return s
}

// With no config file at all there is nothing to default from. Reporting
// port 5432 / listenAddresses ["localhost"] / sslEnabled false describes a
// posture nobody configured, and lets a "does not listen on *" assertion pass
// against a host where PostgreSQL was never set up.
func TestPostgresqlConfNoFileReturnsNull(t *testing.T) {
	empty := map[string]any{}

	t.Run("port", func(t *testing.T) {
		s := confNotFound()
		v, err := s.port(empty)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), v)
		assert.True(t, s.Port.State&plugin.StateIsNull != 0, "port must be null, not 5432")
	})

	t.Run("listenAddresses", func(t *testing.T) {
		s := confNotFound()
		v, err := s.listenAddresses(empty)
		assert.NoError(t, err)
		assert.Nil(t, v)
		assert.True(t, s.ListenAddresses.State&plugin.StateIsNull != 0,
			"listenAddresses must be null, not [localhost]")
	})

	t.Run("sslEnabled", func(t *testing.T) {
		s := confNotFound()
		v, err := s.sslEnabled(empty)
		assert.NoError(t, err)
		assert.False(t, v)
		assert.True(t, s.SslEnabled.State&plugin.StateIsNull != 0,
			"sslEnabled must be null; false reads as a real finding")
	})

	t.Run("loggingCollector", func(t *testing.T) {
		s := confNotFound()
		_, err := s.loggingCollector(empty)
		assert.NoError(t, err)
		assert.True(t, s.LoggingCollector.State&plugin.StateIsNull != 0)
	})

	t.Run("logConnections", func(t *testing.T) {
		s := confNotFound()
		_, err := s.logConnections(empty)
		assert.NoError(t, err)
		assert.True(t, s.LogConnections.State&plugin.StateIsNull != 0)
	})

	t.Run("dataDirectory", func(t *testing.T) {
		s := confNotFound()
		v, err := s.dataDirectory(empty)
		assert.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, s.DataDirectory.State&plugin.StateIsNull != 0)
	})

	t.Run("sharedPreloadLibraries", func(t *testing.T) {
		s := confNotFound()
		v, err := s.sharedPreloadLibraries(empty)
		assert.NoError(t, err)
		assert.Nil(t, v)
		assert.True(t, s.SharedPreloadLibraries.State&plugin.StateIsNull != 0)
	})
}

// The documented defaults are still correct when the file exists and simply
// does not mention the directive. This is the behaviour the guard must not
// break.
func TestPostgresqlConfPresentButEmptyKeepsDefaults(t *testing.T) {
	empty := map[string]any{}

	s := confPresent()
	port, err := s.port(empty)
	assert.NoError(t, err)
	assert.Equal(t, int64(5432), port, "a present file with no port directive still defaults")
	assert.True(t, s.Port.State&plugin.StateIsNull == 0, "and is not null")

	s = confPresent()
	addrs, err := s.listenAddresses(empty)
	assert.NoError(t, err)
	assert.Equal(t, []any{"localhost"}, addrs)

	s = confPresent()
	ssl, err := s.sslEnabled(empty)
	assert.NoError(t, err)
	assert.False(t, ssl, "ssl is genuinely off when the file omits it")
	assert.True(t, s.SslEnabled.State&plugin.StateIsNull == 0)
}

// A directive that IS present must win regardless.
func TestPostgresqlConfPresentWithValues(t *testing.T) {
	s := confPresent()
	port, err := s.port(map[string]any{"port": "6543"})
	assert.NoError(t, err)
	assert.Equal(t, int64(6543), port)

	s = confPresent()
	ssl, err := s.sslEnabled(map[string]any{"ssl": "on"})
	assert.NoError(t, err)
	assert.True(t, ssl)
}
