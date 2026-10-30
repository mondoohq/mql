// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogsinkArgs_Rsyslog(t *testing.T) {
	args, err := logsinkArgs("db-1", &godo.DatabaseLogsink{
		ID:   "sink-1",
		Name: "central-syslog",
		Type: "rsyslog",
		Config: &godo.DatabaseLogsinkConfig{
			Server: "logs.example.com",
			Port:   6514,
			TLS:    true,
			Format: "rfc5424",
			CA:     "-----BEGIN CERTIFICATE-----",
			Key:    "-----BEGIN PRIVATE KEY-----",
			Cert:   "-----BEGIN CERTIFICATE-----",
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "digitalocean.database.logsink/db-1/sink-1", args["__id"].Value)
	assert.Equal(t, "db-1", args["databaseId"].Value)
	assert.Equal(t, "sink-1", args["sinkId"].Value)
	assert.Equal(t, "central-syslog", args["name"].Value)
	assert.Equal(t, "rsyslog", args["type"].Value)
	assert.Equal(t, "logs.example.com", args["server"].Value)
	assert.Equal(t, int64(6514), args["port"].Value)
	assert.Equal(t, true, args["tlsEnabled"].Value)
	assert.Equal(t, "rfc5424", args["format"].Value)
	// A syslog sink carries no search-cluster settings.
	assert.Equal(t, "", args["url"].Value)
	assert.Equal(t, "", args["indexPrefix"].Value)
	assert.Nil(t, args["indexRetentionDays"].Value)

	// The CA, client key, and client certificate configured on a sink are
	// credentials. They must never reach a field, under any name.
	for _, forbidden := range []string{"ca", "key", "cert", "certificate", "privateKey"} {
		_, present := args[forbidden]
		assert.False(t, present, "logsink args must not carry %q", forbidden)
	}
}

func TestLogsinkArgs_Elasticsearch(t *testing.T) {
	args, err := logsinkArgs("db-1", &godo.DatabaseLogsink{
		ID:   "sink-2",
		Name: "es",
		Type: "elasticsearch",
		Config: &godo.DatabaseLogsinkConfig{
			URL:          "https://es.example.com:9200",
			IndexPrefix:  "do-logs",
			IndexDaysMax: 14,
			TLS:          true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "https://es.example.com:9200", args["url"].Value)
	assert.Equal(t, "do-logs", args["indexPrefix"].Value)
	assert.Equal(t, int64(14), args["indexRetentionDays"].Value)
	assert.Equal(t, true, args["tlsEnabled"].Value)
	// A search-cluster sink carries no syslog transport.
	assert.Equal(t, "", args["server"].Value)
	assert.Nil(t, args["port"].Value)
}

func TestLogsinkArgs_NilConfig(t *testing.T) {
	// godo omits the config block entirely on some sink types. Nothing may
	// be invented from its absence: an unset port must read as null rather
	// than as port 0, which is a real value the audit would take at face
	// value.
	args, err := logsinkArgs("db-1", &godo.DatabaseLogsink{
		ID:   "sink-3",
		Name: "dd",
		Type: "datadog",
	})
	require.NoError(t, err)

	assert.Nil(t, args["port"].Value)
	assert.Nil(t, args["indexRetentionDays"].Value)
	assert.Equal(t, "", args["server"].Value)
	assert.Equal(t, "", args["url"].Value)
	// TLS is a claim about encryption. With no config to read, the safe
	// reading is that delivery is not known to be encrypted.
	assert.Equal(t, false, args["tlsEnabled"].Value)
}

func TestLogsinkArgs_MissingIDsRejected(t *testing.T) {
	// Both halves of the cache key must be present, or sinks alias onto one
	// another and a cluster appears to ship its logs to a single place.
	_, err := logsinkArgs("db-1", &godo.DatabaseLogsink{Name: "no-id"})
	require.Error(t, err)

	_, err = logsinkArgs("", &godo.DatabaseLogsink{ID: "sink-4"})
	require.Error(t, err)
}
