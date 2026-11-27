// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: a replica in the shape of godo's DatabaseReplica JSON, decoded through its struct tags; no live account was checked.
func TestDatabaseReplicaArgs(t *testing.T) {
	var rep godo.DatabaseReplica
	require.NoError(t, json.Unmarshal([]byte(`{
		"id":"r1","name":"read-1","region":"nyc3","status":"online","size":"db-s-1vcpu-1gb",
		"private_network_uuid":"vpc-1","storage_size_mib":30720,
		"connection":{"host":"read-1.db.ondigitalocean.com","port":25060,"ssl":true,"user":"doadmin","password":"hunter2","uri":"postgresql://doadmin:hunter2@read-1"},
		"private_connection":{"host":"private-read-1.db.ondigitalocean.com","port":25061,"ssl":false,"password":"hunter2"}
	}`), &rep))

	args := databaseReplicaArgs("db1", &rep)
	assert.Equal(t, "read-1.db.ondigitalocean.com", args["host"].Value)
	assert.Equal(t, int64(25060), args["port"].Value)
	assert.Equal(t, true, args["sslEnabled"].Value)
	assert.Equal(t, "private-read-1.db.ondigitalocean.com", args["privateHost"].Value)
	assert.Equal(t, int64(25061), args["privatePort"].Value)
	assert.Equal(t, false, args["privateSslEnabled"].Value)
	assert.Equal(t, int64(30720), args["storageSizeMib"].Value)

	for k, v := range args {
		assert.NotContains(t, fmt.Sprint(v.Value), "hunter2", k)
	}
}

// Synthetic: a replica without a private endpoint or a reported storage size; no live account was checked.
func TestDatabaseReplicaArgsAbsentIsNull(t *testing.T) {
	args := databaseReplicaArgs("db1", &godo.DatabaseReplica{
		Name:       "read-1",
		Connection: &godo.DatabaseConnection{Host: "h", Port: 25060, SSL: true},
	})
	for _, k := range []string{"privateHost", "privatePort", "privateSslEnabled", "storageSizeMib"} {
		assert.Nil(t, args[k].Value, k)
	}
	assert.Equal(t, "h", args["host"].Value)
}
