// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
)

func TestDatabaseUserAuthPlugin(t *testing.T) {
	t.Run("reads the MySQL auth plugin", func(t *testing.T) {
		u := &godo.DatabaseUser{MySQLSettings: &godo.DatabaseMySQLUserSettings{AuthPlugin: "caching_sha2_password"}}
		assert.Equal(t, "caching_sha2_password", databaseUserAuthPlugin(u))
	})

	t.Run("is empty on engines without MySQL settings", func(t *testing.T) {
		assert.Empty(t, databaseUserAuthPlugin(&godo.DatabaseUser{}))
	})
}

func TestDatabaseUserKafkaAcls(t *testing.T) {
	t.Run("maps every grant", func(t *testing.T) {
		u := &godo.DatabaseUser{Settings: &godo.DatabaseUserSettings{
			ACL: []*godo.KafkaACL{
				{ID: "acl-1", Topic: "events", Permission: "produce"},
				{ID: "acl-2", Topic: "events", Permission: "consume"},
			},
		}}

		// Two grants on the same topic must both survive — this is why the
		// field is a list rather than a topic-keyed map.
		assert.Equal(t, []any{
			map[string]any{"id": "acl-1", "topic": "events", "permission": "produce"},
			map[string]any{"id": "acl-2", "topic": "events", "permission": "consume"},
		}, databaseUserKafkaAcls(u))
	})

	t.Run("skips nil grants", func(t *testing.T) {
		u := &godo.DatabaseUser{Settings: &godo.DatabaseUserSettings{
			ACL: []*godo.KafkaACL{nil, {ID: "acl-1", Topic: "events", Permission: "produce"}},
		}}
		assert.Len(t, databaseUserKafkaAcls(u), 1)
	})

	t.Run("is empty on engines without settings", func(t *testing.T) {
		assert.Empty(t, databaseUserKafkaAcls(&godo.DatabaseUser{}))
	})
}

func TestDatabaseUserOpenSearchAcls(t *testing.T) {
	t.Run("maps every grant", func(t *testing.T) {
		u := &godo.DatabaseUser{Settings: &godo.DatabaseUserSettings{
			OpenSearchACL: []*godo.OpenSearchACL{{Index: "logs-*", Permission: "read"}},
		}}
		assert.Equal(t, []any{
			map[string]any{"index": "logs-*", "permission": "read"},
		}, databaseUserOpenSearchAcls(u))
	})

	t.Run("skips nil grants", func(t *testing.T) {
		u := &godo.DatabaseUser{Settings: &godo.DatabaseUserSettings{
			OpenSearchACL: []*godo.OpenSearchACL{nil},
		}}
		assert.Empty(t, databaseUserOpenSearchAcls(u))
	})

	t.Run("is empty on engines without settings", func(t *testing.T) {
		assert.Empty(t, databaseUserOpenSearchAcls(&godo.DatabaseUser{}))
	})
}

func TestDatabaseUserMongo(t *testing.T) {
	t.Run("reads the databases and role", func(t *testing.T) {
		u := &godo.DatabaseUser{Settings: &godo.DatabaseUserSettings{
			MongoUserSettings: &godo.MongoUserSettings{
				Databases: []string{"admin", "reporting"},
				Role:      "readAnyDatabase",
			},
		}}
		assert.Equal(t, []any{"admin", "reporting"}, databaseUserMongoDatabases(u))
		assert.Equal(t, "readAnyDatabase", databaseUserMongoRole(u))
	})

	t.Run("is empty when settings are present but not MongoDB", func(t *testing.T) {
		u := &godo.DatabaseUser{Settings: &godo.DatabaseUserSettings{}}
		assert.Empty(t, databaseUserMongoDatabases(u))
		assert.Empty(t, databaseUserMongoRole(u))
	})

	t.Run("is empty on engines without settings", func(t *testing.T) {
		assert.Empty(t, databaseUserMongoDatabases(&godo.DatabaseUser{}))
		assert.Empty(t, databaseUserMongoRole(&godo.DatabaseUser{}))
	})
}

func TestProjectResourceType(t *testing.T) {
	cases := []struct {
		urn  string
		want string
	}{
		{"do:droplet:4126873", "droplet"},
		{"do:kubernetes:bd5f5959-5e1e-4205-a714-a914373942af", "kubernetes"},
		{"do:dbaas:abc-123", "dbaas"},
		{"do:space:my-bucket", "space"},
		{"do:loadbalancer:abc", "loadbalancer"},
		{"not-a-urn", ""},
		{"do:droplet", ""},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, projectResourceType(c.urn), "projectResourceType(%q)", c.urn)
	}
}
