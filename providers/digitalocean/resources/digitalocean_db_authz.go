// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/digitalocean/godo"
)

// Managed database users carry engine-specific authorization alongside the
// cluster-wide role: Kafka and OpenSearch scope a user to individual topics and
// indices, MongoDB scopes a role to named databases, and MySQL records which
// authentication plugin the user logs in with. The helpers below read each of
// those out of the engine-specific settings blocks, which are nil on every
// other engine.

// databaseUserAuthPlugin returns the MySQL authentication plugin the user
// authenticates with, or "" on other engines.
func databaseUserAuthPlugin(u *godo.DatabaseUser) string {
	if u.MySQLSettings == nil {
		return ""
	}
	return u.MySQLSettings.AuthPlugin
}

// databaseUserKafkaAcls returns the user's Kafka topic grants.
//
// This is a list rather than a topic-keyed map because a user may hold more
// than one grant on the same topic; DigitalOcean gives each grant its own id.
func databaseUserKafkaAcls(u *godo.DatabaseUser) []any {
	if u.Settings == nil {
		return []any{}
	}
	acls := make([]any, 0, len(u.Settings.ACL))
	for _, acl := range u.Settings.ACL {
		if acl == nil {
			continue
		}
		acls = append(acls, map[string]any{
			"id":         acl.ID,
			"topic":      acl.Topic,
			"permission": acl.Permission,
		})
	}
	return acls
}

// databaseUserOpenSearchAcls returns the user's OpenSearch index grants.
func databaseUserOpenSearchAcls(u *godo.DatabaseUser) []any {
	if u.Settings == nil {
		return []any{}
	}
	acls := make([]any, 0, len(u.Settings.OpenSearchACL))
	for _, acl := range u.Settings.OpenSearchACL {
		if acl == nil {
			continue
		}
		acls = append(acls, map[string]any{
			"index":      acl.Index,
			"permission": acl.Permission,
		})
	}
	return acls
}

// databaseUserMongoDatabases returns the MongoDB databases the user's role
// applies to.
func databaseUserMongoDatabases(u *godo.DatabaseUser) []any {
	if u.Settings == nil || u.Settings.MongoUserSettings == nil {
		return []any{}
	}
	dbs := make([]any, 0, len(u.Settings.MongoUserSettings.Databases))
	for _, db := range u.Settings.MongoUserSettings.Databases {
		dbs = append(dbs, db)
	}
	return dbs
}

// databaseUserMongoRole returns the role the user holds on its MongoDB
// databases, or "" on other engines.
func databaseUserMongoRole(u *godo.DatabaseUser) string {
	if u.Settings == nil || u.Settings.MongoUserSettings == nil {
		return ""
	}
	return u.Settings.MongoUserSettings.Role
}
