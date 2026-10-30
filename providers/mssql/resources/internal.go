// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// The code generator embeds these mql<Resource>Internal structs into the
// generated resource structs, giving cross-reference accessors the parent
// context (database name, mapped login) they need without an extra lookup.

// mqlMssqlLoginInternal caches the login's binary SID so databaseUsers can
// match this login across databases.
type mqlMssqlLoginInternal struct {
	cacheSid []byte
}

// mqlMssqlDatabaseUserInternal caches the containing database and the mapped
// server login so the user's permissions and login reference resolve.
type mqlMssqlDatabaseUserInternal struct {
	cacheDatabase  string
	cacheLoginName string
}

// mqlMssqlDatabaseRoleInternal caches the containing database so role
// membership and permissions resolve.
type mqlMssqlDatabaseRoleInternal struct {
	cacheDatabase string
}

// mqlMssqlApplicationRoleInternal caches the containing database so the role's
// permissions resolve.
type mqlMssqlApplicationRoleInternal struct {
	cacheDatabase string
}
