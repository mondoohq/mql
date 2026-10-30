// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// These mql<Resource>Internal structs are embedded into the generated resource
// structs. They carry the parent context (owning role, containing database)
// that typed references and per-database queries need.

type mqlPostgresdbDatabaseInternal struct {
	cacheOwner string
}

type mqlPostgresdbSchemaInternal struct {
	cacheDatabase string
	cacheOwner    string
}

type mqlPostgresdbFunctionInternal struct {
	cacheDatabase string
	cacheOwner    string
}

type mqlPostgresdbTableInternal struct {
	cacheDatabase string
	cacheOwner    string
}

type mqlPostgresdbTablespaceInternal struct {
	cacheOwner string
}

type mqlPostgresdbExtensionInternal struct {
	cacheOwner string
}

type mqlPostgresdbForeignServerInternal struct {
	cacheOwner    string
	cacheDatabase string
}

type mqlPostgresdbPublicationInternal struct {
	cacheOwner string
}

type mqlPostgresdbSubscriptionInternal struct {
	cacheOwner string
}
