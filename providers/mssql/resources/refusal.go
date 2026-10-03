// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mssql/connection"
)

// SQL Server error numbers for a refused statement.
const (
	errPermissionDenied       = 229 // The %ls permission was denied on the object '%.*ls'
	errColumnPermissionDenied = 230 // The %ls permission was denied on the column '%.*ls'
	errDatabasePermission     = 262 // %ls permission denied in database '%.*ls'
	errNoPermissionForAction  = 297 // The user does not have permission to perform this action
	errServerStateDenied      = 300 // %ls permission was denied on object '%.*ls', database '%.*ls'
	errCannotAccessDatabase   = 916 // The server principal "%.*ls" is not able to access the database
)

// SQL Server error numbers for an object the server does not have, such as
// msdb on Azure SQL Database or a catalog view an older release lacks.
const (
	errInvalidObjectName        = 208   // Invalid object name '%.*ls'
	errCrossDatabaseUnsupported = 40515 // Reference to database and/or server name ... is not supported
)

// SQL Server error numbers for a database that exists but cannot be opened
// right now.
const (
	errSingleUser          = 924 // Database '%.*ls' is already open and can only have one user at a time
	errDatabaseOffline     = 942 // Database '%.*ls' cannot be opened because it is offline
	errDatabaseTransition  = 952 // Database '%.*ls' is in transition
	errDatabaseUnavailable = 4060
)

// isDatabaseUnavailable reports whether err is a database that cannot be
// opened right now (single-user, offline, in transition).
func isDatabaseUnavailable(err error) bool {
	switch sqlErrorNumber(err) {
	case errSingleUser, errDatabaseOffline, errDatabaseTransition, errDatabaseUnavailable:
		return true
	}
	return false
}

// sqlErrorNumber returns the SQL Server error number of err, or 0.
func sqlErrorNumber(err error) int32 {
	var e interface{ SQLErrorNumber() int32 }
	if errors.As(err, &e) {
		return e.SQLErrorNumber()
	}
	return 0
}

// isRefusal reports whether err is the server refusing a statement for lack
// of a permission.
func isRefusal(err error) bool {
	switch sqlErrorNumber(err) {
	case errPermissionDenied, errColumnPermissionDenied, errDatabasePermission,
		errNoPermissionForAction, errServerStateDenied, errCannotAccessDatabase:
		return true
	}
	return false
}

// isAbsentObject reports whether err is the server not having the object
// queried, which is an absence rather than a refusal.
func isAbsentObject(err error) bool {
	switch sqlErrorNumber(err) {
	case errInvalidObjectName, errCrossDatabaseUnsupported:
		return true
	}
	return false
}

// refusedList is what a list accessor returns for a failed query. A refusal
// was read as an empty list in v13, which let a check over the list pass on a
// server the scanner could not read; with StructuredErrors it is an error
// naming the permission the scanner lacks (ADR 046). An absent object is no
// rows. Any other error is returned unchanged.
func refusedList(err error, permissions ...string) ([]any, error) {
	if isAbsentObject(err) {
		return []any{}, nil
	}
	if !isRefusal(err) {
		return nil, err
	}
	if !plugin.StructuredErrors() {
		return []any{}, nil
	}
	return nil, llx.Forbidden(err, llx.WithPermissions(permissions...))
}

// permViewAnyDefinition is what the server-level catalog views need to list
// every row.
const permViewAnyDefinition = "VIEW ANY DEFINITION"

// requireServerCatalog guards a read from a server-level security catalog
// view. SQL Server lists only the rows the caller holds a permission on there,
// without an error, so a least-privileged login reads a subset that looks
// complete: every sysadmin but itself hidden, other logins' permissions
// missing. When the caller would see only part of the view the read is
// refused instead. v13 returned the partial list, so the check only runs with
// StructuredErrors.
func requireServerCatalog(runtime *plugin.Runtime, what string) error {
	if !plugin.StructuredErrors() {
		return nil
	}
	access, err := mssqlConnection(runtime).ServerAccess()
	if err != nil {
		return err
	}
	if access.SecurityCatalogVisible() {
		return nil
	}
	return llx.Forbidden(
		fmt.Errorf("the scanning login cannot see every %s: SQL Server lists only the rows it holds a permission on", what),
		llx.WithPermissions(permViewAnyDefinition))
}

// requireDatabaseList guards sys.databases, which lists only the databases a
// login owns or can reach unless it holds VIEW ANY DATABASE.
func requireDatabaseList(runtime *plugin.Runtime) error {
	if !plugin.StructuredErrors() {
		return nil
	}
	access, err := mssqlConnection(runtime).ServerAccess()
	if err != nil {
		return err
	}
	if access.ViewAnyDatabase {
		return nil
	}
	return llx.Forbidden(
		errors.New("the scanning login cannot see every database: sys.databases lists only the ones it owns"),
		llx.WithPermissions("VIEW ANY DATABASE"))
}

// requireDatabaseCatalog guards a read from a database's security catalog
// views, which SQL Server filters the same way as the server-level ones.
func requireDatabaseCatalog(runtime *plugin.Runtime, database, what string) error {
	return requireDatabaseAccess(runtime, database, what, connection.DatabaseAccess.SecurityCatalogVisible)
}

// requireDatabaseDefinitions guards a read from a database catalog view that
// only VIEW DEFINITION lists in full, such as sys.assemblies.
func requireDatabaseDefinitions(runtime *plugin.Runtime, database, what string) error {
	return requireDatabaseAccess(runtime, database, what, func(a connection.DatabaseAccess) bool { return a.ViewDefinition })
}

func requireDatabaseAccess(runtime *plugin.Runtime, database, what string, visible func(connection.DatabaseAccess) bool) error {
	if !plugin.StructuredErrors() {
		return nil
	}
	access, err := mssqlConnection(runtime).DatabaseAccess(database)
	if err != nil {
		return err
	}
	if visible(access) {
		return nil
	}
	return llx.Forbidden(
		fmt.Errorf("the scanning login cannot see every %s in database %s: SQL Server lists only the rows it holds a permission on", what, quoteName(database)),
		llx.WithPermissions("VIEW DEFINITION ON DATABASE::"+quoteName(database)))
}
