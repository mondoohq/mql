// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"database/sql"
)

// ServerAccess describes what the scanning login can see in the server-level
// catalog views. SQL Server filters sys.server_principals,
// sys.server_permissions, sys.credentials, sys.server_audits and the other
// security catalog views to the rows the caller holds a permission on, without
// raising an error, so a least-privileged scanner reads a partial answer that
// looks complete.
type ServerAccess struct {
	// ViewAnyDefinition is VIEW ANY DEFINITION, which shows every row of the
	// server catalog views (CONTROL SERVER implies it).
	ViewAnyDefinition bool
	// ViewAnySecurityDefinition is VIEW ANY SECURITY DEFINITION (SQL Server
	// 2022 and later), which shows the security catalog views.
	ViewAnySecurityDefinition bool
	// ViewAnyDatabase is VIEW ANY DATABASE, which lists every database in
	// sys.databases. public holds it unless it has been revoked.
	ViewAnyDatabase bool
}

// SecurityCatalogVisible reports whether the server-level security catalog
// views list every row.
func (a *ServerAccess) SecurityCatalogVisible() bool {
	return a.ViewAnyDefinition || a.ViewAnySecurityDefinition
}

// DatabaseAccess describes what the scanning login can see in one database's
// catalog views.
type DatabaseAccess struct {
	// ViewDefinition is VIEW DEFINITION on the database, held directly, through
	// a database role such as db_owner, or implied by VIEW ANY DEFINITION.
	ViewDefinition bool
	// ViewSecurityDefinition is VIEW SECURITY DEFINITION on the database (SQL
	// Server 2022 and later).
	ViewSecurityDefinition bool
}

// SecurityCatalogVisible reports whether the database's security catalog
// views (principals, permissions, keys, credentials, audit specifications)
// list every row.
func (a DatabaseAccess) SecurityCatalogVisible() bool {
	return a.ViewDefinition || a.ViewSecurityDefinition
}

// hasPerm reads a HAS_PERMS_BY_NAME result. The function returns NULL for a
// permission name the server does not know (VIEW ANY SECURITY DEFINITION
// before SQL Server 2022), which counts as not held.
func hasPerm(v sql.NullInt64) bool {
	return v.Valid && v.Int64 == 1
}

// ServerAccess reads what the scanning login may see. It runs once per
// connection.
func (c *MssqlConnection) ServerAccess() (*ServerAccess, error) {
	c.accessOnce.Do(func() {
		c.access, c.accessErr = c.readServerAccess()
	})
	return c.access, c.accessErr
}

func (c *MssqlConnection) readServerAccess() (*ServerAccess, error) {
	db, err := c.Client()
	if err != nil {
		return nil, err
	}
	var def, secDef, anyDB sql.NullInt64
	err = db.QueryRowContext(context.Background(), `SELECT
		HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION'),
		HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY SECURITY DEFINITION'),
		HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DATABASE')`).Scan(&def, &secDef, &anyDB)
	if err != nil {
		return nil, err
	}
	return &ServerAccess{
		ViewAnyDefinition:         hasPerm(def),
		ViewAnySecurityDefinition: hasPerm(secDef),
		ViewAnyDatabase:           hasPerm(anyDB),
	}, nil
}

// DatabaseAccess reads what the scanning login may see in a database. The
// result is cached per database.
func (c *MssqlConnection) DatabaseAccess(database string) (DatabaseAccess, error) {
	c.dbAccessMu.Lock()
	defer c.dbAccessMu.Unlock()
	if a, ok := c.dbAccess[database]; ok {
		return a, nil
	}
	db, err := c.Client()
	if err != nil {
		return DatabaseAccess{}, err
	}
	var def, secDef sql.NullInt64
	err = db.QueryRowContext(context.Background(), `SELECT
		HAS_PERMS_BY_NAME(@p1, 'DATABASE', 'VIEW DEFINITION'),
		HAS_PERMS_BY_NAME(@p1, 'DATABASE', 'VIEW SECURITY DEFINITION')`,
		sql.Named("p1", database)).Scan(&def, &secDef)
	if err != nil {
		return DatabaseAccess{}, err
	}
	a := DatabaseAccess{ViewDefinition: hasPerm(def), ViewSecurityDefinition: hasPerm(secDef)}
	if c.dbAccess == nil {
		c.dbAccess = map[string]DatabaseAccess{}
	}
	c.dbAccess[database] = a
	return a, nil
}
