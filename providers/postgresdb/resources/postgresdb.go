// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/postgresdb/connection"
)

// isPermissionDenied reports whether an error is a PostgreSQL
// insufficient_privilege error (SQLSTATE 42501). Only these should be treated
// as "no visible rows"; every other error must propagate.
func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

func (r *mqlPostgresdb) id() (string, error) {
	return "postgresdb", nil
}

func pgConnection(runtime *plugin.Runtime) *connection.PostgresdbConnection {
	return runtime.Connection.(*connection.PostgresdbConnection)
}

// pgPool returns the connection pool for a database (empty = server database).
func pgPool(runtime *plugin.Runtime, database string) (*pgxpool.Pool, error) {
	return pgConnection(runtime).Client(database)
}

func pgContext() context.Context {
	return context.Background()
}

func pgSystemID(runtime *plugin.Runtime) (string, error) {
	return pgConnection(runtime).SystemID()
}

// --- stable identifier builders ---------------------------------------------

func roleResourceID(systemID, name string) string {
	return name + "@" + systemID
}

func databaseResourceID(systemID, database string) string {
	return systemID + "/" + database
}

func privilegeResourceID(parentID, grantee, privilegeType string) string {
	return parentID + "/priv/" + grantee + "/" + privilegeType
}

// --- password classification ------------------------------------------------

// passwordFormExpr is the server-side projection behind the passwordType field.
//
// pg_authid.rolpassword holds the role's stored credential. passwordType only
// reports which form that credential is stored in, so the discriminator is
// derived by the server and nothing but a fixed token crosses the connection.
//
// A fixed-width prefix would not be enough. Per the PostgreSQL documentation
// the SCRAM form is "SCRAM-SHA-256$<iteration count>:<salt>$<StoredKey>:
// <ServerKey>", whose discriminator is exactly 14 characters, but the md5 form
// is "md5" followed by a 32-character hex digest. Any prefix wide enough to
// name SCRAM therefore also carries 11 hex digits of an md5 role's digest, and
// a legacy plaintext value (possible on a catalog upgraded in place from
// before PostgreSQL 10) would be transferred outright. Emitting the token
// itself is the only projection that leaks nothing for every form.
//
// The tokens are the prefixes classifyPassword already recognizes, so the
// values reported by passwordType are unchanged.
const passwordFormExpr = `CASE
		WHEN rolpassword IS NULL THEN NULL
		WHEN rolpassword = '' THEN ''
		WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256$'
		WHEN rolpassword LIKE 'md5%' THEN 'md5'
		ELSE 'other'
	END`

// classifyPassword maps a passwordFormExpr token to how the password is
// stored. A nil pointer (unreadable or no password) yields "none".
func classifyPassword(rolpassword *string) string {
	if rolpassword == nil || *rolpassword == "" {
		return "none"
	}
	if strings.HasPrefix(*rolpassword, "SCRAM-SHA-256$") {
		return "scram-sha-256"
	}
	if strings.HasPrefix(*rolpassword, "md5") {
		return "md5"
	}
	return "other"
}

// --- privileges (ACL) -------------------------------------------------------

func newPostgresdbPrivilege(runtime *plugin.Runtime, parentID, grantee, privilegeType string, grantable bool) (*mqlPostgresdbPrivilege, error) {
	res, err := CreateResource(runtime, "postgresdb.privilege", map[string]*llx.RawData{
		"__id":          llx.StringData(privilegeResourceID(parentID, grantee, privilegeType)),
		"grantee":       llx.StringData(grantee),
		"privilegeType": llx.StringData(privilegeType),
		"isGrantable":   llx.BoolData(grantable),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPostgresdbPrivilege), nil
}

// aclPrivileges runs an aclexplode-based query that must return
// (grantee text, privilege_type text, is_grantable bool) and builds the
// corresponding privilege resources.
func aclPrivileges(runtime *plugin.Runtime, pool *pgxpool.Pool, parentID, query string, args ...any) ([]any, error) {
	rows, err := pool.Query(pgContext(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var grantee, privilegeType string
		var grantable bool
		if err := rows.Scan(&grantee, &privilegeType, &grantable); err != nil {
			return nil, err
		}
		p, err := newPostgresdbPrivilege(runtime, parentID, grantee, privilegeType, grantable)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// --- typed role references --------------------------------------------------

// resolveRoleRef resolves a role by name for a typed owner/member reference,
// setting the field null when the name is empty.
func resolveRoleRef(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlPostgresdbRole]) (*mqlPostgresdbRole, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "postgresdb.role", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPostgresdbRole), nil
}

// intToStr is a tiny helper for building ids from oids.
func intToStr(i int64) string {
	return strconv.FormatInt(i, 10)
}
