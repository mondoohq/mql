// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

const roleColumns = `r.rolname, r.oid::bigint, r.rolsuper, r.rolcanlogin, r.rolcreaterole,
	r.rolcreatedb, r.rolreplication, r.rolbypassrls, r.rolinherit, r.rolconnlimit,
	r.rolvaliduntil, r.rolconfig`

// roleColumnsFor is roleColumns for the runtime's server. rolbypassrls arrived
// in 9.5; before that no role can bypass row-level security, which does not
// exist yet.
func roleColumnsFor(runtime *plugin.Runtime) string {
	return strings.Replace(roleColumns, "r.rolbypassrls",
		pgColumn(runtime, pgVersion95, "r.rolbypassrls", "false"), 1)
}

// passwordTypesByOid reads pg_authid (superuser-only) and maps each role oid
// to how its password is stored. The credential itself stays in the server:
// only the passwordFormExpr discriminator is selected. A failed read returns
// the error, which passwordTypeField turns into the field's value.
func passwordTypesByOid(pool *pgxpool.Pool) (map[int64]string, error) {
	out := map[int64]string{}
	rows, err := pool.Query(pgContext(), "SELECT oid::bigint, "+passwordFormExpr+" FROM pg_authid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var oid int64
		var passwordForm *string
		if err := rows.Scan(&oid, &passwordForm); err != nil {
			return nil, err
		}
		out[oid] = classifyPassword(passwordForm)
	}
	// pgx reports a permission error from the first row fetch, so it
	// surfaces here rather than from Query.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// passwordTypeField builds the passwordType value for one role from the
// result of passwordTypesByOid.
//
// A refusal to read pg_authid (any role that is not a superuser) is an error
// (ADR 046). Through v14 it stays the v13 null unless StructuredErrors is
// on. Any other failure is returned as is.
func passwordTypeField(passwordTypes map[int64]string, readErr error, oid int64) *llx.RawData {
	if readErr != nil {
		if isPermissionDenied(readErr) {
			if !plugin.StructuredErrors() {
				return llx.NilData
			}
			return &llx.RawData{Type: types.String, Error: llx.Forbidden(readErr,
				llx.WithPermissions("SELECT on pg_catalog.pg_authid (superuser)"))}
		}
		return &llx.RawData{Type: types.String, Error: readErr}
	}
	if pt, ok := passwordTypes[oid]; ok {
		return llx.StringData(pt)
	}
	// a role created between the two catalog reads
	return llx.NilData
}

// validUntilTime maps pg_roles.rolvaliduntil to the validUntil field. NULL
// and 'infinity' both mean the password never expires and read as null;
// '-infinity' means it has always been expired and reads as the earliest
// representable time.
func validUntilTime(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	switch ts.InfinityModifier {
	case pgtype.Infinity:
		return nil
	case pgtype.NegativeInfinity:
		t := llx.NeverPastTime
		return &t
	}
	t := ts.Time
	return &t
}

// newPostgresdbRole builds a role from a row selected with roleColumns.
func newPostgresdbRole(runtime *plugin.Runtime, systemID string, rows pgx.Rows, passwordTypes map[int64]string, passwordTypesErr error) (*mqlPostgresdbRole, error) {
	var name string
	var oid, connLimit int64
	var super, canLogin, createRole, createDb, replication, bypassRLS, inherit bool
	var validUntil pgtype.Timestamptz
	var config []string
	if err := rows.Scan(&name, &oid, &super, &canLogin, &createRole, &createDb,
		&replication, &bypassRLS, &inherit, &connLimit, &validUntil, &config); err != nil {
		return nil, err
	}

	fields := map[string]*llx.RawData{
		"__id":               llx.StringData(roleResourceID(systemID, name)),
		"name":               llx.StringData(name),
		"oid":                llx.IntData(oid),
		"isSuperuser":        llx.BoolData(super),
		"canLogin":           llx.BoolData(canLogin),
		"createRole":         llx.BoolData(createRole),
		"createDb":           llx.BoolData(createDb),
		"isReplication":      llx.BoolData(replication),
		"bypassRLS":          llx.BoolData(bypassRLS),
		"inheritsPrivileges": llx.BoolData(inherit),
		"connectionLimit":    llx.IntData(connLimit),
		"validUntil":         llx.TimeDataPtr(validUntilTime(validUntil)),
		"config":             llx.ArrayData(strSliceToAny(config), types.String),
		"passwordType":       passwordTypeField(passwordTypes, passwordTypesErr, oid),
	}

	res, err := CreateResource(runtime, "postgresdb.role", fields)
	if err != nil {
		return nil, err
	}
	return res.(*mqlPostgresdbRole), nil
}

func initPostgresdbRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, errors.New("postgresdb.role requires a non-empty name")
	}

	systemID, err := pgSystemID(runtime)
	if err != nil {
		return nil, nil, err
	}
	pool, err := pgPool(runtime, "")
	if err != nil {
		return nil, nil, err
	}
	rows, err := pool.Query(pgContext(), "SELECT "+roleColumnsFor(runtime)+" FROM pg_roles r WHERE r.rolname = $1", name)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("postgresdb.role " + name + " not found")
	}
	passwordTypes, passwordTypesErr := passwordTypesByOid(pool)
	res, err := newPostgresdbRole(runtime, systemID, rows, passwordTypes, passwordTypesErr)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlPostgresdbInstance) roles() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	passwordTypes, passwordTypesErr := passwordTypesByOid(pool)
	rows, err := pool.Query(pgContext(), "SELECT "+roleColumnsFor(r.MqlRuntime)+" FROM pg_roles r ORDER BY r.rolname")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		role, err := newPostgresdbRole(r.MqlRuntime, r.SystemIdentifier.Data, rows, passwordTypes, passwordTypesErr)
		if err != nil {
			return nil, err
		}
		list = append(list, role)
	}
	return list, rows.Err()
}

// rolesByQuery resolves each distinct role name returned by a membership query into a
// full postgresdb.role via its init.
func rolesByQuery(runtime *plugin.Runtime, oid int64, query string) ([]any, error) {
	pool, err := pgPool(runtime, "")
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(), query, oid)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	list := []any{}
	for _, name := range names {
		res, err := NewResource(runtime, "postgresdb.role", map[string]*llx.RawData{"name": llx.StringData(name)})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// Since PostgreSQL 16 pg_auth_members has one row per grantor, so the same
// membership granted by two roles appears twice; DISTINCT folds them.
const (
	memberOfQuery = `SELECT DISTINCT g.rolname FROM pg_auth_members m
		JOIN pg_roles g ON m.roleid = g.oid WHERE m.member = $1::oid ORDER BY g.rolname`
	membersQuery = `SELECT DISTINCT mr.rolname FROM pg_auth_members m
		JOIN pg_roles mr ON m.member = mr.oid WHERE m.roleid = $1::oid ORDER BY mr.rolname`
)

func (r *mqlPostgresdbRole) memberOf() ([]any, error) {
	return rolesByQuery(r.MqlRuntime, r.Oid.Data,
		memberOfQuery)
}

func (r *mqlPostgresdbRole) members() ([]any, error) {
	return rolesByQuery(r.MqlRuntime, r.Oid.Data,
		membersQuery)
}
