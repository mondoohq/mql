// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
)

// pgColumnsQuery lists the user columns of every relation in one schema.
//
// It reads pg_attribute rather than information_schema.columns: the latter
// lists only the columns the role holds a privilege on, without an error, which
// would read as a relation with fewer columns. pg_attribute is readable by every
// role unless an administrator revoked it.
//
// attnum > 0 drops the system columns (ctid, xmin, ...) and attisdropped the
// columns removed by ALTER TABLE DROP COLUMN, which stay in the catalog. The
// relation kinds match the ones schema.tables() lists.
const pgColumnsQuery = `SELECT c.oid::bigint, a.attname, a.attnum::bigint,
		format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
		COALESCE(col_description(a.attrelid, a.attnum), '')
	 FROM pg_attribute a
	 JOIN pg_class c ON c.oid = a.attrelid
	 JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE n.nspname = $1 AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
	   AND a.attnum > 0 AND NOT a.attisdropped
	 ORDER BY c.oid, a.attnum`

// pgColumnsPermission is the privilege a role needs to read pgColumnsQuery.
const pgColumnsPermission = "SELECT ON pg_catalog.pg_attribute"

// pgColumnRow is one row of pgColumnsQuery.
type pgColumnRow struct {
	relOid   int64
	name     string
	position int64
	typeName string
	nullable bool
	comment  string
}

// pgRowScanner is the part of pgx.Rows that groupPgColumnRows reads, so the
// grouping can be tested without a server.
type pgRowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// groupPgColumnRows reads pgColumnsQuery rows and groups them by relation oid,
// keeping the query's position order.
func groupPgColumnRows(rows pgRowScanner) (map[int64][]pgColumnRow, error) {
	byRel := map[int64][]pgColumnRow{}
	for rows.Next() {
		var c pgColumnRow
		if err := rows.Scan(&c.relOid, &c.name, &c.position, &c.typeName, &c.nullable, &c.comment); err != nil {
			return nil, err
		}
		byRel[c.relOid] = append(byRel[c.relOid], c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return byRel, nil
}

// classifyPgColumnsError turns a refused catalog read into a Forbidden error
// naming the privilege. The columns field is new, so the refusal is an error
// whatever StructuredErrors says; any other error is returned as is.
func classifyPgColumnsError(err error) error {
	if err == nil {
		return nil
	}
	if isPermissionDenied(err) {
		return llx.Forbidden(err, llx.WithPermissions(pgColumnsPermission))
	}
	return err
}

// pgSchemaColumns memoizes the columns of one schema. Every relation the
// schema lists holds the same pointer, so their columns cost one query. The
// error is memoized with the value: a role refused once is refused again.
type pgSchemaColumns struct {
	once  sync.Once
	byRel map[int64][]pgColumnRow
	err   error
}

// load runs fetch once and returns its outcome on every call.
func (c *pgSchemaColumns) load(fetch func() (map[int64][]pgColumnRow, error)) (map[int64][]pgColumnRow, error) {
	c.once.Do(func() {
		c.byRel, c.err = fetch()
	})
	return c.byRel, c.err
}

func (r *mqlPostgresdbTable) columns() ([]any, error) {
	if r.cacheSchemaColumns == nil {
		r.cacheSchemaColumns = &pgSchemaColumns{}
	}
	byRel, err := r.cacheSchemaColumns.load(func() (map[int64][]pgColumnRow, error) {
		pool, err := pgPool(r.MqlRuntime, r.cacheDatabase)
		if err != nil {
			return nil, err
		}
		rows, err := pool.Query(pgContext(), pgColumnsQuery, r.Schema.Data)
		if err != nil {
			return nil, classifyPgColumnsError(err)
		}
		defer rows.Close()
		byRel, err := groupPgColumnRows(rows)
		return byRel, classifyPgColumnsError(err)
	})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for _, c := range byRel[r.Oid.Data] {
		res, err := CreateResource(r.MqlRuntime, "postgresdb.table.column", map[string]*llx.RawData{
			"__id":     llx.StringData(r.__id + "/column/" + c.name),
			"name":     llx.StringData(c.name),
			"position": llx.IntData(c.position),
			"typeName": llx.StringData(c.typeName),
			"nullable": llx.BoolData(c.nullable),
			"comment":  llx.StringData(c.comment),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
