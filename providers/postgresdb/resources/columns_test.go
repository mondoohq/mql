// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// fakePgRows replays pgColumnsQuery rows for groupPgColumnRows.
type fakePgRows struct {
	rows [][]any
	i    int
	err  error
}

func (f *fakePgRows) Next() bool {
	if f.i >= len(f.rows) {
		return false
	}
	f.i++
	return true
}

func (f *fakePgRows) Scan(dest ...any) error {
	row := f.rows[f.i-1]
	if len(dest) != len(row) {
		return fmt.Errorf("scan: %d destinations for %d columns", len(dest), len(row))
	}
	for i, v := range row {
		switch d := dest[i].(type) {
		case *int64:
			*d = v.(int64)
		case *string:
			*d = v.(string)
		case *bool:
			*d = v.(bool)
		default:
			return fmt.Errorf("scan: unsupported destination %T", dest[i])
		}
	}
	return nil
}

func (f *fakePgRows) Err() error { return f.err }

// measuredPgColumnRows is the output of pgColumnsQuery for schema crm.
//
// Measured: PostgreSQL 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1), 2026-11-27, a
// test database built with:
//
//	CREATE TABLE crm.customers (id bigint PRIMARY KEY, email character varying(255) NOT NULL,
//	  ssn text, balance numeric(10,2), legacy int, created_at timestamp with time zone);
//	ALTER TABLE crm.customers DROP COLUMN legacy;
//	COMMENT ON COLUMN crm.customers.ssn IS 'US social security number';
//	CREATE TABLE crm.orders (order_id integer NOT NULL, customer_id bigint, note varchar);
//	CREATE VIEW crm.customer_emails AS SELECT id, email FROM crm.customers;
//
// The rows were read with psql, not through this code. The types match the
// Type column of \d+ for both tables.
var measuredPgColumnRows = [][]any{
	{int64(16390), "id", int64(1), "bigint", false, ""},
	{int64(16390), "email", int64(2), "character varying(255)", false, ""},
	{int64(16390), "ssn", int64(3), "text", true, "US social security number"},
	{int64(16390), "balance", int64(4), "numeric(10,2)", true, ""},
	{int64(16390), "created_at", int64(6), "timestamp with time zone", true, ""},
	{int64(16397), "order_id", int64(1), "integer", false, ""},
	{int64(16397), "customer_id", int64(2), "bigint", true, ""},
	{int64(16397), "note", int64(3), "character varying", true, ""},
	{int64(16402), "id", int64(1), "bigint", true, ""},
	{int64(16402), "email", int64(2), "character varying(255)", true, ""},
}

func TestGroupPgColumnRows(t *testing.T) {
	byRel, err := groupPgColumnRows(&fakePgRows{rows: measuredPgColumnRows})
	require.NoError(t, err)
	require.Len(t, byRel, 3)

	customers := byRel[16390]
	names := []string{}
	for _, c := range customers {
		names = append(names, c.name)
	}
	// Measured: the dropped column legacy is absent, and created_at keeps
	// its attnum 6, so the positions have a gap where legacy was.
	assert.Equal(t, []string{"id", "email", "ssn", "balance", "created_at"}, names)
	assert.Equal(t, int64(6), customers[4].position)

	assert.Equal(t, pgColumnRow{relOid: 16390, name: "email", position: 2, typeName: "character varying(255)", nullable: false}, customers[1])
	assert.Equal(t, pgColumnRow{relOid: 16390, name: "ssn", position: 3, typeName: "text", nullable: true, comment: "US social security number"}, customers[2])
	assert.Equal(t, "numeric(10,2)", customers[3].typeName)

	// Measured: a view's columns are listed, and nullable, since a view
	// carries no NOT NULL constraint.
	assert.Equal(t, []pgColumnRow{
		{relOid: 16402, name: "id", position: 1, typeName: "bigint", nullable: true},
		{relOid: 16402, name: "email", position: 2, typeName: "character varying(255)", nullable: true},
	}, byRel[16402])
}

func TestGroupPgColumnRowsPropagatesRowError(t *testing.T) {
	// Synthetic: the connection fails after the first row; no target showed this.
	_, err := groupPgColumnRows(&fakePgRows{rows: measuredPgColumnRows[:1], err: errors.New("connection reset")})
	assert.EqualError(t, err, "connection reset")
}

func TestPgColumnsQueryExcludesDroppedAndSystemColumns(t *testing.T) {
	// The filters measured above live in the query; a refactor that drops
	// either one brings back ctid, xmin, ... or ........pg.dropped.5........
	q := strings.Join(strings.Fields(pgColumnsQuery), " ")
	assert.Contains(t, q, "a.attnum > 0")
	assert.Contains(t, q, "NOT a.attisdropped")
	assert.Contains(t, q, "ORDER BY c.oid, a.attnum")
	assert.Contains(t, q, "c.relkind IN ('r', 'v', 'm', 'f', 'p')")
}

func TestPgColumnsOnePerSchema(t *testing.T) {
	// Synthetic: two relations of one schema share the memo, so the query
	// runs once however many relations read their columns, and concurrently.
	memo := &pgSchemaColumns{}
	var calls atomic.Int32
	fetch := func() (map[int64][]pgColumnRow, error) {
		calls.Add(1)
		return groupPgColumnRows(&fakePgRows{rows: measuredPgColumnRows})
	}
	var wg sync.WaitGroup
	for _, oid := range []int64{16390, 16397, 16390, 16397} {
		wg.Go(func() {
			byRel, err := memo.load(fetch)
			assert.NoError(t, err)
			assert.NotEmpty(t, byRel[oid])
		})
	}
	wg.Wait()
	assert.Equal(t, int32(1), calls.Load())

	// A second schema has its own memo and adds one query.
	other := &pgSchemaColumns{}
	_, err := other.load(fetch)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load())
}

func TestPgColumnsErrorIsMemoized(t *testing.T) {
	// Synthetic: a refused read is not retried per relation.
	memo := &pgSchemaColumns{}
	calls := 0
	fetch := func() (map[int64][]pgColumnRow, error) {
		calls++
		return nil, errors.New("refused")
	}
	_, err1 := memo.load(fetch)
	_, err2 := memo.load(fetch)
	assert.Error(t, err1)
	assert.Equal(t, err1, err2)
	assert.Equal(t, 1, calls)
}

func TestPgColumnsDeniedIsForbidden(t *testing.T) {
	// Measured: PostgreSQL 16.15, 2026-11-27. After REVOKE SELECT ON
	// pg_catalog.pg_attribute FROM PUBLIC, a non-superuser's read of
	// pg_attribute fails with "42501: permission denied for table
	// pg_attribute" (psql, VERBOSITY verbose). The error value is built here
	// with that code and message.
	denied := &pgconn.PgError{Code: "42501", Message: "permission denied for table pg_attribute"}
	err := classifyPgColumnsError(fmt.Errorf("query: %w", denied))
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden), "want Forbidden, got %v", err)
	assert.Equal(t, []string{pgColumnsPermission}, llx.ErrorDetailOf(err).Permissions)

	// Any other error is returned as is, never as Forbidden.
	other := &pgconn.PgError{Code: "57P01", Message: "terminating connection"}
	err = classifyPgColumnsError(other)
	assert.False(t, errors.Is(err, llx.ErrForbidden))
	assert.Equal(t, other, err)

	assert.NoError(t, classifyPgColumnsError(nil))
}
