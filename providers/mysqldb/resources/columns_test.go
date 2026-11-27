// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/mysqldb/connection"
)

// fakeMysqlRows replays mysqlColumnsQuery rows for groupMysqlColumnRows.
type fakeMysqlRows struct {
	rows [][]any
	i    int
	err  error
}

func (f *fakeMysqlRows) Next() bool {
	if f.i >= len(f.rows) {
		return false
	}
	f.i++
	return true
}

func (f *fakeMysqlRows) Scan(dest ...any) error {
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
		default:
			return fmt.Errorf("scan: unsupported destination %T", dest[i])
		}
	}
	return nil
}

func (f *fakeMysqlRows) Err() error { return f.err }

// The rows below are information_schema.COLUMNS for a test schema built with:
//
//	CREATE TABLE crm.customers (id bigint unsigned NOT NULL PRIMARY KEY,
//	  email varchar(255) NOT NULL COMMENT 'login address', ssn char(11) NULL,
//	  balance decimal(10,2), flags int unsigned, created_at datetime(3));
//	CREATE TABLE crm.orders (order_id int NOT NULL, note text);
//	CREATE VIEW crm.customer_emails AS SELECT id, email FROM crm.customers;
//
// read with the mysql and mariadb command-line clients, not through this code.

// Measured: MySQL 8.4.13 (mysql:8.4 image), 2026-11-27.
var measuredMysql8ColumnRows = [][]any{
	{"customer_emails", "id", int64(1), "bigint unsigned", "NO", ""},
	{"customer_emails", "email", int64(2), "varchar(255)", "NO", "login address"},
	{"customers", "id", int64(1), "bigint unsigned", "NO", ""},
	{"customers", "email", int64(2), "varchar(255)", "NO", "login address"},
	{"customers", "ssn", int64(3), "char(11)", "YES", ""},
	{"customers", "balance", int64(4), "decimal(10,2)", "YES", ""},
	{"customers", "flags", int64(5), "int unsigned", "YES", ""},
	{"customers", "created_at", int64(6), "datetime(3)", "YES", ""},
	{"orders", "order_id", int64(1), "int", "NO", ""},
	{"orders", "note", int64(2), "text", "YES", ""},
}

// Measured: MariaDB 11.4.13-MariaDB-ubu2404 (mariadb:11.4 image), 2026-11-27.
// MariaDB sorts the view after the table and reports integer display widths.
var measuredMariadbColumnRows = [][]any{
	{"customers", "id", int64(1), "bigint(20) unsigned", "NO", ""},
	{"customers", "email", int64(2), "varchar(255)", "NO", "login address"},
	{"customers", "ssn", int64(3), "char(11)", "YES", ""},
	{"customers", "balance", int64(4), "decimal(10,2)", "YES", ""},
	{"customers", "flags", int64(5), "int(10) unsigned", "YES", ""},
	{"customers", "created_at", int64(6), "datetime(3)", "YES", ""},
	{"customer_emails", "id", int64(1), "bigint(20) unsigned", "NO", ""},
	{"customer_emails", "email", int64(2), "varchar(255)", "NO", "login address"},
	{"orders", "order_id", int64(1), "int(11)", "NO", ""},
	{"orders", "note", int64(2), "text", "YES", ""},
}

func TestMysqlSchemaColumns(t *testing.T) {
	for name, tc := range map[string]struct {
		rows           [][]any
		bigint, intTyp string
	}{
		"mysql 8.4":    {measuredMysql8ColumnRows, "bigint unsigned", "int unsigned"},
		"mariadb 11.4": {measuredMariadbColumnRows, "bigint(20) unsigned", "int(10) unsigned"},
	} {
		t.Run(name, func(t *testing.T) {
			byTable, err := groupMysqlColumnRows(&fakeMysqlRows{rows: tc.rows})
			if err != nil {
				t.Fatal(err)
			}
			if len(byTable) != 3 {
				t.Fatalf("tables = %d, want 3", len(byTable))
			}
			want := []mysqlColumnRow{
				{table: "customers", name: "id", position: 1, typeName: tc.bigint, nullable: false},
				{table: "customers", name: "email", position: 2, typeName: "varchar(255)", nullable: false, comment: "login address"},
				{table: "customers", name: "ssn", position: 3, typeName: "char(11)", nullable: true},
				{table: "customers", name: "balance", position: 4, typeName: "decimal(10,2)", nullable: true},
				{table: "customers", name: "flags", position: 5, typeName: tc.intTyp, nullable: true},
				{table: "customers", name: "created_at", position: 6, typeName: "datetime(3)", nullable: true},
			}
			if got := byTable["customers"]; !reflect.DeepEqual(got, want) {
				t.Errorf("customers = %+v, want %+v", got, want)
			}
			if n := len(byTable["customer_emails"]); n != 2 {
				t.Errorf("customer_emails columns = %d, want 2", n)
			}
			if got := byTable["orders"][1].typeName; got != "text" {
				t.Errorf("orders.note type = %q, want text", got)
			}
		})
	}
}

func TestGroupMysqlColumnRowsPropagatesRowError(t *testing.T) {
	// Synthetic: the connection fails mid-result; no target showed this.
	_, err := groupMysqlColumnRows(&fakeMysqlRows{rows: measuredMysql8ColumnRows[:1], err: errors.New("invalid connection")})
	if err == nil || err.Error() != "invalid connection" {
		t.Errorf("err = %v, want invalid connection", err)
	}
}

func TestMysqlColumnsWithoutGlobalSelect(t *testing.T) {
	// Measured: MySQL 8.4.13 and MariaDB 11.4.13, 2026-11-27. An account
	// granted SELECT (id) ON crm.customers, and nothing on *.*, reads one row
	// from information_schema.COLUMNS for schema crm (customers.id) where root
	// reads ten, and gets no error. The access value is built here.
	//
	// The refusal does not depend on StructuredErrors: the field is new.
	for _, on := range []bool{true, false} {
		setStructuredErrors(t, on)
		err := columnsVisible(&connection.CallerAccess{Self: "'lowpriv'@'%'", Global: map[string]bool{"USAGE": true}})
		if !errors.Is(err, llx.ErrForbidden) {
			t.Fatalf("structured=%v: want Forbidden, got %v", on, err)
		}
		if got := llx.ErrorDetailOf(err).Permissions; !reflect.DeepEqual(got, []string{mysqlColumnsPermission}) {
			t.Errorf("permissions = %v", got)
		}
		if !strings.Contains(err.Error(), "'lowpriv'@'%'") {
			t.Errorf("error does not name the account: %v", err)
		}
	}

	// Synthetic: global SELECT makes the view complete.
	if err := columnsVisible(&connection.CallerAccess{Global: map[string]bool{"SELECT": true}}); err != nil {
		t.Errorf("global SELECT refused: %v", err)
	}
}

func TestMysqlColumnsAccessDeniedIsForbidden(t *testing.T) {
	// Synthetic: no target refused the query itself; 1142 is the number the
	// server uses for a denied table read (errTableDenied).
	if err := classifyMysqlColumnsError(fmt.Errorf("columns: %w", errTableDenied)); !errors.Is(err, llx.ErrForbidden) {
		t.Errorf("want Forbidden, got %v", err)
	}

	// A transport error is not a refusal.
	other := errors.New("dial tcp: i/o timeout")
	if got := classifyMysqlColumnsError(other); got != other {
		t.Errorf("transport error changed: %v", got)
	}
	lost := &mysqldriver.MySQLError{Number: 2013, Message: "Lost connection"}
	if errors.Is(classifyMysqlColumnsError(lost), llx.ErrForbidden) {
		t.Error("lost connection classified as Forbidden")
	}
	if classifyMysqlColumnsError(nil) != nil {
		t.Error("nil error classified")
	}
}

func TestMysqlColumnsOnePerSchema(t *testing.T) {
	// Synthetic: concurrent reads from tables of one schema share one query,
	// and a failure is memoized with it.
	memo := &mysqlSchemaColumns{}
	var calls atomic.Int32
	fetch := func() (map[string][]mysqlColumnRow, error) {
		calls.Add(1)
		return groupMysqlColumnRows(&fakeMysqlRows{rows: measuredMysql8ColumnRows})
	}
	var wg sync.WaitGroup
	for _, table := range []string{"customers", "orders", "customer_emails", "customers"} {
		wg.Go(func() {
			byTable, err := memo.load(fetch)
			if err != nil || len(byTable[table]) == 0 {
				t.Errorf("%s: %d columns, err=%v", table, len(byTable[table]), err)
			}
		})
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("queries = %d, want 1", n)
	}

	failing := &mysqlSchemaColumns{}
	failures := 0
	fail := func() (map[string][]mysqlColumnRow, error) { failures++; return nil, errors.New("refused") }
	_, err1 := failing.load(fail)
	_, err2 := failing.load(fail)
	if err1 == nil || err1 != err2 || failures != 1 {
		t.Errorf("err1=%v err2=%v failures=%d, want one memoized failure", err1, err2, failures)
	}
}
