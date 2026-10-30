// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	mssqldb "github.com/microsoft/go-mssqldb"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func setStructuredErrors(t *testing.T, on bool) {
	t.Helper()
	if on {
		plugin.ReadFeatures(mql.Features{byte(mql.StructuredErrors)})
	} else {
		// a non-empty feature set without the flag turns it off
		plugin.ReadFeatures(mql.Features{byte(mql.MassQueries)})
	}
	t.Cleanup(func() { plugin.ReadFeatures(mql.Features{byte(mql.MassQueries)}) })
}

// Errors SQL Server 2025 returned live: db4_auditor (VIEW SERVER STATE, VIEW
// ANY DEFINITION) reading msdb proxies, and db4_lowpriv reading a database it
// has no user in.
var (
	errProxiesDenied = mssqldb.Error{Number: 229, Class: 14, State: 5,
		Message: "The SELECT permission was denied on the object 'sysproxies', database 'msdb', schema 'dbo'."}
	errNoDatabaseAccess = mssqldb.Error{Number: 916, Class: 14, State: 2,
		Message: `The server principal "db4_lowpriv" is not able to access the database "db4_app" under the current security context.`}
	errNoMsdb = mssqldb.Error{Number: 40515, Class: 15,
		Message: "Reference to database and/or server name in 'msdb.dbo.sysproxies' is not supported in this version of SQL Server."}
	errMissingView = mssqldb.Error{Number: 208, Class: 16,
		Message: "Invalid object name 'sys.database_scoped_credentials'."}
)

func TestIsRefusal(t *testing.T) {
	for _, err := range []error{errProxiesDenied, errNoDatabaseAccess, fmt.Errorf("proxies: %w", errProxiesDenied)} {
		if !isRefusal(err) {
			t.Errorf("isRefusal(%v) = false", err)
		}
	}
	for _, err := range []error{errNoMsdb, errMissingView, errors.New("dial tcp 192.0.2.5:1433: i/o timeout"),
		mssqldb.Error{Number: 18456, Message: "Login failed for user 'x'."}, nil} {
		if isRefusal(err) {
			t.Errorf("isRefusal(%v) = true", err)
		}
	}
}

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	list, err := refusedList(errProxiesDenied, "SELECT ON msdb.dbo.sysproxies")
	if err != nil || list == nil || len(list) != 0 {
		t.Errorf("refusedList = %#v, %v; want an empty list and no error", list, err)
	}
}

func TestRefusedListIsForbidden(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errProxiesDenied, "SELECT ON msdb.dbo.sysproxies")
	if list != nil || !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("refusedList = %#v, %v; want forbidden", list, err)
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "SELECT ON msdb.dbo.sysproxies" {
		t.Errorf("permissions = %+v", e)
	}
	if sqlErrorNumber(err) != 229 {
		t.Errorf("wrapped SQL Server error lost: %v", err)
	}
}

func TestRefusedListAbsenceAndOtherErrors(t *testing.T) {
	for _, on := range []bool{false, true} {
		setStructuredErrors(t, on)
		// msdb missing (Azure SQL Database) or a view older releases lack is no rows
		for _, absent := range []error{errNoMsdb, errMissingView} {
			list, err := refusedList(absent, "x")
			if err != nil || list == nil || len(list) != 0 {
				t.Errorf("StructuredErrors=%v: refusedList(%v) = %#v, %v; want no rows", on, absent, list, err)
			}
		}
		// v13 swallowed every msdb error; anything that is neither absence
		// nor a refusal now fails in both modes
		other := mssqldb.Error{Number: 924, Message: "Database 'msdb' is already open and can only have one user at a time."}
		if _, err := refusedList(other, "x"); err == nil {
			t.Errorf("StructuredErrors=%v: error 924 swallowed", on)
		}
	}
}

func TestIsDatabaseUnavailable(t *testing.T) {
	if !isDatabaseUnavailable(mssqldb.Error{Number: 942, Message: "Database 'db4_off' cannot be opened because it is offline."}) {
		t.Error("942 not an unavailable database")
	}
	for _, err := range []error{errProxiesDenied, errMissingView, errors.New("driver: bad connection")} {
		if isDatabaseUnavailable(err) {
			t.Errorf("isDatabaseUnavailable(%v) = true", err)
		}
	}
}
