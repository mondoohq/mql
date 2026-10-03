// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
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

// The error a USAGE-only account gets for SELECT ... FROM mysql.user.
var errTableDenied = &mysqldriver.MySQLError{
	Number:  1142,
	Message: "SELECT command denied to user 'mqlnone'@'127.0.0.1' for table 'user'",
}

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	list, err := refusedList(errTableDenied, "SELECT ON mysql.user")
	if err != nil {
		t.Fatalf("refusedList returned %v with StructuredErrors off", err)
	}
	if list == nil || len(list) != 0 {
		t.Errorf("refusedList = %#v, want an empty non-nil list", list)
	}
}

func TestRefusedListIsForbidden(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errTableDenied, "SELECT ON mysql.user")
	if list != nil {
		t.Errorf("refusedList returned a list %#v alongside the refusal", list)
	}
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("refusedList error kind = %v, want forbidden", llx.KindOf(err))
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "SELECT ON mysql.user" {
		t.Errorf("permissions = %+v", e)
	}
	// the server's own message must survive the classification
	var myErr *mysqldriver.MySQLError
	if !errors.As(err, &myErr) || myErr.Number != 1142 {
		t.Errorf("wrapped MySQL error lost: %v", err)
	}
}

func TestIsAccessDeniedDoesNotMatchTransportErrors(t *testing.T) {
	if isAccessDenied(errors.New("dial tcp 192.0.2.1:3306: i/o timeout")) {
		t.Error("a transport error is not a refusal")
	}
	if isAccessDenied(&mysqldriver.MySQLError{Number: 1146, Message: "Table 'mysql.role_edges' doesn't exist"}) {
		t.Error("a missing table is not a refusal")
	}
	if !isAccessDenied(errTableDenied) {
		t.Error("1142 is a refusal")
	}
}
