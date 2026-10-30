// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
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

// The exception ClickHouse 26.9 returns to a user without SELECT on
// system.users, captured live.
var errUsersDenied = &proto.Exception{
	Code:    497,
	Name:    "DB::Exception",
	Message: "nopriv: Not enough privileges. To execute this query, it's necessary to have the grant SELECT ON system.users",
}

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	list, err := refusedList(errUsersDenied, "SELECT ON system.users")
	if err != nil {
		t.Fatalf("refusedList returned %v with StructuredErrors off", err)
	}
	if list == nil || len(list) != 0 {
		t.Errorf("refusedList = %#v, want an empty non-nil list", list)
	}
}

func TestRefusedListIsForbidden(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errUsersDenied, "SELECT ON system.users")
	if list != nil {
		t.Errorf("refusedList returned a list %#v alongside the refusal", list)
	}
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("refusedList error kind = %v, want forbidden", llx.KindOf(err))
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "SELECT ON system.users" {
		t.Errorf("permissions = %+v", e)
	}
	var ex *proto.Exception
	if !errors.As(err, &ex) || ex.Code != 497 {
		t.Errorf("wrapped ClickHouse exception lost: %v", err)
	}
}

func TestRefusedListPassesOtherErrorsThrough(t *testing.T) {
	for _, on := range []bool{false, true} {
		setStructuredErrors(t, on)
		transport := errors.New("dial tcp 192.0.2.10:9000: i/o timeout")
		list, err := refusedList(transport, "SELECT ON system.users")
		if list != nil || err != transport {
			t.Errorf("StructuredErrors=%v: refusedList(transport) = %v, %v; want the error unchanged", on, list, err)
		}
		// UNKNOWN_ACCESS_ENTITY is read as "not permitted" by v13 but is not
		// a refusal, so it must not be classified as one.
		unknown := &proto.Exception{Code: 492, Message: "There is no role `x` in user directories"}
		_, err = refusedList(unknown, "SELECT ON system.users")
		if on && (err == nil || errors.Is(err, llx.ErrForbidden)) {
			t.Errorf("492 classified as %v, want unclassified", llx.KindOf(err))
		}
	}
}
