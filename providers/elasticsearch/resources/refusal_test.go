// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/elasticsearch/connection"
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

var (
	errMonuser403 = &connection.PermissionError{Path: "/_security/user", StatusCode: 403,
		Reason: "action [cluster:admin/xpack/security/user/get] is unauthorized for user [monuser] with effective roles [monitor_only], this action is granted by the cluster privileges [read_security,manage_security,all]"}
	errNoCreds401 = &connection.PermissionError{Path: "/_security/api_key", StatusCode: 401}
)

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	for _, refused := range []error{errMonuser403, errNoCreds401} {
		list, err := refusedList(refused, "read_security")
		if err != nil || list == nil || len(list) != 0 {
			t.Errorf("refusedList(%v) = %#v, %v; want an empty list and no error", refused, list, err)
		}
	}
}

func TestRefusedListClassifies(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errMonuser403, "read_security")
	if list != nil || !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("403: refusedList = %#v, %v; want forbidden", list, err)
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "read_security" {
		t.Errorf("permissions = %+v", e)
	}
	if !connection.IsPermissionError(err) {
		t.Error("the wrapped PermissionError is lost")
	}

	_, err = refusedList(errNoCreds401, "read_security")
	if !errors.Is(err, llx.ErrUnauthenticated) {
		t.Errorf("401 classified as %v, want unauthenticated", llx.KindOf(err))
	}
}

func TestRefusedListPassesOtherErrorsThrough(t *testing.T) {
	setStructuredErrors(t, true)
	other := errors.New("elasticsearch GET /_security/user: status 405: Incorrect HTTP method")
	list, err := refusedList(other, "read_security")
	if list != nil || err != other {
		t.Errorf("refusedList(405) = %v, %v; want the error unchanged", list, err)
	}
}
