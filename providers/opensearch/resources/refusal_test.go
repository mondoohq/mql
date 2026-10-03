// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/opensearch/connection"
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
	errMonuser403 = &connection.PermissionError{Path: "/_plugins/_security/api/internalusers", StatusCode: 403,
		Reason: "No permission to access REST API: User monuser with Security roles [monitor_only] does not have any role privileged for admin access. No client TLS certificate found in request"}
	errNoCreds401 = &connection.PermissionError{Path: "/_plugins/_security/api/roles", StatusCode: 401}
)

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	for _, refused := range []error{errMonuser403, errNoCreds401} {
		list, err := refusedList(refused, permSecurityAPI)
		if err != nil || list == nil || len(list) != 0 {
			t.Errorf("refusedList(%v) = %#v, %v; want an empty list and no error", refused, list, err)
		}
	}
}

func TestRefusedListClassifies(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errMonuser403, permSecurityAPI)
	if list != nil || !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("403: refusedList = %#v, %v; want forbidden", list, err)
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "security_rest_api_access" {
		t.Errorf("permissions = %+v", e)
	}
	if !connection.IsPermissionError(err) {
		t.Error("the wrapped PermissionError is lost")
	}

	_, err = refusedList(errNoCreds401, permSecurityAPI)
	if !errors.Is(err, llx.ErrUnauthenticated) {
		t.Errorf("401 classified as %v, want unauthenticated", llx.KindOf(err))
	}
}

func TestRefusedListPassesOtherErrorsThrough(t *testing.T) {
	setStructuredErrors(t, true)
	// what a cluster with the security plugin disabled answers
	other := errors.New(`opensearch GET /_plugins/_security/api/roles: status 400: {"error":"no handler found for uri [/_plugins/_security/api/roles] and method [GET]"}`)
	list, err := refusedList(other, permSecurityAPI)
	if list != nil || err != other {
		t.Errorf("refusedList(400) = %v, %v; want the error unchanged", list, err)
	}
}
