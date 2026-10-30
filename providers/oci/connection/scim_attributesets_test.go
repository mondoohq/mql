// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
)

// requestFor builds the request an interceptor would receive for a raw query.
func requestFor(t *testing.T, rawQuery string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://idcs.example.com/admin/v1/Users?"+rawQuery, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	return req
}

// TestCollapseScimAttributeSetsJoinsRepeatedValues pins the fix itself.
//
// The identity domains service reads only the first of a repeated
// attributeSets parameter, so the two-value form the SDK emits has to become
// one comma-delimited value before the request is signed.
func TestCollapseScimAttributeSetsJoinsRepeatedValues(t *testing.T) {
	req := requestFor(t, "attributeSets=default&attributeSets=request&count=200")

	if err := collapseScimAttributeSets(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.URL.Query()["attributeSets"]
	if len(got) != 1 {
		t.Fatalf("attributeSets stayed repeated as %v; the service would honor only the first", got)
	}
	if got[0] != "default,request" {
		t.Errorf("attributeSets = %q, want %q", got[0], "default,request")
	}

	// The rest of the query has to survive: dropping count would silently
	// change the page size the pagination loop is built around.
	if count := req.URL.Query().Get("count"); count != "200" {
		t.Errorf("count = %q, want %q", count, "200")
	}
}

// TestCollapseScimAttributeSetsPreservesOrder keeps `default` ahead of
// `request`. The service resolves a repeated parameter to whichever value comes
// first, so an order flip is exactly the failure this guards against and it
// would not show up as an error.
func TestCollapseScimAttributeSetsPreservesOrder(t *testing.T) {
	req := requestFor(t, "attributeSets=default&attributeSets=request")

	if err := collapseScimAttributeSets(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.URL.Query().Get("attributeSets"); got != "default,request" {
		t.Errorf("attributeSets = %q, want the values joined in the order they were sent", got)
	}
}

// TestCollapseScimAttributeSetsLeavesOtherRequestsAlone covers the cases the
// interceptor must not touch: it runs on every identity domains call, not only
// the listings that ask for two attribute sets.
func TestCollapseScimAttributeSetsLeavesOtherRequestsAlone(t *testing.T) {
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{"no attributeSets at all", "count=200&startIndex=1"},
		{"a single attributeSets value", "attributeSets=default&count=200"},
		{"an empty query", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := requestFor(t, test.rawQuery)
			before := req.URL.RawQuery

			if err := collapseScimAttributeSets(req); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.URL.RawQuery != before {
				t.Errorf("query rewritten to %q, want it left as %q", req.URL.RawQuery, before)
			}
		})
	}
}

// TestCollapseScimAttributeSetsSurvivesAnEmptyRequest guards the interceptor
// against a nil request or URL rather than panicking inside the SDK's call
// path, where a panic would take down the whole scan rather than one field.
func TestCollapseScimAttributeSetsSurvivesAnEmptyRequest(t *testing.T) {
	if err := collapseScimAttributeSets(nil); err != nil {
		t.Errorf("nil request returned %v, want no error", err)
	}
	if err := collapseScimAttributeSets(&http.Request{}); err != nil {
		t.Errorf("request without a URL returned %v, want no error", err)
	}
}

// TestScimListingEmitsRepeatedAttributeSets is the reason the interceptor
// exists, pinned against the SDK rather than against our own assumption.
//
// The request struct tags attributeSets collectionFormat:"multi". If a future
// SDK switched it to a comma-joined value this test fails, which is the signal
// to delete the interceptor rather than to keep a rewrite that has become a
// no-op.
func TestScimListingEmitsRepeatedAttributeSets(t *testing.T) {
	request := identitydomains.ListUsersRequest{
		Count: new(200),
		AttributeSets: []identitydomains.AttributeSetsEnum{
			identitydomains.AttributeSetsDefault,
			identitydomains.AttributeSetsRequest,
		},
	}

	httpRequest, err := common.MakeDefaultHTTPRequestWithTaggedStruct(
		http.MethodGet, "/admin/v1/Users", request)
	if err != nil {
		t.Fatalf("building the SDK request: %v", err)
	}

	values, err := url.ParseQuery(httpRequest.URL.RawQuery)
	if err != nil {
		t.Fatalf("parsing the SDK query: %v", err)
	}

	if got := values["attributeSets"]; len(got) != 2 {
		t.Fatalf("the SDK emitted attributeSets as %v; the interceptor is written for the repeated form", got)
	}
}

// TestIdentityDomainsClientInstallsTheInterceptor makes the wiring explicit:
// the rewrite only takes effect if the client carries it, and a client built
// without it fails silently by returning listings that are missing attributes.
func TestIdentityDomainsClientInstallsTheInterceptor(t *testing.T) {
	conn := testConnection(t)

	client, err := conn.IdentityDomainsClient("https://idcs.example.com")
	if err != nil {
		t.Fatalf("building the identity domains client: %v", err)
	}
	if client.Interceptor == nil {
		t.Fatal("the identity domains client has no interceptor; repeated attributeSets would reach the service unjoined")
	}

	req := requestFor(t, "attributeSets=default&attributeSets=request")
	if err := client.Interceptor(req); err != nil {
		t.Fatalf("the installed interceptor returned %v", err)
	}
	if got := req.URL.Query().Get("attributeSets"); got != "default,request" {
		t.Errorf("the installed interceptor produced %q, want %q", got, "default,request")
	}
}
