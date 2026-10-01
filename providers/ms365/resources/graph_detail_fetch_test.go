// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGraph serves the Graph $batch endpoint and plain GETs from canned
// bodies keyed by the request path. It records each batched step's url so a
// test can assert on the query a fetcher sent.
type fakeGraph struct {
	t   *testing.T
	srv *httptest.Server
	// path (without query) -> status and JSON body. A body may reference
	// the server's own address as {{base}}, for nextLink urls.
	routes map[string]fakeRoute

	mu    sync.Mutex
	steps []string
}

type fakeRoute struct {
	status int
	body   string
}

func newFakeGraph(t *testing.T, routes map[string]fakeRoute) *fakeGraph {
	f := &fakeGraph{t: t, routes: routes}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) base() string { return f.srv.URL + "/v1.0" }

func (f *fakeGraph) client() *msgraphsdkgo.GraphServiceClient {
	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(f.t, err)
	adapter.SetBaseUrl(f.base())
	return msgraphsdkgo.NewGraphServiceClient(adapter)
}

func (f *fakeGraph) render(r fakeRoute) (int, json.RawMessage) {
	body := strings.ReplaceAll(r.body, "{{base}}", f.base())
	return r.status, json.RawMessage(body)
}

func (f *fakeGraph) lookup(rawURL string) fakeRoute {
	u, err := url.Parse(rawURL)
	require.NoError(f.t, err)
	path := strings.TrimPrefix(u.Path, "/v1.0")
	route, ok := f.routes[path]
	if !ok {
		return fakeRoute{status: http.StatusNotFound, body: `{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`}
	}
	return route
}

func (f *fakeGraph) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/$batch") {
		var req struct {
			Requests []struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			} `json:"requests"`
		}
		var reqBody io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			require.NoError(f.t, err)
			reqBody = gz
		}
		require.NoError(f.t, json.NewDecoder(reqBody).Decode(&req))
		type sub struct {
			ID      string            `json:"id"`
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
			Body    json.RawMessage   `json:"body"`
		}
		out := struct {
			Responses []sub `json:"responses"`
		}{}
		for _, step := range req.Requests {
			f.mu.Lock()
			f.steps = append(f.steps, step.URL)
			f.mu.Unlock()
			status, body := f.render(f.lookup(step.URL))
			out.Responses = append(out.Responses, sub{
				ID:      step.ID,
				Status:  status,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    body,
			})
		}
		require.NoError(f.t, json.NewEncoder(w).Encode(out))
		return
	}
	status, body := f.render(f.lookup(r.URL.String()))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// The assignments of a service principal come from its own
// appRoleAssignedTo collection, fully paged. A $batch sub-response only
// carries the first page, so dropping the iterate over @odata.nextLink loses
// the second page here; a failing principal must not take the other one down.
func TestFetchAppRoleAssignedTo_PagesAndIsolatesFailures(t *testing.T) {
	f := newFakeGraph(t, map[string]fakeRoute{
		"/servicePrincipals/sp-1/appRoleAssignedTo": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/servicePrincipals/sp-1/appRoleAssignedTo/page2",
			"value": [
				{"id": "a-1", "principalDisplayName": "Alice", "principalType": "User"},
				{"id": "a-2", "principalDisplayName": "Admins", "principalType": "Group"}
			]}`},
		"/servicePrincipals/sp-1/appRoleAssignedTo/page2": {status: 200, body: `{
			"value": [
				{"id": "a-3", "principalDisplayName": "Robot", "principalType": "ServicePrincipal"}
			]}`},
		"/servicePrincipals/sp-2/appRoleAssignedTo": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`},
		"/servicePrincipals/sp-3/appRoleAssignedTo": {status: 200, body: `{"value": []}`},
	})

	got, errs, err := fetchAppRoleAssignedTo(context.Background(), f.client(), []string{"sp-1", "sp-2", "sp-3"})
	require.NoError(t, err)

	require.Len(t, got["sp-1"], 3)
	names := []string{}
	principalTypes := []string{}
	for _, a := range got["sp-1"] {
		names = append(names, *a.GetPrincipalDisplayName())
		principalTypes = append(principalTypes, *a.GetPrincipalType())
	}
	assert.Equal(t, []string{"Alice", "Admins", "Robot"}, names)
	assert.Equal(t, []string{"User", "Group", "ServicePrincipal"}, principalTypes)

	assert.Error(t, errs["sp-2"])
	assert.NotContains(t, got, "sp-2")

	assert.NoError(t, errs["sp-3"])
	assert.Contains(t, got, "sp-3")
	assert.Empty(t, got["sp-3"])

	for _, step := range f.steps {
		assert.Contains(t, step, "/appRoleAssignedTo", "each principal is read from its own appRoleAssignedTo collection")
	}
}

// udid, iccid, notes and ethernetMacAddress are only returned by a
// single-device GET that selects them. The fetcher must ask for them by name
// (an unselected GET answers with the same empty values the list returns) and
// map each property to its own field, with an absent property left nil so
// the field reads null rather than "".
func TestFetchManagedDeviceDetails(t *testing.T) {
	f := newFakeGraph(t, map[string]fakeRoute{
		"/deviceManagement/managedDevices/dev-1": {status: 200, body: `{
			"udid": "00008030-001A2B3C4D5E6F70",
			"iccid": "8901260000000000001",
			"notes": "loaner laptop",
			"ethernetMacAddress": "AABBCCDDEEFF"
		}`},
		"/deviceManagement/managedDevices/dev-2": {status: 200, body: `{
			"udid": "00008030-0000000000000002"
		}`},
		"/deviceManagement/managedDevices/dev-3": {status: 404, body: `{"error":{"code":"ResourceNotFound","message":"gone"}}`},
	})

	data, errs, err := fetchManagedDeviceDetails(context.Background(), f.client(), []string{"dev-1", "dev-2", "dev-3"})
	require.NoError(t, err)

	d1 := data["dev-1"].(managedDeviceDetail)
	require.NotNil(t, d1.udid)
	require.NotNil(t, d1.iccid)
	require.NotNil(t, d1.notes)
	require.NotNil(t, d1.ethernetMacAddress)
	assert.Equal(t, "00008030-001A2B3C4D5E6F70", *d1.udid)
	assert.Equal(t, "8901260000000000001", *d1.iccid)
	assert.Equal(t, "loaner laptop", *d1.notes)
	assert.Equal(t, "AABBCCDDEEFF", *d1.ethernetMacAddress)

	d2 := data["dev-2"].(managedDeviceDetail)
	require.NotNil(t, d2.udid)
	assert.Equal(t, "00008030-0000000000000002", *d2.udid)
	assert.Nil(t, d2.iccid, "an absent property stays nil so the field reads null")
	assert.Nil(t, d2.notes)
	assert.Nil(t, d2.ethernetMacAddress)

	assert.Error(t, errs["dev-3"])
	assert.NotContains(t, data, "dev-3")

	require.Len(t, f.steps, 3)
	for _, step := range f.steps {
		u, err := url.Parse(step)
		require.NoError(t, err)
		sel := strings.Split(u.Query().Get("$select"), ",")
		assert.ElementsMatch(t, []string{"udid", "iccid", "notes", "ethernetMacAddress"}, sel)
	}
}
