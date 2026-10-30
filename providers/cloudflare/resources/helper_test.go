// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

const (
	testAccountID = "01a7362d577a6c3019a474fd6f485823"
	testZoneID    = "d56084adb405e0b7e32c52321bf07be6"
)

// providerCallbacks is a minimal implementation of the plugin.ProviderCallback
// interface for testing purposes.
type providerCallbacks struct{}

func (p *providerCallbacks) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	return &plugin.DataRes{
		Data: &llx.Primitive{
			Type:  string(types.Resource(req.Resource)),
			Value: []byte("not of interest"),
		},
	}, nil
}

func (p *providerCallbacks) GetRecording(req *plugin.DataReq) (*plugin.ResourceData, error) {
	return &plugin.ResourceData{}, nil
}

func (p *providerCallbacks) Collect(req *plugin.DataRes) error {
	return nil
}

// testEnv holds all the pieces needed for a test: the mock HTTP server,
// the Cloudflare connection, and the MQL plugin runtime.
type testEnv struct {
	Mux     *http.ServeMux
	Server  *httptest.Server
	Conn    *connection.CloudflareConnection
	Runtime *plugin.Runtime
}

// setupTestEnv creates a test environment with a mock HTTP server,
// a Cloudflare API client pointed at it, and a plugin runtime.
// The returned testEnv.Mux can be used to register endpoint handlers.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Create a cloudflare-go client pointed at the mock server.
	client := cloudflare.NewClient(
		option.WithAPIToken("test-key"),
		option.WithBaseURL(server.URL+"/"),
	)

	conn := &connection.CloudflareConnection{
		Cf: client,
	}

	runtime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
		Callback:   &providerCallbacks{},
	}

	return &testEnv{
		Mux:     mux,
		Server:  server,
		Conn:    conn,
		Runtime: runtime,
	}
}

// createTestZone creates a cloudflare.zone resource in the runtime with
// a minimal set of fields. It returns the zone resource for use in tests.
func createTestZone(t *testing.T, env *testEnv) *mqlCloudflareZone {
	t.Helper()

	// First create the account resource (needed by zone methods that call c.GetAccount())
	acc, err := CreateResource(env.Runtime, "cloudflare.zone.account", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.zone.account@" + testAccountID),
		"id":   llx.StringData(testAccountID),
		"name": llx.StringData("Test Account"),
	})
	if err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}

	zone, err := CreateResource(env.Runtime, "cloudflare.zone", map[string]*llx.RawData{
		"id":                  llx.StringData(testZoneID),
		"name":                llx.StringData("example.com"),
		"nameServers":         llx.ArrayData([]any{"ns1.example.com"}, types.String),
		"originalNameServers": llx.ArrayData([]any{}, types.String),
		"status":              llx.StringData("active"),
		"paused":              llx.BoolData(false),
		"type":                llx.StringData("full"),
		"createdOn":           llx.TimeData(llx.DurationToTime(0)),
		"modifiedOn":          llx.TimeData(llx.DurationToTime(0)),
		"account":             llx.ResourceData(acc, acc.MqlName()),
		"owner":               llx.NilData,
	})
	if err != nil {
		t.Fatalf("failed to create test zone: %v", err)
	}

	return zone.(*mqlCloudflareZone)
}

// createTestOne creates a cloudflare.one resource in the runtime.
func createTestOne(t *testing.T, env *testEnv) *mqlCloudflareOne {
	t.Helper()

	one, err := CreateResource(env.Runtime, "cloudflare.one", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.one@" + testZoneID),
	})
	if err != nil {
		t.Fatalf("failed to create test one: %v", err)
	}

	o := one.(*mqlCloudflareOne)
	o.ZoneID = testZoneID
	o.AccountID = testAccountID

	return o
}

// createTestAccount creates a cloudflare.account resource in the runtime.
func createTestAccount(t *testing.T, env *testEnv) *mqlCloudflareAccount {
	t.Helper()

	acc, err := CreateResource(env.Runtime, "cloudflare.account", map[string]*llx.RawData{
		"id":        llx.StringData(testAccountID),
		"name":      llx.StringData("Test Account"),
		"type":      llx.StringData("standard"),
		"settings":  llx.NilData,
		"createdOn": llx.TimeData(llx.DurationToTime(0)),
	})
	if err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}

	return acc.(*mqlCloudflareAccount)
}

// loadFixture reads a JSON fixture file from the testdata directory.
func loadFixture(name string) string {
	b, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		panic(fmt.Sprintf("failed to load fixture %q: %v", name, err))
	}
	return string(b)
}

// jsonResponse is a helper to write a JSON response with standard wrapping.
func jsonResponse(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body)
}

// boolPtr returns a pointer to v, for table tests that distinguish an absent
// value from an explicit false.
//
//go:fix inline
func boolPtr(v bool) *bool { return new(v) }

// pagedFixture serves a fixture on the first page and an empty result on every
// later page. cloudflare-go's V4 page paginator stops only when a page comes
// back empty, so a handler that ignores `page` and always returns the same
// fixture makes the auto-pager loop forever.
func pagedFixture(name string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page != "" && page != "1" {
			jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":[],`+
				`"result_info":{"page":2,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`)
			return
		}
		jsonResponse(w, loadFixture(name))
	}
}
