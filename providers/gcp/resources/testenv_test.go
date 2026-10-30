// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

// testProjectId is the project every fixture in this package is scoped to.
const testProjectId = "test-project"

// testEnv wires a GCP connection and an MQL runtime to a local HTTP server, so
// a lister can be driven end to end -- request, pagination, decode, resource
// construction -- with no credentials and no network.
//
// Register handlers on Mux using the API's real path, e.g.
// "/compute/v1/projects/test-project/zones". The Google client libraries build
// their normal request URLs against googleapis.com; the transport installed
// here rewrites only the scheme and host, so the path, query and headers the
// client actually produces are what the handler sees. A test that asserts on
// the query string is therefore asserting on real client behavior (this is how
// the pagination tests check the cursor is echoed back).
type testEnv struct {
	Mux     *http.ServeMux
	Server  *httptest.Server
	Conn    *connection.GcpConnection
	Runtime *plugin.Runtime
}

// setupTestEnv builds the environment and points the given scope sets at it.
//
// The scope sets must match what the lister under test passes to conn.Client();
// a mismatch means the lister asks for a client that was never seeded, falls
// through to real credential resolution, and the test fails with an auth error
// rather than a useful one.
func setupTestEnv(t *testing.T, scopeSets ...[]string) *testEnv {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	client := &http.Client{Transport: &redirectTransport{base: base}}

	conn := &connection.GcpConnection{
		Conf: &inventory.Config{
			Type:    "gcp",
			Options: map[string]string{"project-id": testProjectId},
		},
	}
	for _, scopes := range scopeSets {
		conn.UseHTTPClient(client, scopes...)
	}

	return &testEnv{
		Mux:    mux,
		Server: server,
		Conn:   conn,
		Runtime: &plugin.Runtime{
			Resources:  &syncx.Map[plugin.Resource]{},
			Connection: conn,
			Callback:   &testCallbacks{},
		},
	}
}

// redirectTransport sends every request to the test server, leaving the path,
// query and headers the Google client built untouched.
type redirectTransport struct {
	base *url.URL
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme = t.base.Scheme
	out.URL.Host = t.base.Host
	out.Host = t.base.Host
	return http.DefaultTransport.RoundTrip(out)
}

// testCallbacks is the minimum plugin.ProviderCallback the runtime needs to
// construct resources.
type testCallbacks struct{}

func (p *testCallbacks) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	return &plugin.DataRes{
		Data: &llx.Primitive{Type: string(types.Resource(req.Resource))},
	}, nil
}

func (p *testCallbacks) GetRecording(req *plugin.DataReq) (*plugin.ResourceData, error) {
	return &plugin.ResourceData{}, nil
}

func (p *testCallbacks) Collect(req *plugin.DataRes) error { return nil }

// newTestComputeService builds a gcp.project.computeService with its
// service-enabled gate pre-satisfied.
//
// Compute resolves that gate through an .lr-declared `enabled` field, which
// would otherwise call Service Usage over gRPC -- a transport the HTTP seam
// cannot reach. Setting it directly keeps these tests about the lister.
func newTestComputeService(t *testing.T, env *testEnv) *mqlGcpProjectComputeService {
	t.Helper()

	res, err := CreateResource(env.Runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(testProjectId),
	})
	if err != nil {
		t.Fatalf("create compute service: %v", err)
	}
	svc := res.(*mqlGcpProjectComputeService)
	svc.Enabled = plugin.TValue[bool]{Data: true, State: plugin.StateIsSet}
	return svc
}

// newTestDnsService builds a gcp.project.dnsService with its service-enabled
// gate pre-satisfied through the serviceGate's own record path.
func newTestDnsService(t *testing.T, env *testEnv) *mqlGcpProjectDnsService {
	t.Helper()

	res, err := CreateResource(env.Runtime, "gcp.project.dnsService", map[string]*llx.RawData{
		"projectId": llx.StringData(testProjectId),
	})
	if err != nil {
		t.Fatalf("create dns service: %v", err)
	}
	svc := res.(*mqlGcpProjectDnsService)
	svc.recordEnabled(true)
	return svc
}
