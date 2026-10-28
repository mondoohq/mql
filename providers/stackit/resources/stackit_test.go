// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/stackit/connection"
	"go.mondoo.com/mql/utils/syncx"
)

const (
	fakeProjectID = "3b2f1a0e-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
	fakeRegion    = "eu01"
)

// fakeAnswer is one canned API response.
type fakeAnswer struct {
	status int
	body   string
}

// fakeAPI serves canned STACKIT API answers keyed by "METHOD /path" and
// counts the requests each route receives. Every service client of the
// connection talks to it, since the endpoint override replaces each service's
// base URL. A request no route answers fails the test.
type fakeAPI struct {
	t      *testing.T
	routes map[string]fakeAnswer
	mu     sync.Mutex
	hits   map[string]int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	f.mu.Lock()
	f.hits[key]++
	f.mu.Unlock()
	a, ok := f.routes[key]
	if !ok {
		f.t.Errorf("unexpected request %s", key)
		w.WriteHeader(http.StatusTeapot)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.status)
	_, _ = w.Write([]byte(a.body))
}

func (f *fakeAPI) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[key]
}

// fakeRuntime starts a fake STACKIT API with the given routes and returns a
// runtime whose connection is scoped to fakeProjectID in fakeRegion.
func fakeRuntime(t *testing.T, routes map[string]fakeAnswer) (*plugin.Runtime, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{t: t, routes: routes, hits: map[string]int{}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	c, err := connection.NewStackitConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OptionProjectID: fakeProjectID,
			connection.OptionRegion:    fakeRegion,
			connection.OptionEndpoint:  srv.URL,
			connection.OptionToken:     "test-token",
		},
	})
	require.NoError(t, err)
	return &plugin.Runtime{Connection: c, Resources: &syncx.Map[plugin.Resource]{}}, api
}

func json200(body string) fakeAnswer { return fakeAnswer{status: http.StatusOK, body: body} }

func jsonStatus(status int) fakeAnswer {
	return fakeAnswer{status: status, body: `{"message":"` + http.StatusText(status) + `"}`}
}

// newProject builds the stackit.project resource the way stackit.project()
// does, without the resource-manager call.
func newProject(t *testing.T, runtime *plugin.Runtime) *mqlStackitProject {
	t.Helper()
	res, err := CreateResource(runtime, "stackit.project", map[string]*llx.RawData{
		"id": llx.StringData(fakeProjectID),
	})
	require.NoError(t, err)
	return res.(*mqlStackitProject)
}

const iaasProjectPath = "GET /v2/projects/" + fakeProjectID

func TestProjectIaasDetails(t *testing.T) {
	// Synthetic: a VPC project with internet access, shaped after the SDK's
	// iaas Project model; no target showed this.
	t.Run("fields read the IaaS project record with one call", func(t *testing.T) {
		runtime, api := fakeRuntime(t, map[string]fakeAnswer{
			iaasProjectPath: json200(`{"areaId":"PUBLIC","id":"` + fakeProjectID + `","status":"CREATED",` +
				`"internetAccess":true,"projectType":"VPC","vpcId":"9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"}`),
		})
		p := newProject(t, runtime)

		ia := p.GetInternetAccess()
		require.NoError(t, ia.Error)
		assert.True(t, ia.Data)
		pt := p.GetProjectType()
		require.NoError(t, pt.Error)
		assert.Equal(t, "VPC", pt.Data)
		vpc := p.GetVpcId()
		require.NoError(t, vpc.Error)
		assert.Equal(t, "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d", vpc.Data)
		assert.Equal(t, 1, api.count(iaasProjectPath), "the three fields share one GetProjectDetails call")
	})

	// Synthetic: a record that omits internetAccess and vpcId.
	t.Run("omitted internetAccess is null, not false", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{
			iaasProjectPath: json200(`{"areaId":"PUBLIC","id":"` + fakeProjectID + `","status":"CREATED","projectType":"Public"}`),
		})
		p := newProject(t, runtime)

		ia := p.GetInternetAccess()
		require.NoError(t, ia.Error)
		assert.True(t, ia.IsNull(), "internetAccess must be null when the record omits it")
		assert.Equal(t, "", p.GetVpcId().Data)
	})

	// Synthetic: a project the IaaS API has no record of.
	t.Run("404 reads as null", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{iaasProjectPath: jsonStatus(http.StatusNotFound)})
		p := newProject(t, runtime)

		pt := p.GetProjectType()
		require.NoError(t, pt.Error)
		assert.True(t, pt.IsNull())
	})

	// Synthetic: a credential without IaaS read access.
	t.Run("403 is a Forbidden error", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{iaasProjectPath: jsonStatus(http.StatusForbidden)})
		p := newProject(t, runtime)

		ia := p.GetInternetAccess()
		require.Error(t, ia.Error)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(ia.Error))
	})
}
