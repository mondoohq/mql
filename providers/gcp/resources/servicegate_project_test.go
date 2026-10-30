// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
)

// seedProjectEndpoint serves the one HTTP call initGcpProject makes, counting
// how many times it is asked.
//
// The service-enablement lookup itself is not driven here: it goes out over
// gRPC to serviceusage, which the HTTP test server cannot intercept. That does
// not matter for what these tests check, because serviceEnabledForInit resolves
// gcp.project *before* it asks about services, so the cache is already in
// whatever state it is going to be in by the time the services call fails.
func seedProjectEndpoint(t *testing.T, env *testEnv) *int {
	t.Helper()
	gets := 0
	env.Mux.HandleFunc("/v3/projects/"+testProjectId, func(w http.ResponseWriter, r *http.Request) {
		gets++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"name": "projects/123456789",
			"projectId": %q,
			"displayName": "Test Project",
			"state": "ACTIVE",
			"parent": "organizations/42",
			"labels": {"env": "test"}
		}`, testProjectId)
	})
	return &gets
}

func projectScopes() []string {
	return []string{
		cloudresourcemanager.CloudPlatformReadOnlyScope,
		iam.CloudPlatformScope,
		compute.CloudPlatformScope,
	}
}

// Asking whether a service is enabled must not leave a husk of gcp.project
// behind for everyone else.
//
// serviceEnabledForInit resolves gcp.project to reach the memoized
// enabled-services map. Building that with CreateResource made a project
// carrying nothing but an id and cached it under that id -- and initGcpProject
// returns whatever is cached, so whichever call arrived first decided what
// every later caller received. The husk never fills itself in: name, state,
// parentId, labels, createTime and number are declared as computed fields but
// implemented as placeholders returning "not implemented", because they are
// meant to be populated by the init.
//
// The order below is the one that breaks: the gate first, the project second.
// A real scan passed only by luck, because discovery happened to resolve the
// project before any gated init ran.
func TestServiceGateDoesNotPoisonTheProjectCache(t *testing.T) {
	env := setupTestEnv(t, projectScopes())
	gets := seedProjectEndpoint(t, env)

	// the gate runs first. Its own answer is not the subject here and needs
	// serviceusage over gRPC, so the error it returns is deliberately ignored;
	// the project has already been resolved and cached by this point.
	_, _ = serviceEnabledForInit(env.Runtime, testProjectId, service_memcache)

	// now resolve the project the way any query would
	res, err := NewResource(env.Runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(testProjectId),
	})
	require.NoError(t, err)
	proj := res.(*mqlGcpProject)

	// the fields the placeholders cannot supply must already be populated
	require.NoError(t, proj.Name.Error)
	assert.Equal(t, "Test Project", proj.Name.Data, "name is empty -- the cache is holding a husk")
	assert.Equal(t, "ACTIVE", proj.State.Data)
	assert.Equal(t, "organizations/42", proj.ParentId.Data)
	assert.Equal(t, "123456789", proj.Number.Data)

	assert.Equal(t, 1, *gets, "gcp.project should be fetched exactly once")
}

// The reverse order has to keep working and must not add a second fetch: the
// project is resolved first, then the gate reuses what is already cached.
func TestServiceGateReusesAnAlreadyResolvedProject(t *testing.T) {
	env := setupTestEnv(t, projectScopes())
	gets := seedProjectEndpoint(t, env)

	res, err := NewResource(env.Runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(testProjectId),
	})
	require.NoError(t, err)
	assert.Equal(t, "Test Project", res.(*mqlGcpProject).Name.Data)

	_, _ = serviceEnabledForInit(env.Runtime, testProjectId, service_memcache)

	assert.Equal(t, 1, *gets, "the gate must reuse the cached project, not refetch it")
}

// An empty project id is reported rather than sent to the API, so a caller that
// could not work one out gets a usable error instead of a confusing 404.
func TestServiceGateRejectsAnEmptyProjectId(t *testing.T) {
	env := setupTestEnv(t, projectScopes())
	gets := seedProjectEndpoint(t, env)

	_, err := serviceEnabledForInit(env.Runtime, "", service_memcache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), service_memcache)
	assert.Equal(t, 0, *gets, "nothing should be fetched without a project id")
}
