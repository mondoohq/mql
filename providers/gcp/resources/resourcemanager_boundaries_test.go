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
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/cloudresourcemanager/v3"
)

// newBoundariesTestEnv registers the Resource Manager client the boundary
// accessors use and the one initGcpProject uses for managementProject.
func newBoundariesTestEnv(t *testing.T) *testEnv {
	return setupTestEnv(t, []string{cloudresourcemanager.CloudPlatformReadOnlyScope}, projectScopes())
}

func newTestFolder(env *testEnv, id string) *mqlGcpFolder {
	return &mqlGcpFolder{
		MqlRuntime: env.Runtime,
		Id:         plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
	}
}

// Synthetic: the v3 Boundary shape from the API reference; the measured
// organization and folders had no boundaries.
func TestOrganizationBoundariesPaginatesAndDecodes(t *testing.T) {
	env := newBoundariesTestEnv(t)
	env.Mux.HandleFunc("/v3/organizations/123/boundaries", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("pageToken") == "" {
			fmt.Fprint(w, `{"boundaries":[{"name":"organizations/123/boundaries/production",
				"displayName":"Production Boundary","etag":"abc","state":"ACTIVE",
				"managementProject":"projects/987654321",
				"resourceFilter":{"tagFilter":{"tagKey":"123/env","tagValue":"production"}},
				"createTime":"2026-09-01T10:00:00Z","updateTime":"2026-09-02T10:00:00Z"}],
				"nextPageToken":"p2"}`)
			return
		}
		assert.Equal(t, "p2", r.URL.Query().Get("pageToken"))
		fmt.Fprint(w, `{"boundaries":[{"name":"organizations/123/boundaries/new","state":"CREATING",
			"createTime":"2026-10-01T10:00:00Z"}]}`)
	})

	list, err := newTestOrganization(env, "123").boundaries()
	require.NoError(t, err)
	require.Len(t, list, 2)

	prod := list[0].(*mqlGcpResourcemanagerBoundary)
	assert.Equal(t, "organizations/123/boundaries/production", prod.Name.Data)
	assert.Equal(t, "Production Boundary", prod.DisplayName.Data)
	assert.Equal(t, "ACTIVE", prod.State.Data)
	assert.Equal(t, "123/env", prod.TagFilterKey.Data)
	assert.Equal(t, "production", prod.TagFilterValue.Data)
	require.NotNil(t, prod.CreateTime.Data)
	require.NotNil(t, prod.UpdateTime.Data)
	assert.Equal(t, 2, prod.UpdateTime.Data.Day())
	assert.Equal(t, "projects/987654321", prod.cacheManagementProject)

	fresh := list[1].(*mqlGcpResourcemanagerBoundary)
	assert.Equal(t, "CREATING", fresh.State.Data)
	assert.Equal(t, "", fresh.TagFilterKey.Data)
	assert.Equal(t, "", fresh.TagFilterValue.Data)
	assert.Nil(t, fresh.UpdateTime.Data, "an absent updateTime is null, not year 1")
	assert.Equal(t, "", fresh.cacheManagementProject)
}

// Measured: GET /v3/organizations/<id>/boundaries and
// /v3/folders/<id>/boundaries on an organization with no boundaries answered
// 200 with the body `{}`, 2026-10-30.
func TestFolderBoundariesEmpty(t *testing.T) {
	env := newBoundariesTestEnv(t)
	env.Mux.HandleFunc("/v3/folders/456/boundaries", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	list, err := newTestFolder(env, "456").boundaries()
	require.NoError(t, err)
	assert.NotNil(t, list, "no boundaries is an empty list, not null")
	assert.Empty(t, list)
}

// Synthetic: the tag filter names its key and value by namespaced name, which
// resolves through the namespaced lookups.
func TestBoundaryTagFilterResolves(t *testing.T) {
	env := newBoundariesTestEnv(t)
	env.Mux.HandleFunc("/v3/tagKeys/namespaced", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "123/env", r.URL.Query().Get("name"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"tagKeys/1","parent":"organizations/123","shortName":"env","namespacedName":"123/env"}`)
	})
	env.Mux.HandleFunc("/v3/tagValues/namespaced", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "123/env/production", r.URL.Query().Get("name"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"tagValues/10","parent":"tagKeys/1","shortName":"production","namespacedName":"123/env/production"}`)
	})
	env.Mux.HandleFunc("/v3/projects/987654321", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"projects/987654321","projectId":"mgmt-project","state":"ACTIVE"}`)
	})

	b := &mqlGcpResourcemanagerBoundary{
		MqlRuntime:     env.Runtime,
		TagFilterKey:   plugin.TValue[string]{Data: "123/env", State: plugin.StateIsSet},
		TagFilterValue: plugin.TValue[string]{Data: "production", State: plugin.StateIsSet},
	}
	b.cacheManagementProject = "projects/987654321"

	key, err := b.tagKey()
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, "tagKeys/1", key.Name.Data)

	value, err := b.tagValue()
	require.NoError(t, err)
	require.NotNil(t, value)
	assert.Equal(t, "tagValues/10", value.Name.Data)
	assert.Equal(t, "tagKeys/1", value.cacheTagKeyName)

	proj, err := b.managementProject()
	require.NoError(t, err)
	require.NotNil(t, proj)
	assert.Equal(t, "mgmt-project", proj.Id.Data)
	assert.Equal(t, "987654321", proj.Number.Data)
}

// Synthetic: a boundary without a tag filter or management project reads null
// for each reference without calling the API (no handler is registered).
func TestBoundaryReferencesNullWhenAbsent(t *testing.T) {
	env := newBoundariesTestEnv(t)
	b := &mqlGcpResourcemanagerBoundary{
		MqlRuntime:     env.Runtime,
		TagFilterKey:   plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
		TagFilterValue: plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
	}

	key, err := b.tagKey()
	require.NoError(t, err)
	assert.Nil(t, key)
	assert.True(t, b.TagKey.IsNull())

	value, err := b.tagValue()
	require.NoError(t, err)
	assert.Nil(t, value)
	assert.True(t, b.TagValue.IsNull())

	proj, err := b.managementProject()
	require.NoError(t, err)
	assert.Nil(t, proj)
	assert.True(t, b.ManagementProject.IsNull())
}

// Synthetic: namespaced tag value names.
func TestNamespacedTagValueName(t *testing.T) {
	assert.Equal(t, "123/env/production", namespacedTagValueName("123/env", "production"))
	assert.Equal(t, "my-project/env/prod", namespacedTagValueName("my-project/env", "prod"))
	assert.Equal(t, "", namespacedTagValueName("", "production"))
	assert.Equal(t, "", namespacedTagValueName("123/env", ""))
}

func TestBoundariesRefusals(t *testing.T) {
	cases := []struct {
		name string
		body string
		kind llx.ErrorKind
	}{
		{
			// Measured: GET /v3/organizations/<id>/boundaries on an
			// organization where the caller lacks resourcemanager.boundaries.list,
			// 2026-10-30 (ids and troubleshooter URL trimmed).
			name: "permission denied",
			body: `{"error":{"code":403,"message":"Permission 'resourcemanager.boundaries.list' denied on resource '//cloudresourcemanager.googleapis.com/organizations/1' (or it may not exist).","status":"PERMISSION_DENIED"}}`,
			kind: llx.ErrorKind_ERROR_KIND_FORBIDDEN,
		},
		{
			// Synthetic: the Resource Manager API turned off on the quota project.
			name: "api disabled",
			body: `{"error":{"code":403,"message":"Cloud Resource Manager API has not been used in project 1 before or it is disabled.","status":"PERMISSION_DENIED"}}`,
			kind: llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newBoundariesTestEnv(t)
			env.Mux.HandleFunc("/v3/organizations/1/boundaries", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, tc.body)
			})
			_, err := newTestOrganization(env, "1").boundaries()
			require.Error(t, err)
			assert.Equal(t, tc.kind, llx.KindOf(err))
		})
	}
}
