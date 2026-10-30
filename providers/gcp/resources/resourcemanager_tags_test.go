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

func newTestOrganization(env *testEnv, id string) *mqlGcpOrganization {
	return &mqlGcpOrganization{
		MqlRuntime: env.Runtime,
		Id:         plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
	}
}

func newTagsTestEnv(t *testing.T) *testEnv {
	return setupTestEnv(t, []string{cloudresourcemanager.CloudPlatformReadOnlyScope})
}

// Synthetic: the shape of the v3 tagKeys and tagValues responses; the test
// organization had no tags.
func TestOrganizationTagKeysPaginatesAndResolvesValues(t *testing.T) {
	env := newTagsTestEnv(t)
	env.Mux.HandleFunc("/v3/tagKeys", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "organizations/123", r.URL.Query().Get("parent"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("pageToken") == "" {
			fmt.Fprint(w, `{"tagKeys":[{"name":"tagKeys/1","parent":"organizations/123","shortName":"environment",
				"namespacedName":"123/environment","description":"deployment stage",
				"createTime":"2024-05-01T10:00:00Z","updateTime":"2024-06-01T10:00:00Z"}],"nextPageToken":"p2"}`)
			return
		}
		assert.Equal(t, "p2", r.URL.Query().Get("pageToken"))
		fmt.Fprint(w, `{"tagKeys":[{"name":"tagKeys/2","parent":"organizations/123","shortName":"fw",
			"namespacedName":"123/fw","purpose":"GCE_FIREWALL",
			"purposeData":{"network":"https://www.googleapis.com/compute/v1/projects/p/global/networks/default"},
			"createTime":"2024-05-02T10:00:00Z"}]}`)
	})
	env.Mux.HandleFunc("/v3/tagValues", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "tagKeys/1", r.URL.Query().Get("parent"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tagValues":[{"name":"tagValues/10","parent":"tagKeys/1","shortName":"production",
			"namespacedName":"123/environment/production","createTime":"2024-05-01T11:00:00Z"}]}`)
	})

	keys, err := newTestOrganization(env, "organizations/123").tagKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)

	env1 := keys[0].(*mqlGcpOrganizationTagKey)
	assert.Equal(t, "tagKeys/1", env1.Name.Data)
	assert.Equal(t, "environment", env1.ShortName.Data)
	assert.Equal(t, "123/environment", env1.NamespacedName.Data)
	assert.Equal(t, "deployment stage", env1.Description.Data)
	assert.Equal(t, "", env1.Purpose.Data)
	assert.Empty(t, env1.PurposeData.Data)
	require.NotNil(t, env1.UpdateTime.Data)
	assert.Equal(t, 2024, env1.UpdateTime.Data.Year())

	fw := keys[1].(*mqlGcpOrganizationTagKey)
	assert.Equal(t, "GCE_FIREWALL", fw.Purpose.Data)
	assert.Equal(t, "https://www.googleapis.com/compute/v1/projects/p/global/networks/default", fw.PurposeData.Data["network"])
	assert.Nil(t, fw.UpdateTime.Data, "an absent updateTime is null, not year 1")

	values, err := env1.values()
	require.NoError(t, err)
	require.Len(t, values, 1)
	prod := values[0].(*mqlGcpOrganizationTagValue)
	assert.Equal(t, "production", prod.ShortName.Data)
	assert.Equal(t, "123/environment/production", prod.NamespacedName.Data)

	// No handler serves GET /v3/tagKeys/1, so resolving the key through the
	// API would fail: the key listed above must come back from the cache.
	key, err := prod.tagKey()
	require.NoError(t, err)
	assert.Same(t, env1, key)
}

// Synthetic: a tag binding whose value was never listed, resolved by name.
func TestTagBindingValueResolvesByName(t *testing.T) {
	env := newTagsTestEnv(t)
	env.Mux.HandleFunc("/v3/tagValues/456", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"tagValues/456","parent":"tagKeys/9","shortName":"pci","namespacedName":"my-project/scope/pci"}`)
	})
	env.Mux.HandleFunc("/v3/tagKeys/9", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"tagKeys/9","parent":"projects/my-project","shortName":"scope","namespacedName":"my-project/scope"}`)
	})

	binding := &mqlGcpProjectTagBinding{
		MqlRuntime: env.Runtime,
		TagValue:   plugin.TValue[string]{Data: "tagValues/456", State: plugin.StateIsSet},
	}
	value, err := binding.value()
	require.NoError(t, err)
	require.NotNil(t, value)
	assert.Equal(t, "my-project/scope/pci", value.NamespacedName.Data)

	key, err := value.tagKey()
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, "my-project/scope", key.NamespacedName.Data)
}

// Synthetic: a binding without a tag value reads null instead of calling the API.
func TestTagBindingValueNullWithoutTagValue(t *testing.T) {
	env := newTagsTestEnv(t)
	binding := &mqlGcpProjectTagBinding{
		MqlRuntime: env.Runtime,
		TagValue:   plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
	}
	value, err := binding.value()
	require.NoError(t, err)
	assert.Nil(t, value)
	assert.True(t, binding.Value.IsNull())
}

func TestTagKeysRefusals(t *testing.T) {
	cases := []struct {
		name string
		body string
		kind llx.ErrorKind
	}{
		{
			// Measured: GET /v3/tagKeys?parent=organizations/<id> without
			// resourcemanager.tagKeys.list, 2026-10-27.
			name: "permission denied",
			body: `{"error":{"code":403,"message":"Permission 'resourcemanager.tagKeys.list' denied on resource '//cloudresourcemanager.googleapis.com/organizations/1' (or it may not exist).","status":"PERMISSION_DENIED"}}`,
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
			env := newTagsTestEnv(t)
			env.Mux.HandleFunc("/v3/tagKeys", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, tc.body)
			})
			_, err := newTestOrganization(env, "organizations/1").tagKeys()
			require.Error(t, err)
			assert.Equal(t, tc.kind, llx.KindOf(err))
		})
	}
}

// Synthetic: binding conversion edge cases.
func TestPolicyBindings(t *testing.T) {
	env := newTagsTestEnv(t)

	empty, err := policyBindings(env.Runtime, "tagKeys/1", nil)
	require.NoError(t, err)
	assert.Empty(t, empty)

	res, err := policyBindings(env.Runtime, "tagValues/2", &cloudresourcemanager.Policy{
		Bindings: []*cloudresourcemanager.Binding{
			nil,
			{
				Role:    "roles/resourcemanager.tagUser",
				Members: []string{"group:ops@example.com"},
				Condition: &cloudresourcemanager.Expr{
					Title:      "prod only",
					Expression: "request.time < timestamp('2030-01-01T00:00:00Z')",
				},
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, res, 1)
	b := res[0].(*mqlGcpResourcemanagerBinding)
	// The id keeps the binding's position in the policy, so a skipped entry
	// does not shift the ids of the ones after it.
	assert.Equal(t, "tagValues/2-1", b.Id.Data)
	assert.Equal(t, "roles/resourcemanager.tagUser", b.Role.Data)
	assert.Equal(t, []any{"group:ops@example.com"}, b.Members.Data)
	assert.Equal(t, "prod only", b.ConditionTitle.Data)
	assert.Equal(t, "request.time < timestamp('2030-01-01T00:00:00Z')", b.ConditionExpression.Data)
}
