// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaviate/weaviate-go-client/v5/weaviate/fault"
)

// Synthetic: a GET /v1/authz/roles body shaped after the server's models.Role
// and models.Permission JSON tags; no live server was checked. It holds every
// qualifier the Go client's role type drops (tenant on data and tenants grants,
// collection on tenants grants, the users qualifier), a domain that type does
// not know (namespaces), and one this build has no model for (indices).
const rolesBody = `[
  {
    "name": "tenantReader",
    "permissions": [
      {"action": "read_data", "data": {"collection": "Article", "tenant": "tenantA", "object": "*"}},
      {"action": "read_tenants", "tenants": {"collection": "Article", "tenant": "tenantA"}},
      {"action": "update_users", "users": {"users": "ci-bot"}},
      {"action": "manage_namespaces", "namespaces": {"namespace": "team-a"}},
      {"action": "read_indices", "indices": {"index": "Article"}},
      {"action": "read_cluster"},
      {"action": "create_roles", "roles": {"role": "*", "scope": "all"}, "users": null}
    ]
  },
  {"name": "viewer", "permissions": []}
]`

func TestRoleDecode(t *testing.T) {
	var roles []*Role
	require.NoError(t, json.Unmarshal([]byte(rolesBody), &roles))
	require.Len(t, roles, 2)
	require.Equal(t, "tenantReader", roles[0].Name)
	require.Equal(t, "viewer", roles[1].Name)
	require.Empty(t, roles[1].Permissions)

	perms := roles[0].Permissions
	require.Len(t, perms, 7, "no grant may be dropped")

	data := perms[0]
	require.Equal(t, "read_data", data.ActionName())
	require.NotNil(t, data.Data)
	require.Equal(t, "Article", *data.Data.Collection)
	require.Equal(t, "tenantA", *data.Data.Tenant)
	require.Equal(t, "*", *data.Data.Object)
	require.Equal(t, []string{"data"}, data.QualifierKeys)

	tenants := perms[1]
	require.NotNil(t, tenants.Tenants)
	require.Equal(t, "Article", *tenants.Tenants.Collection)
	require.Equal(t, "tenantA", *tenants.Tenants.Tenant)

	users := perms[2]
	require.NotNil(t, users.Users)
	require.Equal(t, "ci-bot", *users.Users.Users)

	namespaces := perms[3]
	require.NotNil(t, namespaces.Namespaces)
	require.Equal(t, "team-a", *namespaces.Namespaces.Namespace)

	// A qualifier object this build has no model for still names its domain.
	require.Equal(t, "read_indices", perms[4].ActionName())
	require.Equal(t, []string{"indices"}, perms[4].QualifierKeys)

	// A grant with no qualifiers carries no keys.
	require.Equal(t, "read_cluster", perms[5].ActionName())
	require.Empty(t, perms[5].QualifierKeys)

	// A null qualifier is no qualifier.
	require.Equal(t, []string{"roles"}, perms[6].QualifierKeys)
	require.Nil(t, perms[6].Users)
}

func TestPermissionActionNameAbsent(t *testing.T) {
	var p Permission
	require.NoError(t, json.Unmarshal([]byte(`{"data":{"collection":"Article"}}`), &p))
	require.Equal(t, "", p.ActionName())
	require.Equal(t, "", (*Permission)(nil).ActionName())
}

func testServerConnection(t *testing.T, srv *httptest.Server, apiKey string) *WeaviateConnection {
	t.Helper()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	host, portStr, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return &WeaviateConnection{scheme: "http", host: host, port: port, apiKey: apiKey}
}

func TestRolesReadsServerResponseOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "/v1/authz/roles", r.URL.Path)
		assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(rolesBody))
	}))
	defer srv.Close()

	c := testServerConnection(t, srv, "secret")
	roles, err := c.Roles()
	require.NoError(t, err)
	require.Len(t, roles, 2)
	require.Len(t, roles[0].Permissions, 7)

	role, ok := c.RoleByName("tenantReader")
	require.True(t, ok)
	require.Same(t, roles[0], role)
	_, ok = c.RoleByName("missing")
	require.False(t, ok)

	require.Equal(t, int32(1), calls.Load(), "the role list is read once per connection")
}

// A refusal must surface as the Go client's error type, which is what the
// resources classify to decide that role-based access control is enabled but
// the credential cannot read roles.
func TestRolesRefusalKeepsClientErrorType(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":[{"message":"forbidden"}]}`))
	}))
	defer srv.Close()

	c := testServerConnection(t, srv, "")
	_, err := c.Roles()
	require.Error(t, err)
	ce, ok := errors.AsType[*fault.WeaviateClientError](err)
	require.True(t, ok, "want *fault.WeaviateClientError, got %T", err)
	require.Equal(t, http.StatusForbidden, ce.StatusCode)

	// The error is remembered: a second caller costs no request.
	_, err = c.Roles()
	require.Error(t, err)
	_, ok = c.RoleByName("viewer")
	require.False(t, ok)
	require.Equal(t, int32(1), calls.Load())
}

func TestGroupRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/authz/groups/platform admins/roles/oidc", r.URL.Path)
		assert.Equal(t, "true", r.URL.Query().Get("includeFullRoles"))
		_, _ = w.Write([]byte(rolesBody))
	}))
	defer srv.Close()

	c := testServerConnection(t, srv, "")
	roles, err := c.GroupRoles(t.Context(), "oidc", "platform admins")
	require.NoError(t, err)
	require.Len(t, roles, 2)
	require.Equal(t, "tenantA", *roles[0].Permissions[1].Tenants.Tenant)
}
