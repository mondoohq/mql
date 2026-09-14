// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/weaviate/weaviate-go-client/v5/weaviate/fault"
	"github.com/weaviate/weaviate-go-client/v5/weaviate/rbac"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestModuleNames(t *testing.T) {
	// A decoded module-config object yields its sorted keys.
	got := moduleNames(map[string]any{"text2vec-openai": map[string]any{}, "generative-cohere": nil})
	want := []any{"generative-cohere", "text2vec-openai"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("moduleNames = %v, want %v", got, want)
	}

	// Non-object values yield an empty list, never nil.
	if got := moduleNames(nil); got == nil || len(got) != 0 {
		t.Errorf("moduleNames(nil) = %v, want empty non-nil", got)
	}
	if got := moduleNames("not-a-map"); len(got) != 0 {
		t.Errorf("moduleNames(string) = %v, want empty", got)
	}
}

func TestBuiltinRoles(t *testing.T) {
	for _, name := range []string{"root", "admin", "viewer", "read-only"} {
		if _, ok := builtinRoles[name]; !ok {
			t.Errorf("%q should be a built-in role", name)
		}
	}
	if _, ok := builtinRoles["articleReader"]; ok {
		t.Error("a custom role should not be treated as built-in")
	}
}

func TestIsForbidden(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&fault.WeaviateClientError{StatusCode: 401}, true},
		{&fault.WeaviateClientError{StatusCode: 403}, true},
		{&fault.WeaviateClientError{StatusCode: 404}, false},
		{&fault.WeaviateClientError{StatusCode: 500}, false},
		{errors.New("plain error"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isForbidden(c.err); got != c.want {
			t.Errorf("isForbidden(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestFlattenPermissions(t *testing.T) {
	role := &rbac.Role{
		Name:        "articleReader",
		Data:        []rbac.DataPermission{{Actions: []string{"read_data"}, Collection: "Article"}},
		Collections: []rbac.CollectionsPermission{{Actions: []string{"read_collections"}, Collection: "Article"}},
		Roles:       []rbac.RolesPermission{{Actions: []string{"read_roles", "create_roles"}}},
	}
	got := flattenPermissions(role)
	// One entry per action: 1 data + 1 collections + 2 roles = 4.
	if len(got) != 4 {
		t.Fatalf("flattenPermissions returned %d entries, want 4: %+v", len(got), got)
	}

	// Collection-scoped domains carry the collection; role domain does not.
	byAction := map[string]permEntry{}
	for _, p := range got {
		byAction[p.action] = p
	}
	if byAction["read_data"].collection != "Article" {
		t.Errorf("read_data collection = %q, want Article", byAction["read_data"].collection)
	}
	if byAction["create_roles"].collection != "" {
		t.Errorf("create_roles collection = %q, want empty", byAction["create_roles"].collection)
	}

	// Each entry says which domain it came from.
	if d := byAction["read_data"].domain; d != domainData {
		t.Errorf("read_data domain = %q, want %q", d, domainData)
	}
	if d := byAction["read_collections"].domain; d != domainCollections {
		t.Errorf("read_collections domain = %q, want %q", d, domainCollections)
	}
	if d := byAction["create_roles"].domain; d != domainRoles {
		t.Errorf("create_roles domain = %q, want %q", d, domainRoles)
	}
}

// TestFlattenPermissionsQualifiers pins the qualifier each domain carries. Every
// one of them is read straight off the SDK's typed permission struct, and
// dropping any of them (as the code did for all but Collection) leaves two
// materially different grants looking identical.
func TestFlattenPermissionsQualifiers(t *testing.T) {
	role := &rbac.Role{
		Name:      "mixed",
		Alias:     []rbac.AliasPermission{{Actions: []string{"read_aliases"}, Alias: "ArticleAlias", Collection: "Article"}},
		Backups:   []rbac.BackupsPermission{{Actions: []string{"manage_backups"}, Collection: "Article"}},
		Groups:    []rbac.GroupPermission{{Actions: []string{"read_groups"}, Group: "platform-admins", GroupType: "oidc"}},
		Nodes:     []rbac.NodesPermission{{Actions: []string{"read_nodes"}, Collection: "Article", Verbosity: "verbose"}},
		Replicate: []rbac.ReplicatePermission{{Actions: []string{"create_replicate"}, Collection: "Article", Shard: "shard-1"}},
		Roles:     []rbac.RolesPermission{{Actions: []string{"create_roles"}, Role: "*", Scope: "all"}},
	}
	byAction := map[string]permEntry{}
	for _, p := range flattenPermissions(role) {
		byAction[p.action] = p
	}

	// Scope is the privilege-escalation control: "all" lets the holder grant
	// permissions it does not itself hold.
	if got := derefStr(byAction["create_roles"].scope); got != "all" {
		t.Errorf("create_roles scope = %q, want all", got)
	}
	if got := derefStr(byAction["create_roles"].targetRole); got != "*" {
		t.Errorf("create_roles targetRole = %q, want *", got)
	}
	if got := derefStr(byAction["read_groups"].group); got != "platform-admins" {
		t.Errorf("read_groups group = %q, want platform-admins", got)
	}
	if got := derefStr(byAction["read_groups"].groupType); got != "oidc" {
		t.Errorf("read_groups groupType = %q, want oidc", got)
	}
	if got := derefStr(byAction["read_aliases"].alias); got != "ArticleAlias" {
		t.Errorf("read_aliases alias = %q, want ArticleAlias", got)
	}
	if got := derefStr(byAction["create_replicate"].shard); got != "shard-1" {
		t.Errorf("create_replicate shard = %q, want shard-1", got)
	}
	if got := derefStr(byAction["read_nodes"].verbosity); got != "verbose" {
		t.Errorf("read_nodes verbosity = %q, want verbose", got)
	}

	// The alias, backups, nodes and replicate domains all carry a collection
	// scope that was previously reported as unscoped.
	for _, action := range []string{"read_aliases", "manage_backups", "read_nodes", "create_replicate"} {
		if got := byAction[action].collection; got != "Article" {
			t.Errorf("%s collection = %q, want Article", action, got)
		}
	}

	// A qualifier belonging to another domain is absent, not empty: a data
	// grant says nothing about scope, and must not read as scope "".
	dataOnly := flattenPermissions(&rbac.Role{
		Data: []rbac.DataPermission{{Actions: []string{"read_data"}, Collection: "Article"}},
	})
	if len(dataOnly) != 1 {
		t.Fatalf("want one data entry, got %d", len(dataOnly))
	}
	for name, ptr := range map[string]*string{
		"scope": dataOnly[0].scope, "targetRole": dataOnly[0].targetRole,
		"group": dataOnly[0].group, "groupType": dataOnly[0].groupType,
		"alias": dataOnly[0].alias, "shard": dataOnly[0].shard,
		"verbosity": dataOnly[0].verbosity,
	} {
		if ptr != nil {
			t.Errorf("data permission %s = %q, want absent", name, *ptr)
		}
	}
}

func TestFlattenPermissionsNilRole(t *testing.T) {
	if got := flattenPermissions(nil); got != nil {
		t.Errorf("flattenPermissions(nil) = %v, want nil", got)
	}
}

// TestPermEntryKeyCarriesEveryDimension proves the identity of a permission
// includes its qualifiers. Two create_roles grants that differ only in scope are
// two different grants; a key built from the action alone reports the first
// twice, because CreateResource hands back the cached first instance.
func TestPermEntryKeyCarriesEveryDimension(t *testing.T) {
	role := &rbac.Role{
		Name: "roleManager",
		Roles: []rbac.RolesPermission{
			{Actions: []string{"create_roles"}, Role: "viewer", Scope: "all"},
			{Actions: []string{"create_roles"}, Role: "viewer", Scope: "match"},
		},
	}
	entries := flattenPermissions(role)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if permEntryKey(entries[0]) == permEntryKey(entries[1]) {
		t.Errorf("create_roles scoped all and match share the key %q", permEntryKey(entries[0]))
	}

	// The same holds for the other qualifiers.
	shards := flattenPermissions(&rbac.Role{Replicate: []rbac.ReplicatePermission{
		{Actions: []string{"read_replicate"}, Collection: "Article", Shard: "shard-1"},
		{Actions: []string{"read_replicate"}, Collection: "Article", Shard: "shard-2"},
	}})
	if permEntryKey(shards[0]) == permEntryKey(shards[1]) {
		t.Errorf("two shards share the key %q", permEntryKey(shards[0]))
	}
}

func TestHasPermissions(t *testing.T) {
	// A role reference built from a name alone carries nothing.
	if hasPermissions(&rbac.Role{Name: "viewer"}) {
		t.Error("a name-only role reference has no permissions")
	}
	if hasPermissions(nil) {
		t.Error("a nil role has no permissions")
	}

	// Every one of the twelve permission slices counts. Missing one here means
	// a role holding only that kind of grant is mistaken for a bare reference
	// and gets overwritten by one.
	populated := map[string]*rbac.Role{
		"alias":       {Alias: []rbac.AliasPermission{{Actions: []string{"read_aliases"}}}},
		"backups":     {Backups: []rbac.BackupsPermission{{Actions: []string{"manage_backups"}}}},
		"cluster":     {Cluster: []rbac.ClusterPermission{{Actions: []string{"read_cluster"}}}},
		"collections": {Collections: []rbac.CollectionsPermission{{Actions: []string{"read_collections"}}}},
		"data":        {Data: []rbac.DataPermission{{Actions: []string{"read_data"}}}},
		"groups":      {Groups: []rbac.GroupPermission{{Actions: []string{"read_groups"}}}},
		"mcp":         {MCP: []rbac.MCPPermission{{Actions: []string{"read_mcp"}}}},
		"nodes":       {Nodes: []rbac.NodesPermission{{Actions: []string{"read_nodes"}}}},
		"replicate":   {Replicate: []rbac.ReplicatePermission{{Actions: []string{"read_replicate"}}}},
		"roles":       {Roles: []rbac.RolesPermission{{Actions: []string{"read_roles"}}}},
		"tenants":     {Tenants: []rbac.TenantsPermission{{Actions: []string{"read_tenants"}}}},
		"users":       {Users: []rbac.UsersPermission{{Actions: []string{"read_users"}}}},
	}
	for domain, role := range populated {
		if !hasPermissions(role) {
			t.Errorf("a role holding only %s permissions should count as populated", domain)
		}
	}
}

func testRuntime() *plugin.Runtime {
	// The role cache is reached without touching the connection, so a runtime
	// with no connection is enough to exercise it.
	return plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func permissionActions(t *testing.T, role *mqlWeaviateRole) []string {
	t.Helper()
	list, err := role.permissions()
	if err != nil {
		t.Fatalf("permissions() errored: %v", err)
	}
	actions := make([]string, 0, len(list))
	for _, x := range list {
		actions = append(actions, x.(*mqlWeaviateRolePermission).Action.Data)
	}
	return actions
}

// TestRolePermissionsSurviveNameOnlyReference is the regression test for the
// cache clobber. The user listing hands back roles by name with no permissions,
// and both role objects share one resource id, so whichever arrives second used
// to win. Reporting no permissions is the dangerous direction: an empty list
// satisfies every assertion made about it, so "no role may hold create_roles"
// passed on a server where one did.
func TestRolePermissionsSurviveNameOnlyReference(t *testing.T) {
	const serverID = "http://localhost:8080"
	full := func() *rbac.Role {
		return &rbac.Role{
			Name:  "articleReader",
			Data:  []rbac.DataPermission{{Actions: []string{"read_data"}, Collection: "Article"}},
			Roles: []rbac.RolesPermission{{Actions: []string{"create_roles"}, Role: "*", Scope: "all"}},
		}
	}
	// As users.DB().Lister() builds it: name set, every permission slice nil.
	nameOnly := func() *rbac.Role { return &rbac.Role{Name: "articleReader"} }

	t.Run("full role read first", func(t *testing.T) {
		runtime := testRuntime()
		populated, err := newWeaviateRole(runtime, serverID, full())
		if err != nil {
			t.Fatalf("newWeaviateRole: %v", err)
		}
		fromRef, err := newWeaviateRole(runtime, serverID, nameOnly())
		if err != nil {
			t.Fatalf("newWeaviateRole: %v", err)
		}
		// One role name, one resource: the reference resolves to the same
		// object, which is why the clobber reached the already-read role.
		if populated != fromRef {
			t.Fatal("the same role name should resolve to one resource")
		}
		if got := permissionActions(t, fromRef); len(got) != 2 {
			t.Errorf("permissions = %v, want read_data and create_roles", got)
		}
	})

	t.Run("name-only reference read first", func(t *testing.T) {
		runtime := testRuntime()
		if _, err := newWeaviateRole(runtime, serverID, nameOnly()); err != nil {
			t.Fatalf("newWeaviateRole: %v", err)
		}
		populated, err := newWeaviateRole(runtime, serverID, full())
		if err != nil {
			t.Fatalf("newWeaviateRole: %v", err)
		}
		if got := permissionActions(t, populated); len(got) != 2 {
			t.Errorf("permissions = %v, want read_data and create_roles", got)
		}
	})
}

// TestRolePermissionsAreDistinctResources guards the other half of the id: two
// grants of one action that differ only in a qualifier must not collapse into a
// single permission through the resource cache.
func TestRolePermissionsAreDistinctResources(t *testing.T) {
	runtime := testRuntime()
	role, err := newWeaviateRole(runtime, "http://localhost:8080", &rbac.Role{
		Name: "roleManager",
		Roles: []rbac.RolesPermission{
			{Actions: []string{"create_roles"}, Role: "viewer", Scope: "all"},
			{Actions: []string{"create_roles"}, Role: "viewer", Scope: "match"},
		},
	})
	if err != nil {
		t.Fatalf("newWeaviateRole: %v", err)
	}
	list, err := role.permissions()
	if err != nil {
		t.Fatalf("permissions() errored: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 permissions, got %d", len(list))
	}
	scopes := map[string]bool{}
	for _, x := range list {
		p := x.(*mqlWeaviateRolePermission)
		if p.Scope.State&plugin.StateIsNull != 0 {
			t.Error("a roles permission must report its scope, not null")
			continue
		}
		scopes[p.Scope.Data] = true
	}
	if !scopes["all"] || !scopes["match"] {
		t.Errorf("scopes = %v, want both all and match", scopes)
	}
}

// TestPermissionQualifiersAreNullOffDomain pins null rather than "" for a
// qualifier the domain does not carry, so a policy can tell a data grant from a
// role grant whose scope happens to be blank.
func TestPermissionQualifiersAreNullOffDomain(t *testing.T) {
	runtime := testRuntime()
	role, err := newWeaviateRole(runtime, "http://localhost:8080", &rbac.Role{
		Name: "articleReader",
		Data: []rbac.DataPermission{{Actions: []string{"read_data"}, Collection: "Article"}},
	})
	if err != nil {
		t.Fatalf("newWeaviateRole: %v", err)
	}
	list, err := role.permissions()
	if err != nil {
		t.Fatalf("permissions() errored: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 permission, got %d", len(list))
	}
	p := list[0].(*mqlWeaviateRolePermission)
	for name, tv := range map[string]plugin.TValue[string]{
		"scope": p.Scope, "targetRole": p.TargetRole, "group": p.Group,
		"groupType": p.GroupType, "alias": p.Alias, "shard": p.Shard,
		"verbosity": p.Verbosity,
	} {
		if tv.State&plugin.StateIsNull == 0 {
			t.Errorf("data permission %s = %q, want null", name, tv.Data)
		}
	}
	// The domain and collection it does carry are reported by value.
	if p.Domain.Data != domainData {
		t.Errorf("domain = %q, want %q", p.Domain.Data, domainData)
	}
	if p.Collection.Data != "Article" {
		t.Errorf("collection = %q, want Article", p.Collection.Data)
	}
}

func TestIDBuilders(t *testing.T) {
	const s = "http://localhost:8080"
	cases := map[string]string{
		collectionResourceID(s, "Article"): "http://localhost:8080/collection/Article",
		roleResourceID(s, "viewer"):        "http://localhost:8080/role/viewer",
		userResourceID(s, "root-user"):     "http://localhost:8080/user/root-user",
		nodeResourceID(s, "node1"):         "http://localhost:8080/node/node1",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("id = %q, want %q", got, want)
		}
	}
}
