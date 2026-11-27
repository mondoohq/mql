// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/weaviate/weaviate-go-client/v5/weaviate/fault"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/weaviate/connection"
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

// testRole decodes a role the way the server sends it in GET /v1/authz/roles:
// a name and a list of grants, each an action plus, under the key naming its
// domain, the qualifiers that limit it. Building roles from that JSON rather
// than from Go literals keeps the tests on the path the provider reads.
func testRole(t *testing.T, name, permissions string) *connection.Role {
	t.Helper()
	var role connection.Role
	body := `{"name":` + jsonString(t, name) + `,"permissions":` + permissions + `}`
	if err := json.Unmarshal([]byte(body), &role); err != nil {
		t.Fatalf("decoding role %s: %v", body, err)
	}
	return &role
}

func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("encoding %q: %v", s, err)
	}
	return string(b)
}

func byAction(entries []permEntry) map[string]permEntry {
	out := map[string]permEntry{}
	for _, p := range entries {
		out[p.action] = p
	}
	return out
}

// Synthetic: the JSON shape follows the server's models.Permission; no live
// server was checked.
func TestFlattenPermissions(t *testing.T) {
	role := testRole(t, "articleReader", `[
		{"action":"read_data","data":{"collection":"Article","tenant":"*","object":"*"}},
		{"action":"read_collections","collections":{"collection":"Article"}},
		{"action":"read_roles","roles":{"role":"*","scope":"match"}},
		{"action":"create_roles","roles":{"role":"*","scope":"match"}}
	]`)
	got := flattenPermissions(role)
	// One entry per action: 1 data + 1 collections + 2 roles = 4.
	if len(got) != 4 {
		t.Fatalf("flattenPermissions returned %d entries, want 4: %+v", len(got), got)
	}

	// Collection-scoped domains carry the collection; role domain does not.
	actions := byAction(got)
	if actions["read_data"].collection != "Article" {
		t.Errorf("read_data collection = %q, want Article", actions["read_data"].collection)
	}
	if actions["create_roles"].collection != "" {
		t.Errorf("create_roles collection = %q, want empty", actions["create_roles"].collection)
	}

	// Each entry says which domain it came from.
	if d := actions["read_data"].domain; d != domainData {
		t.Errorf("read_data domain = %q, want %q", d, domainData)
	}
	if d := actions["read_collections"].domain; d != domainCollections {
		t.Errorf("read_collections domain = %q, want %q", d, domainCollections)
	}
	if d := actions["create_roles"].domain; d != domainRoles {
		t.Errorf("create_roles domain = %q, want %q", d, domainRoles)
	}
}

// TestFlattenPermissionsQualifiers pins the qualifier each domain carries.
// Dropping any of them leaves two materially different grants looking
// identical.
//
// Synthetic: the JSON shape follows the server's models.Permission; no live
// server was checked.
func TestFlattenPermissionsQualifiers(t *testing.T) {
	role := testRole(t, "mixed", `[
		{"action":"read_aliases","aliases":{"alias":"ArticleAlias","collection":"Article"}},
		{"action":"manage_backups","backups":{"collection":"Article"}},
		{"action":"read_groups","groups":{"group":"platform-admins","groupType":"oidc"}},
		{"action":"read_nodes","nodes":{"collection":"Article","verbosity":"verbose"}},
		{"action":"create_replicate","replicate":{"collection":"Article","shard":"shard-1"}},
		{"action":"create_roles","roles":{"role":"*","scope":"all"}}
	]`)
	actions := byAction(flattenPermissions(role))

	// Scope is the privilege-escalation control: "all" lets the holder grant
	// permissions it does not itself hold.
	if got := derefStr(actions["create_roles"].scope); got != "all" {
		t.Errorf("create_roles scope = %q, want all", got)
	}
	if got := derefStr(actions["create_roles"].targetRole); got != "*" {
		t.Errorf("create_roles targetRole = %q, want *", got)
	}
	if got := derefStr(actions["read_groups"].group); got != "platform-admins" {
		t.Errorf("read_groups group = %q, want platform-admins", got)
	}
	if got := derefStr(actions["read_groups"].groupType); got != "oidc" {
		t.Errorf("read_groups groupType = %q, want oidc", got)
	}
	if got := derefStr(actions["read_aliases"].alias); got != "ArticleAlias" {
		t.Errorf("read_aliases alias = %q, want ArticleAlias", got)
	}
	if got := derefStr(actions["create_replicate"].shard); got != "shard-1" {
		t.Errorf("create_replicate shard = %q, want shard-1", got)
	}
	if got := derefStr(actions["read_nodes"].verbosity); got != "verbose" {
		t.Errorf("read_nodes verbosity = %q, want verbose", got)
	}
	if got := actions["read_aliases"].domain; got != domainAlias {
		t.Errorf("read_aliases domain = %q, want %q", got, domainAlias)
	}

	// The alias, backups, nodes and replicate domains all carry a collection
	// scope that was previously reported as unscoped.
	for _, action := range []string{"read_aliases", "manage_backups", "read_nodes", "create_replicate"} {
		if got := actions[action].collection; got != "Article" {
			t.Errorf("%s collection = %q, want Article", action, got)
		}
	}

	// A qualifier belonging to another domain is absent, not empty: a data
	// grant says nothing about scope, and must not read as scope "".
	dataOnly := flattenPermissions(testRole(t, "articleReader",
		`[{"action":"read_data","data":{"collection":"Article"}}]`))
	if len(dataOnly) != 1 {
		t.Fatalf("want one data entry, got %d", len(dataOnly))
	}
	for name, ptr := range map[string]*string{
		"scope": dataOnly[0].scope, "targetRole": dataOnly[0].targetRole,
		"group": dataOnly[0].group, "groupType": dataOnly[0].groupType,
		"alias": dataOnly[0].alias, "shard": dataOnly[0].shard,
		"verbosity": dataOnly[0].verbosity, "targetUser": dataOnly[0].targetUser,
		"namespace": dataOnly[0].namespace,
	} {
		if ptr != nil {
			t.Errorf("data permission %s = %q, want absent", name, *ptr)
		}
	}
}

// TestFlattenPermissionsTenantQualifiers is the regression test for grants
// scoped to a tenant. The Go client's role type kept no tenant at all, so
// read_data on one tenant of Article read as read_data on every tenant, and a
// tenants grant lost its collection too and read as global.
//
// Synthetic: the JSON shape follows the server's models.PermissionData and
// models.PermissionTenants; no live server was checked.
func TestFlattenPermissionsTenantQualifiers(t *testing.T) {
	role := testRole(t, "tenantA", `[
		{"action":"read_data","data":{"collection":"Article","tenant":"tenantA","object":"*"}},
		{"action":"read_tenants","tenants":{"collection":"Article","tenant":"tenantA"}}
	]`)
	actions := byAction(flattenPermissions(role))

	data := actions["read_data"]
	if data.collection != "Article" || derefStr(data.tenant) != "tenantA" {
		t.Errorf("read_data collection/tenant = %q/%q, want Article/tenantA", data.collection, derefStr(data.tenant))
	}
	if data.object == nil || *data.object != "*" {
		t.Errorf("read_data object = %v, want *", data.object)
	}

	tenants := actions["read_tenants"]
	if tenants.domain != domainTenants {
		t.Errorf("read_tenants domain = %q, want %q", tenants.domain, domainTenants)
	}
	if tenants.collection != "Article" || derefStr(tenants.tenant) != "tenantA" {
		t.Errorf("read_tenants collection/tenant = %q/%q, want Article/tenantA", tenants.collection, derefStr(tenants.tenant))
	}
	// A tenants grant carries no object.
	if tenants.object != nil {
		t.Errorf("read_tenants object = %q, want absent", *tenants.object)
	}
}

// TestFlattenPermissionsUsersQualifier: the Go client's users permission kept
// only the action, so a grant over one named user read as a grant over all.
//
// Synthetic: the JSON shape follows the server's models.PermissionUsers; no
// live server was checked.
func TestFlattenPermissionsUsersQualifier(t *testing.T) {
	role := testRole(t, "userManager", `[
		{"action":"update_users","users":{"users":"ci-bot"}},
		{"action":"read_users","users":{"users":"*"}}
	]`)
	actions := byAction(flattenPermissions(role))
	if got := actions["update_users"]; got.domain != domainUsers || derefStr(got.targetUser) != "ci-bot" {
		t.Errorf("update_users domain/targetUser = %q/%q, want users/ci-bot", got.domain, derefStr(got.targetUser))
	}
	if got := derefStr(actions["read_users"].targetUser); got != "*" {
		t.Errorf("read_users targetUser = %q, want *", got)
	}
}

// TestPermissionDomain covers the grants the Go client either recognized by
// action name alone or dropped. The domain values it did report must not
// change, and a domain it did not know must still be reported.
//
// Synthetic: the JSON shape follows the server's models.Permission; no live
// server was checked.
func TestPermissionDomain(t *testing.T) {
	role := testRole(t, "mixed", `[
		{"action":"read_cluster"},
		{"action":"read_mcp"},
		{"action":"read_tenants"},
		{"action":"assign_and_revoke_users"},
		{"action":"read_aliases"},
		{"action":"manage_namespaces","namespaces":{"namespace":"team-a"}},
		{"action":"read_index_stats","indices":{"index":"Article"}},
		{"action":"manage_widgets"}
	]`)
	entries := flattenPermissions(role)
	if len(entries) != 8 {
		t.Fatalf("want 8 entries, one per grant, got %d: %+v", len(entries), entries)
	}
	want := map[string]string{
		"read_cluster":            domainCluster,
		"read_mcp":                domainMCP,
		"read_tenants":            domainTenants,
		"assign_and_revoke_users": domainUsers,
		"read_aliases":            domainAlias,
		"manage_namespaces":       domainNamespaces,
		// Domains this build has no model for: named by the server's key when
		// it sent qualifiers, by the action otherwise.
		"read_index_stats": "indices",
		"manage_widgets":   "widgets",
	}
	actions := byAction(entries)
	for action, domain := range want {
		if got := actions[action].domain; got != domain {
			t.Errorf("%s domain = %q, want %q", action, got, domain)
		}
	}
	if got := derefStr(actions["manage_namespaces"].namespace); got != "team-a" {
		t.Errorf("manage_namespaces namespace = %q, want team-a", got)
	}
	// A tenants or users grant without its qualifier object says nothing about
	// which tenant or user, so the qualifier stays null rather than "".
	if actions["read_tenants"].tenant != nil || actions["assign_and_revoke_users"].targetUser != nil {
		t.Error("a grant sent without qualifiers must report them as null")
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
//
// Synthetic: the JSON shape follows the server's models.Permission; no live
// server was checked.
func TestPermEntryKeyCarriesEveryDimension(t *testing.T) {
	entries := flattenPermissions(testRole(t, "roleManager", `[
		{"action":"create_roles","roles":{"role":"viewer","scope":"all"}},
		{"action":"create_roles","roles":{"role":"viewer","scope":"match"}}
	]`))
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if permEntryKey(entries[0]) == permEntryKey(entries[1]) {
		t.Errorf("create_roles scoped all and match share the key %q", permEntryKey(entries[0]))
	}

	// The same holds for the other qualifiers.
	for name, perms := range map[string]string{
		"shard": `[{"action":"read_replicate","replicate":{"collection":"Article","shard":"shard-1"}},
			{"action":"read_replicate","replicate":{"collection":"Article","shard":"shard-2"}}]`,
		"data tenant": `[{"action":"read_data","data":{"collection":"Article","tenant":"tenantA"}},
			{"action":"read_data","data":{"collection":"Article","tenant":"tenantB"}}]`,
		"tenants tenant": `[{"action":"read_tenants","tenants":{"collection":"Article","tenant":"tenantA"}},
			{"action":"read_tenants","tenants":{"collection":"Article","tenant":"tenantB"}}]`,
		"object": `[{"action":"read_data","data":{"collection":"Article","object":"a"}},
			{"action":"read_data","data":{"collection":"Article","object":"b"}}]`,
		"target user": `[{"action":"update_users","users":{"users":"alice"}},
			{"action":"update_users","users":{"users":"bob"}}]`,
		"namespace": `[{"action":"manage_namespaces","namespaces":{"namespace":"a"}},
			{"action":"manage_namespaces","namespaces":{"namespace":"b"}}]`,
	} {
		pair := flattenPermissions(testRole(t, "r", perms))
		if len(pair) != 2 {
			t.Fatalf("%s: want 2 entries, got %d", name, len(pair))
		}
		if permEntryKey(pair[0]) == permEntryKey(pair[1]) {
			t.Errorf("two grants differing only by %s share the key %q", name, permEntryKey(pair[0]))
		}
	}
}

func TestHasPermissions(t *testing.T) {
	// A role reference built from a name alone carries nothing.
	if hasPermissions(&connection.Role{Name: "viewer"}) {
		t.Error("a name-only role reference has no permissions")
	}
	if hasPermissions(nil) {
		t.Error("a nil role has no permissions")
	}
	// A grant with no qualifiers at all still counts. Missing it means a role
	// holding only that kind of grant is mistaken for a bare reference and
	// gets overwritten by one.
	if !hasPermissions(testRole(t, "clusterReader", `[{"action":"read_cluster"}]`)) {
		t.Error("a role holding only a cluster grant should count as populated")
	}
}

func testRuntime() *plugin.Runtime {
	// The role cache is reached without touching the connection, so a runtime
	// with no connection is enough to exercise it.
	return plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func permissionList(t *testing.T, role *mqlWeaviateRole) []*mqlWeaviateRolePermission {
	t.Helper()
	list, err := role.permissions()
	if err != nil {
		t.Fatalf("permissions() errored: %v", err)
	}
	out := make([]*mqlWeaviateRolePermission, 0, len(list))
	for _, x := range list {
		out = append(out, x.(*mqlWeaviateRolePermission))
	}
	return out
}

func permissionActions(t *testing.T, role *mqlWeaviateRole) []string {
	t.Helper()
	perms := permissionList(t, role)
	actions := make([]string, 0, len(perms))
	for _, p := range perms {
		actions = append(actions, p.Action.Data)
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
	full := func() *connection.Role {
		return testRole(t, "articleReader", `[
			{"action":"read_data","data":{"collection":"Article"}},
			{"action":"create_roles","roles":{"role":"*","scope":"all"}}
		]`)
	}
	// As the user listing names it: a name and no permissions.
	nameOnly := func() *connection.Role { return &connection.Role{Name: "articleReader"} }

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

// TestResolveRoleFallsBackWhenRolesUnreadable exercises the degraded path,
// which no happy-path test reaches. A credential that may list users but not
// roles keeps the role's name rather than losing the role altogether, so the
// lookup has to hand back a bare reference when it cannot answer.
func TestResolveRoleFallsBackWhenRolesUnreadable(t *testing.T) {
	// Port 1 on loopback refuses immediately, which is the cheapest stand-in
	// for a role list this connection cannot read.
	conf := &inventory.Config{
		Type:    "weaviate",
		Options: map[string]string{"host": "127.0.0.1", "port": "1"},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewWeaviateConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("building the connection: %v", err)
	}
	if _, ok := conn.RoleByName("articleReader"); ok {
		t.Fatal("an unreadable role list should resolve nothing")
	}

	runtime := plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
	got := resolveRole(runtime, "articleReader")
	if got == nil || got.Name != "articleReader" || hasPermissions(got) {
		t.Errorf("resolveRole = %+v, want a bare reference named articleReader", got)
	}
}

// TestRolePermissionsAreDistinctResources guards the other half of the id: two
// grants of one action that differ only in a qualifier must not collapse into a
// single permission through the resource cache.
//
// Synthetic: the JSON shape follows the server's models.Permission; no live
// server was checked.
func TestRolePermissionsAreDistinctResources(t *testing.T) {
	runtime := testRuntime()
	role, err := newWeaviateRole(runtime, "http://localhost:8080", testRole(t, "roleManager", `[
		{"action":"create_roles","roles":{"role":"viewer","scope":"all"}},
		{"action":"create_roles","roles":{"role":"viewer","scope":"match"}}
	]`))
	if err != nil {
		t.Fatalf("newWeaviateRole: %v", err)
	}
	list := permissionList(t, role)
	if len(list) != 2 {
		t.Fatalf("want 2 permissions, got %d", len(list))
	}
	scopes := map[string]bool{}
	for _, p := range list {
		if p.Scope.State&plugin.StateIsNull != 0 {
			t.Error("a roles permission must report its scope, not null")
			continue
		}
		scopes[p.Scope.Data] = true
	}
	if !scopes["all"] || !scopes["match"] {
		t.Errorf("scopes = %v, want both all and match", scopes)
	}

	// Two tenants of one collection are two permission resources, each
	// reporting its own tenant.
	tenantRole, err := newWeaviateRole(runtime, "http://localhost:8080", testRole(t, "twoTenants", `[
		{"action":"read_data","data":{"collection":"Article","tenant":"tenantA"}},
		{"action":"read_data","data":{"collection":"Article","tenant":"tenantB"}}
	]`))
	if err != nil {
		t.Fatalf("newWeaviateRole: %v", err)
	}
	tenants := map[string]bool{}
	for _, p := range permissionList(t, tenantRole) {
		tenants[p.Tenant.Data] = true
	}
	if !tenants["tenantA"] || !tenants["tenantB"] {
		t.Errorf("tenants = %v, want both tenantA and tenantB", tenants)
	}
}

// TestPermissionQualifiersAreNullOffDomain pins null rather than "" for a
// qualifier the domain does not carry, so a policy can tell a data grant from a
// role grant whose scope happens to be blank.
//
// Synthetic: the JSON shape follows the server's models.Permission; no live
// server was checked.
func TestPermissionQualifiersAreNullOffDomain(t *testing.T) {
	runtime := testRuntime()
	role, err := newWeaviateRole(runtime, "http://localhost:8080", testRole(t, "articleReader",
		`[{"action":"read_data","data":{"collection":"Article","tenant":"tenantA"}}]`))
	if err != nil {
		t.Fatalf("newWeaviateRole: %v", err)
	}
	list := permissionList(t, role)
	if len(list) != 1 {
		t.Fatalf("want 1 permission, got %d", len(list))
	}
	p := list[0]
	for name, tv := range map[string]plugin.TValue[string]{
		"scope": p.Scope, "targetRole": p.TargetRole, "group": p.Group,
		"groupType": p.GroupType, "alias": p.Alias, "shard": p.Shard,
		"verbosity": p.Verbosity, "targetUser": p.TargetUser, "namespace": p.Namespace,
	} {
		if tv.State&plugin.StateIsNull == 0 {
			t.Errorf("data permission %s = %q, want null", name, tv.Data)
		}
	}
	// The domain, collection and tenant it does carry are reported by value.
	if p.Domain.Data != domainData {
		t.Errorf("domain = %q, want %q", p.Domain.Data, domainData)
	}
	if p.Collection.Data != "Article" {
		t.Errorf("collection = %q, want Article", p.Collection.Data)
	}
	if p.Tenant.State&plugin.StateIsNull != 0 || p.Tenant.Data != "tenantA" {
		t.Errorf("tenant = %q (null: %v), want tenantA", p.Tenant.Data, p.Tenant.State&plugin.StateIsNull != 0)
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&fault.WeaviateClientError{StatusCode: 404}, true},
		{&fault.WeaviateClientError{StatusCode: 403}, false},
		{&fault.WeaviateClientError{StatusCode: 500}, false},
		{errors.New("plain error"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isNotFound(c.err); got != c.want {
			t.Errorf("isNotFound(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// TestNonZeroTime pins null rather than year 1 for a timestamp the server did
// not report. A live 1.38.9 sends a never-used API key back as
// "lastUsedAt":"0001-01-01T00:00:00.000Z", which the client decodes to the zero
// time, so reporting it by value would date every unused key to January of the
// year 1 and make "not used in 90 days" true for a key issued this morning.
func TestNonZeroTime(t *testing.T) {
	if got := nonZeroTime(time.Time{}); got != nil {
		t.Errorf("nonZeroTime(zero) = %v, want nil", got)
	}
	// The zero value of the wire format decodes to the same zero time.
	wire, err := time.Parse(time.RFC3339, "0001-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatalf("parsing the wire zero: %v", err)
	}
	if got := nonZeroTime(wire); got != nil {
		t.Errorf("nonZeroTime(%v) = %v, want nil", wire, got)
	}

	real := time.Date(2026, 9, 14, 20, 28, 8, 0, time.UTC)
	got := nonZeroTime(real)
	if got == nil || !got.Equal(real) {
		t.Errorf("nonZeroTime(%v) = %v, want the same instant", real, got)
	}
}

// TestGroupResourceIDCarriesGroupType guards the second identity dimension. One
// group name can belong to two kinds of group, and an id built from the name
// alone makes the second resolve to the first through the resource cache.
func TestGroupResourceIDCarriesGroupType(t *testing.T) {
	const s = "http://localhost:8080"
	oidc := groupResourceID(s, "oidc", "platform-admins")
	other := groupResourceID(s, "db", "platform-admins")
	if oidc == other {
		t.Errorf("two kinds of group named platform-admins share the id %q", oidc)
	}
	if oidc != "http://localhost:8080/group/oidc/platform-admins" {
		t.Errorf("id = %q", oidc)
	}
}

// TestGroupsOfDifferentTypesAreDistinctResources is the same guarantee one
// level up: the ids have to keep the two groups apart in the resource cache.
func TestGroupsOfDifferentTypesAreDistinctResources(t *testing.T) {
	runtime := testRuntime()
	const serverID = "http://localhost:8080"
	oidc, err := newWeaviateGroup(runtime, serverID, "platform-admins", groupTypeOIDC)
	if err != nil {
		t.Fatalf("newWeaviateGroup: %v", err)
	}
	other, err := newWeaviateGroup(runtime, serverID, "platform-admins", "db")
	if err != nil {
		t.Fatalf("newWeaviateGroup: %v", err)
	}
	if oidc == other {
		t.Fatal("two kinds of group named platform-admins resolved to one resource")
	}
	if oidc.GroupType.Data != groupTypeOIDC || other.GroupType.Data != "db" {
		t.Errorf("groupType = %q and %q", oidc.GroupType.Data, other.GroupType.Data)
	}
	// The same group asked for twice is one resource, which is what makes the
	// dedup in assignedGroups necessary rather than cosmetic.
	again, err := newWeaviateGroup(runtime, serverID, "platform-admins", groupTypeOIDC)
	if err != nil {
		t.Fatalf("newWeaviateGroup: %v", err)
	}
	if again != oidc {
		t.Error("one group should resolve to one resource")
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
