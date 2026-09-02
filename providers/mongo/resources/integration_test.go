// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/mongo/connection"
)

// newIntegrationRuntime connects to a live MongoDB server described by the
// MONGO_TEST_* environment, or skips when it is not configured.
//
//	MONGO_TEST_HOST      host or host:port (default port 27017)
//	MONGO_TEST_USER      user (default "admin")
//	MONGO_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("MONGO_TEST_HOST")
	password := os.Getenv("MONGO_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set MONGO_TEST_HOST and MONGO_TEST_PASSWORD to run mongo integration tests")
	}
	user := os.Getenv("MONGO_TEST_USER")
	if user == "" {
		user = "admin"
	}

	options := map[string]string{}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid MONGO_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "mongo",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewMongoConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustInstance(t *testing.T, runtime *plugin.Runtime) *mqlMongoInstance {
	res, err := NewResource(runtime, "mongo.instance", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve mongo.instance: %v", err)
	}
	return res.(*mqlMongoInstance)
}

func resolveList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Errorf("%s errored: %v", label, tv.Error)
		return nil
	}
	return tv.Data
}

func TestIntegrationInstance(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))
	if v := inst.GetVersion(); v.Error != nil || v.Data == "" {
		t.Errorf("version = %q (err=%v)", v.Data, v.Error)
	}
	// A container started with root credentials has authorization enabled.
	if v := inst.GetAuthenticationEnabled(); v.Error != nil {
		t.Errorf("authenticationEnabled errored: %v", v.Error)
	}
	for _, tv := range []*plugin.TValue[bool]{inst.GetJavascriptEnabled(), inst.GetTlsFIPSMode()} {
		if tv.Error != nil {
			t.Errorf("instance bool field errored: %v", tv.Error)
		}
	}
}

// TestIntegrationResolveAll walks every resource and field getter and asserts
// each resolves without error against a live server.
func TestIntegrationResolveAll(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))

	resolveList(t, "parameters", inst.GetParameters())
	resolveList(t, "databases", inst.GetDatabases())

	for _, x := range resolveList(t, "users", inst.GetUsers()) {
		u := x.(*mqlMongoUser)
		resolveList(t, "user.effectiveRoles", u.GetEffectiveRoles())
		for _, r := range resolveList(t, "user.roles", u.GetRoles()) {
			role := r.(*mqlMongoRole)
			resolveList(t, "role.privileges", role.GetPrivileges())
			resolveList(t, "role.inheritedRoles", role.GetInheritedRoles())
		}
	}
	for _, x := range resolveList(t, "roles", inst.GetRoles()) {
		role := x.(*mqlMongoRole)
		resolveList(t, "role.privileges", role.GetPrivileges())
		resolveList(t, "role.inheritedRoles", role.GetInheritedRoles())
	}
}

// TestIntegrationSeededFixtures verifies values from testdata/seed.js.
// Enable it with MONGO_TEST_SEEDED=1 after loading the seed.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("MONGO_TEST_SEEDED") == "" {
		t.Skip("set MONGO_TEST_SEEDED=1 after loading testdata/seed.js")
	}
	inst := mustInstance(t, newIntegrationRuntime(t))

	users := map[string]*mqlMongoUser{}
	for _, x := range inst.GetUsers().Data {
		u := x.(*mqlMongoUser)
		users[u.GetUser().Data] = u
	}

	// low-privilege app user with the custom role, not flagged privileged
	appuser := users["appuser"]
	if appuser == nil {
		t.Fatal("appuser not found")
	}
	if appuser.GetIsPrivileged().Data {
		t.Error("appuser should not be flagged privileged")
	}
	var appRole *mqlMongoRole
	for _, r := range appuser.GetRoles().Data {
		if role := r.(*mqlMongoRole); role.GetRole().Data == "appReadMetrics" {
			appRole = role
		}
	}
	if appRole == nil {
		t.Fatal("appuser should hold appReadMetrics")
	}
	if appRole.GetIsBuiltin().Data {
		t.Error("appReadMetrics is a custom role, not built-in")
	}
	// custom role's privilege + inherited built-in role resolve
	if len(appRole.GetPrivileges().Data) == 0 {
		t.Error("appReadMetrics should have at least one privilege")
	}
	inheritsRead := false
	for _, ir := range appRole.GetInheritedRoles().Data {
		if ir.(*mqlMongoRole).GetRole().Data == "read" {
			inheritsRead = true
		}
	}
	if !inheritsRead {
		t.Error("appReadMetrics should inherit the read role")
	}

	// instance.roles must include the custom role even though appdb holds no
	// data and is therefore absent from listDatabases (regression guard for the
	// admin.system.roles union).
	foundAppRole := false
	for _, x := range inst.GetRoles().Data {
		role := x.(*mqlMongoRole)
		if role.GetRole().Data == "appReadMetrics" && role.GetDb().Data == "appdb" {
			foundAppRole = true
		}
	}
	if !foundAppRole {
		t.Error("instance.roles should include appReadMetrics@appdb from admin.system.roles")
	}

	// appuser's effective roles expand the custom role into the read role it
	// inherits, and neither is privileged.
	if !hasEffectiveRole(appuser, "read") {
		t.Error("appuser effectiveRoles should include the inherited read role")
	}

	// high-privilege user flagged
	opsadmin := users["opsadmin"]
	if opsadmin == nil {
		t.Fatal("opsadmin not found")
	}
	if !opsadmin.GetIsPrivileged().Data {
		t.Error("opsadmin holds readWriteAnyDatabase and should be flagged privileged")
	}

	// Users whose only grant is a custom role that inherits a superuser role
	// must be flagged too: one level of indirection for metricsbot, two for
	// supportbot. Neither has a privileged role written on the account.
	for _, name := range []string{"metricsbot", "supportbot"} {
		u := users[name]
		if u == nil {
			t.Fatalf("%s not found", name)
		}
		for _, r := range u.GetRoles().Data {
			if _, priv := privilegedRoles[r.(*mqlMongoRole).GetRole().Data]; priv {
				t.Fatalf("%s fixture is wrong: it holds a privileged role directly", name)
			}
		}
		if !u.GetIsPrivileged().Data {
			t.Errorf("%s inherits userAdminAnyDatabase and should be flagged privileged", name)
		}
		if !hasEffectiveRole(u, "userAdminAnyDatabase") {
			t.Errorf("%s effectiveRoles should include the inherited userAdminAnyDatabase", name)
		}
	}
}

func hasEffectiveRole(u *mqlMongoUser, name string) bool {
	for _, r := range u.GetEffectiveRoles().Data {
		if r.(*mqlMongoRole).GetRole().Data == name {
			return true
		}
	}
	return false
}
