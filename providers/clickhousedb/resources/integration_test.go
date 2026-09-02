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
	"go.mondoo.com/mql/providers/clickhousedb/connection"
)

// newIntegrationRuntime connects to a live ClickHouse server described by the
// CLICKHOUSE_TEST_* environment, or skips when it is not configured.
//
//	CLICKHOUSE_TEST_HOST      host or host:port (default port 9000)
//	CLICKHOUSE_TEST_USER      user (default "default")
//	CLICKHOUSE_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("CLICKHOUSE_TEST_HOST")
	password := os.Getenv("CLICKHOUSE_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set CLICKHOUSE_TEST_HOST and CLICKHOUSE_TEST_PASSWORD to run clickhousedb integration tests")
	}
	user := os.Getenv("CLICKHOUSE_TEST_USER")
	if user == "" {
		user = "default"
	}

	options := map[string]string{}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid CLICKHOUSE_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "clickhousedb",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewClickhousedbConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustInstance(t *testing.T, runtime *plugin.Runtime) *mqlClickhousedbInstance {
	res, err := NewResource(runtime, "clickhousedb.instance", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve clickhousedb.instance: %v", err)
	}
	return res.(*mqlClickhousedbInstance)
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
}

// TestIntegrationResolveAll walks every resource and field getter.
func TestIntegrationResolveAll(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))

	if s := resolveList(t, "serverSettings", inst.GetServerSettings()); len(s) == 0 {
		t.Error("expected at least one server setting")
	}
	resolveList(t, "settingsProfiles", inst.GetSettingsProfiles())
	resolveList(t, "quotas", inst.GetQuotas())
	resolveList(t, "clusters", inst.GetClusters())

	for _, x := range resolveList(t, "roles", inst.GetRoles()) {
		r := x.(*mqlClickhousedbRole)
		if v := r.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("role.name = %q (err=%v)", v.Data, v.Error)
		}
		resolveList(t, "role.grants", r.GetGrants())
	}

	users := resolveList(t, "users", inst.GetUsers())
	if len(users) == 0 {
		t.Error("expected at least one user")
	}
	for _, x := range users {
		u := x.(*mqlClickhousedbUser)
		if v := u.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("user.name = %q (err=%v)", v.Data, v.Error)
		}
		resolveList(t, "user.grants", u.GetGrants())
	}
}

// TestIntegrationSeededFixtures verifies the fixtures from testdata/seed.sql.
// Enable it with CLICKHOUSE_TEST_SEEDED=1 after running the seed.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("CLICKHOUSE_TEST_SEEDED") == "" {
		t.Skip("set CLICKHOUSE_TEST_SEEDED=1 after running testdata/seed.sql")
	}
	inst := mustInstance(t, newIntegrationRuntime(t))

	users := map[string]*mqlClickhousedbUser{}
	for _, x := range inst.GetUsers().Data {
		u := x.(*mqlClickhousedbUser)
		users[u.GetName().Data] = u
	}

	// The seeded weakuser can log in without a password.
	weak := users["weakuser"]
	if weak == nil {
		t.Fatal("seeded weakuser not found")
	}
	if weak.GetHasPassword().Data {
		t.Error("weakuser should have no password")
	}

	// The seeded appuser is restricted to a host range (not any host).
	app := users["appuser"]
	if app == nil {
		t.Fatal("seeded appuser not found")
	}
	if app.GetAnyHost().Data {
		t.Error("appuser should be host-restricted, not any-host")
	}
	if v := app.GetHostIps(); len(v.Data) == 0 {
		t.Errorf("appuser.hostIps = %v (err=%v), want the seeded range", v.Data, v.Error)
	}

	// The seeded openregexpuser is pinned to one IP address but also carries a
	// host name expression matching every name, so it is reachable from
	// anywhere. Reading host_ip alone reported it as restricted.
	open := users["openregexpuser"]
	if open == nil {
		t.Fatal("seeded openregexpuser not found")
	}
	if v := open.GetHostNamesRegexp(); len(v.Data) == 0 {
		t.Errorf("openregexpuser.hostNamesRegexp = %v (err=%v), want the seeded expression", v.Data, v.Error)
	}
	if !open.GetAnyHost().Data {
		t.Error("openregexpuser should be any-host: its host name expression matches every name")
	}

	// The seeded analyst role holds a broad SELECT grant.
	var analyst *mqlClickhousedbRole
	for _, x := range inst.GetRoles().Data {
		if r := x.(*mqlClickhousedbRole); r.GetName().Data == "analyst" {
			analyst = r
		}
	}
	if analyst == nil {
		t.Fatal("seeded analyst role not found")
	}
	hasBroad := false
	for _, g := range analyst.GetGrants().Data {
		if s, ok := g.(string); ok && strings.HasPrefix(s, "SELECT ON *.*") {
			hasBroad = true
		}
	}
	if !hasBroad {
		t.Error("analyst role should hold SELECT ON *.*")
	}
}
