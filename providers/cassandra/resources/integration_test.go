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
	"go.mondoo.com/mql/providers/cassandra/connection"
)

// newIntegrationRuntime connects to a live Cassandra cluster described by the
// CASSANDRA_TEST_* environment, or skips when it is not configured.
//
//	CASSANDRA_TEST_HOST      host or host:port (default port 9042)
//	CASSANDRA_TEST_USER      role (default "cassandra")
//	CASSANDRA_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("CASSANDRA_TEST_HOST")
	password := os.Getenv("CASSANDRA_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set CASSANDRA_TEST_HOST and CASSANDRA_TEST_PASSWORD to run cassandra integration tests")
	}
	user := os.Getenv("CASSANDRA_TEST_USER")
	if user == "" {
		user = "cassandra"
	}

	options := map[string]string{}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid CASSANDRA_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "cassandra",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewCassandraConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustCluster(t *testing.T, runtime *plugin.Runtime) *mqlCassandraCluster {
	res, err := NewResource(runtime, "cassandra.cluster", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve cassandra.cluster: %v", err)
	}
	return res.(*mqlCassandraCluster)
}

func resolveList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Errorf("%s errored: %v", label, tv.Error)
		return nil
	}
	return tv.Data
}

func TestIntegrationCluster(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))
	if v := c.GetVersion(); v.Error != nil || v.Data == "" {
		t.Errorf("version = %q (err=%v)", v.Data, v.Error)
	}
	sec := c.GetSecurity()
	if sec.Error != nil {
		t.Fatalf("security errored: %v", sec.Error)
	}
	if v := sec.Data.GetAuthenticationEnabled(); v.Error != nil {
		t.Errorf("security.authenticationEnabled errored: %v", v.Error)
	}
}

// TestIntegrationResolveAll walks every resource and field getter.
func TestIntegrationResolveAll(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))

	for _, x := range resolveList(t, "roles", c.GetRoles()) {
		role := x.(*mqlCassandraRole)
		if v := role.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("role.name = %q (err=%v)", v.Data, v.Error)
		}
		resolveList(t, "role.permissions", role.GetPermissions())
	}
	resolveList(t, "nodes", c.GetNodes())
	resolveList(t, "keyspaces", c.GetKeyspaces())
}

// TestIntegrationSeededFixtures verifies the default superuser and the fixtures
// from testdata/seed.sh. Enable it with CASSANDRA_TEST_SEEDED=1.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("CASSANDRA_TEST_SEEDED") == "" {
		t.Skip("set CASSANDRA_TEST_SEEDED=1 after running testdata/seed.sh")
	}
	c := mustCluster(t, newIntegrationRuntime(t))

	roles := map[string]*mqlCassandraRole{}
	for _, x := range c.GetRoles().Data {
		r := x.(*mqlCassandraRole)
		roles[r.GetName().Data] = r
	}

	// The default cassandra superuser (a CIS review target) still exists.
	def := roles["cassandra"]
	if def == nil {
		t.Fatal("default cassandra role not found")
	}
	if !def.GetIsSuperuser().Data || !def.GetCanLogin().Data {
		t.Error("cassandra should be a login superuser")
	}

	// The seeded auditor is a non-superuser login role with a scoped grant.
	auditor := roles["auditor"]
	if auditor == nil {
		t.Fatal("seeded auditor role not found")
	}
	if auditor.GetIsSuperuser().Data {
		t.Error("auditor should not be a superuser")
	}
	if !auditor.GetHasPassword().Data {
		t.Error("auditor should have a password")
	}
	var appGrant *mqlCassandraRolePermission
	for _, x := range auditor.GetPermissions().Data {
		p := x.(*mqlCassandraRolePermission)
		if p.GetResource().Data == "data/app" {
			appGrant = p
		}
	}
	if appGrant == nil {
		t.Fatal("auditor should have a permission on data/app")
	}

	// The seeded app keyspace is SimpleStrategy, RF 1 (a replication finding).
	var app *mqlCassandraKeyspace
	for _, x := range c.GetKeyspaces().Data {
		if k := x.(*mqlCassandraKeyspace); k.GetName().Data == "app" {
			app = k
		}
	}
	if app == nil {
		t.Fatal("seeded app keyspace not found")
	}
	if app.GetReplicationStrategy().Data != "SimpleStrategy" {
		t.Errorf("app replicationStrategy = %q, want SimpleStrategy", app.GetReplicationStrategy().Data)
	}
	if app.GetIsSystem().Data {
		t.Error("app should not be a system keyspace")
	}
}
