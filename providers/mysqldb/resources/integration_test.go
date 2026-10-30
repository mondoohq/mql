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
	"go.mondoo.com/mql/providers/mysqldb/connection"
)

// newIntegrationRuntime connects to a live MySQL/MariaDB server described by the
// MYSQL_TEST_* environment, or skips when it is not configured.
//
//	MYSQL_TEST_HOST      host or host:port (default port 3306)
//	MYSQL_TEST_USER      user name (default "root")
//	MYSQL_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("MYSQL_TEST_HOST")
	password := os.Getenv("MYSQL_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set MYSQL_TEST_HOST and MYSQL_TEST_PASSWORD to run mysqldb integration tests")
	}
	user := os.Getenv("MYSQL_TEST_USER")
	if user == "" {
		user = "root"
	}

	options := map[string]string{"tls-mode": "preferred"}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid MYSQL_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "mysqldb",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewMysqldbConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustInstance(t *testing.T, runtime *plugin.Runtime) *mqlMysqldbInstance {
	res, err := NewResource(runtime, "mysqldb.instance", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve mysqldb.instance: %v", err)
	}
	return res.(*mqlMysqldbInstance)
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
	flavor := inst.GetFlavor()
	if flavor.Error != nil || (flavor.Data != "mysql" && flavor.Data != "mariadb" && flavor.Data != "percona") {
		t.Errorf("flavor = %q (err=%v)", flavor.Data, flavor.Error)
	}
	t.Logf("connected to flavor=%s version=%s", flavor.Data, inst.GetVersion().Data)
}

// TestIntegrationResolveAll walks every resource and field getter and asserts
// each resolves without error against a live server, on both MySQL and MariaDB.
func TestIntegrationResolveAll(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))

	for _, tv := range []*plugin.TValue[bool]{inst.GetSsl(), inst.GetRequireSecureTransport(), inst.GetLocalInfile()} {
		if tv.Error != nil {
			t.Errorf("instance bool field errored: %v", tv.Error)
		}
	}
	resolveList(t, "variables", inst.GetVariables())
	resolveList(t, "plugins", inst.GetPlugins())
	resolveList(t, "components", inst.GetComponents())
	resolveList(t, "replicationChannels", inst.GetReplicationChannels())

	// Child __ids must carry the server prefix so resources from different
	// servers never collide (regression guard for the MariaDB no-server_uuid
	// case, where the prefix would otherwise be empty).
	serverPrefix := inst.MqlID()
	for _, x := range resolveList(t, "users", inst.GetUsers()) {
		u := x.(*mqlMysqldbUser)
		if !strings.HasPrefix(u.MqlID(), serverPrefix+"/") {
			t.Errorf("user __id %q not prefixed by server id %q", u.MqlID(), serverPrefix)
		}
		resolveList(t, "user.grantedRoles", u.GetGrantedRoles())
		resolveList(t, "user.privileges", u.GetPrivileges())
	}
	for _, x := range resolveList(t, "schemas", inst.GetSchemas()) {
		sc := x.(*mqlMysqldbSchema)
		name := sc.GetName().Data
		if !strings.HasPrefix(sc.MqlID(), serverPrefix+"/") {
			t.Errorf("schema __id %q not prefixed by server id %q", sc.MqlID(), serverPrefix)
		}
		resolveList(t, name+".privileges", sc.GetPrivileges())
		resolveList(t, name+".routines", sc.GetRoutines())
		for _, tb := range resolveList(t, name+".tables", sc.GetTables()) {
			resolveList(t, name+".table.privileges", tb.(*mqlMysqldbTable).GetPrivileges())
		}
	}
}

// TestIntegrationSeededFixtures verifies values from testdata/seed.sql.
// Enable it with MYSQL_TEST_SEEDED=1 after loading the seed.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("MYSQL_TEST_SEEDED") == "" {
		t.Skip("set MYSQL_TEST_SEEDED=1 after loading testdata/seed.sql")
	}
	inst := mustInstance(t, newIntegrationRuntime(t))

	var appuser *mqlMysqldbUser
	for _, x := range inst.GetUsers().Data {
		if u := x.(*mqlMysqldbUser); u.GetUser().Data == "appuser" {
			appuser = u
		}
	}
	if appuser == nil {
		t.Fatal("appuser not found")
	}
	if !appuser.GetIsWildcardHost().Data {
		t.Error("appuser host should be a wildcard (%)")
	}
	if !appuser.GetHasPassword().Data {
		t.Error("appuser should have a password")
	}
	globalPrivs := map[string]bool{}
	schemaPrivs := map[string]bool{}
	for _, x := range appuser.GetPrivileges().Data {
		p := x.(*mqlMysqldbPrivilege)
		switch p.GetScope().Data {
		case "GLOBAL":
			globalPrivs[p.GetPrivilegeType().Data] = true
		case "SCHEMA":
			if p.GetSchema().Data == "appdb" {
				schemaPrivs[p.GetPrivilegeType().Data] = true
			}
		}
	}
	if !globalPrivs["PROCESS"] {
		t.Error("appuser should hold the global PROCESS privilege")
	}
	if !schemaPrivs["SELECT"] {
		t.Error("appuser should hold SELECT on appdb")
	}

	// appdb schema + SECURITY DEFINER routine
	var appdb *mqlMysqldbSchema
	for _, x := range inst.GetSchemas().Data {
		if sc := x.(*mqlMysqldbSchema); sc.GetName().Data == "appdb" {
			appdb = sc
		}
	}
	if appdb == nil {
		t.Fatal("appdb schema not found")
	}
	var secdef *mqlMysqldbRoutine
	for _, x := range appdb.GetRoutines().Data {
		if rt := x.(*mqlMysqldbRoutine); rt.GetName().Data == "secdef_proc" {
			secdef = rt
		}
	}
	if secdef == nil {
		t.Fatal("secdef_proc routine not found")
	}
	if secdef.GetSecurityType().Data != "DEFINER" {
		t.Errorf("secdef_proc securityType = %q, want DEFINER", secdef.GetSecurityType().Data)
	}
	if !strings.Contains(secdef.GetDefiner().Data, "appuser") {
		t.Errorf("secdef_proc definer = %q, want appuser", secdef.GetDefiner().Data)
	}
}
