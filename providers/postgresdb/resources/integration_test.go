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
	"go.mondoo.com/mql/providers/postgresdb/connection"
)

// newIntegrationRuntime connects to a live PostgreSQL server described by the
// PG_TEST_* environment, or skips when it is not configured.
//
//	PG_TEST_HOST      host or host:port (default port 5432)
//	PG_TEST_USER      role name (default "postgres")
//	PG_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("PG_TEST_HOST")
	password := os.Getenv("PG_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set PG_TEST_HOST and PG_TEST_PASSWORD to run postgres integration tests")
	}
	user := os.Getenv("PG_TEST_USER")
	if user == "" {
		user = "postgres"
	}

	options := map[string]string{"sslmode": "disable"}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid PG_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "postgresdb",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewPostgresdbConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustInstance(t *testing.T, runtime *plugin.Runtime) *mqlPostgresdbInstance {
	res, err := NewResource(runtime, "postgresdb.instance", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve postgresdb.instance: %v", err)
	}
	return res.(*mqlPostgresdbInstance)
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
	if v := inst.GetVersion(); v.Error != nil || !strings.Contains(v.Data, "PostgreSQL") {
		t.Errorf("version = %q (err=%v)", v.Data, v.Error)
	}
	if v := inst.GetSystemIdentifier(); v.Error != nil || v.Data == "" {
		t.Errorf("systemIdentifier empty (err=%v)", v.Error)
	}
	if v := inst.GetPasswordEncryption(); v.Error != nil || v.Data == "" {
		t.Errorf("passwordEncryption = %q (err=%v)", v.Data, v.Error)
	}
}

// TestIntegrationResolveAll walks every resource and field getter and asserts
// each resolves without error against a live server, independent of seeded data.
func TestIntegrationResolveAll(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))

	for _, tv := range []*plugin.TValue[bool]{inst.GetSsl(), inst.GetInRecovery()} {
		if tv.Error != nil {
			t.Errorf("instance bool field errored: %v", tv.Error)
		}
	}
	resolveList(t, "settings", inst.GetSettings())
	// pg_hba_file_rules arrived in 10: an older server answers with an error,
	// since its rules exist but cannot be listed.
	if pgAtLeast(inst.MqlRuntime, pgVersion10) {
		resolveList(t, "hbaRules", inst.GetHbaRules())
	} else if inst.GetHbaRules().Error == nil {
		t.Error("hbaRules before PostgreSQL 10 must be an error, not a list")
	}
	resolveList(t, "replicationSlots", inst.GetReplicationSlots())
	resolveList(t, "subscriptions", inst.GetSubscriptions())

	for _, x := range resolveList(t, "roles", inst.GetRoles()) {
		role := x.(*mqlPostgresdbRole)
		resolveList(t, "role.memberOf", role.GetMemberOf())
		resolveList(t, "role.members", role.GetMembers())
	}
	for _, x := range resolveList(t, "tablespaces", inst.GetTablespaces()) {
		ts := x.(*mqlPostgresdbTablespace)
		if ts.GetOwner().Error != nil {
			t.Errorf("tablespace.owner errored: %v", ts.GetOwner().Error)
		}
		resolveList(t, "tablespace.privileges", ts.GetPrivileges())
	}
	for _, x := range resolveList(t, "databases", inst.GetDatabases()) {
		db := x.(*mqlPostgresdbDatabase)
		name := db.GetName().Data
		if db.GetOwner().Error != nil {
			t.Errorf("%s.owner errored: %v", name, db.GetOwner().Error)
		}
		resolveList(t, name+".privileges", db.GetPrivileges())
		resolveList(t, name+".extensions", db.GetExtensions())
		if v := db.GetPgvectorVersion(); v.Error != nil {
			t.Errorf("%s.pgvectorVersion errored: %v", name, v.Error)
		}
		resolveList(t, name+".publications", db.GetPublications())
		for _, f := range resolveList(t, name+".foreignServers", db.GetForeignServers()) {
			fs := f.(*mqlPostgresdbForeignServer)
			if fs.GetOwner().Error != nil {
				t.Errorf("%s foreignServer owner errored: %v", name, fs.GetOwner().Error)
			}
			resolveList(t, name+".foreignServer.userMappings", fs.GetUserMappings())
		}
		for _, s := range resolveList(t, name+".schemas", db.GetSchemas()) {
			sc := s.(*mqlPostgresdbSchema)
			if sc.GetOwner().Error != nil {
				t.Errorf("%s schema owner errored: %v", name, sc.GetOwner().Error)
			}
			resolveList(t, name+".schema.privileges", sc.GetPrivileges())
			for _, tb := range resolveList(t, name+".tables", sc.GetTables()) {
				tbl := tb.(*mqlPostgresdbTable)
				if tbl.GetOwner().Error != nil {
					t.Errorf("%s table owner errored: %v", name, tbl.GetOwner().Error)
				}
				resolveList(t, name+".table.privileges", tbl.GetPrivileges())
				resolveList(t, name+".table.policies", tbl.GetPolicies())
			}
		}
		for _, f := range resolveList(t, name+".functions", db.GetFunctions()) {
			fn := f.(*mqlPostgresdbFunction)
			if fn.GetOwner().Error != nil {
				t.Errorf("%s function owner errored: %v", name, fn.GetOwner().Error)
			}
			resolveList(t, name+".function.privileges", fn.GetPrivileges())
		}
	}
}

// TestIntegrationSeededFixtures verifies specific values from testdata/seed.sql.
// Enable it with PG_TEST_SEEDED=1 after loading the seed.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("PG_TEST_SEEDED") == "" {
		t.Skip("set PG_TEST_SEEDED=1 after loading testdata/seed.sql")
	}
	inst := mustInstance(t, newIntegrationRuntime(t))

	// role attributes
	var admin *mqlPostgresdbRole
	for _, x := range inst.GetRoles().Data {
		if r := x.(*mqlPostgresdbRole); r.GetName().Data == "app_admin" {
			admin = r
		}
	}
	if admin == nil {
		t.Fatal("app_admin role not found")
	}
	if !admin.GetCreateRole().Data {
		t.Error("app_admin should have createRole")
	}
	if admin.GetConnectionLimit().Data != 5 {
		t.Errorf("app_admin connectionLimit = %d, want 5", admin.GetConnectionLimit().Data)
	}
	memberOf := map[string]bool{}
	for _, x := range admin.GetMemberOf().Data {
		memberOf[x.(*mqlPostgresdbRole).GetName().Data] = true
	}
	if !memberOf["app_group"] {
		t.Error("app_admin should be a member of app_group")
	}

	// appdb: owner, SECURITY DEFINER function with an EXECUTE grant
	var appdb *mqlPostgresdbDatabase
	for _, x := range inst.GetDatabases().Data {
		if d := x.(*mqlPostgresdbDatabase); d.GetName().Data == "appdb" {
			appdb = d
		}
	}
	if appdb == nil {
		t.Fatal("appdb not found")
	}
	if o := appdb.GetOwner(); o.Error != nil || o.Data == nil || o.Data.GetName().Data != "app_admin" {
		t.Errorf("appdb owner not app_admin")
	}
	var secdef *mqlPostgresdbFunction
	for _, x := range appdb.GetFunctions().Data {
		if f := x.(*mqlPostgresdbFunction); f.GetName().Data == "secdef_fn" {
			secdef = f
		}
	}
	if secdef == nil {
		t.Fatal("secdef_fn not found")
	}
	if !secdef.GetIsSecurityDefiner().Data {
		t.Error("secdef_fn should be SECURITY DEFINER")
	}
	grantees := map[string]bool{}
	for _, x := range secdef.GetPrivileges().Data {
		grantees[x.(*mqlPostgresdbPrivilege).GetGrantee().Data] = true
	}
	if !grantees["app_group"] {
		t.Error("secdef_fn should grant EXECUTE to app_group")
	}

	// table DML privileges (CIS 4.6) and row-level security (CIS 4.7)
	var t1 *mqlPostgresdbTable
	for _, s := range appdb.GetSchemas().Data {
		sc := s.(*mqlPostgresdbSchema)
		if sc.GetName().Data != "appschema" {
			continue
		}
		for _, tb := range sc.GetTables().Data {
			if tbl := tb.(*mqlPostgresdbTable); tbl.GetName().Data == "t1" {
				t1 = tbl
			}
		}
	}
	if t1 == nil {
		t.Fatal("appschema.t1 not found")
	}
	if !t1.GetRowSecurityEnabled().Data {
		t.Error("t1 should have row-level security enabled")
	}
	dmlGrantees := map[string]bool{}
	for _, x := range t1.GetPrivileges().Data {
		p := x.(*mqlPostgresdbPrivilege)
		if p.GetPrivilegeType().Data == "SELECT" {
			dmlGrantees[p.GetGrantee().Data] = true
		}
	}
	if !dmlGrantees["app_group"] {
		t.Error("t1 should grant SELECT to app_group")
	}
	policyNames := map[string]bool{}
	for _, x := range t1.GetPolicies().Data {
		policyNames[x.(*mqlPostgresdbRlsPolicy).GetName().Data] = true
	}
	if !policyNames["t1_sel"] {
		t.Error("t1 should have policy t1_sel")
	}

	// foreign server user mapping must not expose the password option
	var fs *mqlPostgresdbForeignServer
	for _, x := range appdb.GetForeignServers().Data {
		if s := x.(*mqlPostgresdbForeignServer); s.GetName().Data == "remote_srv" {
			fs = s
		}
	}
	if fs == nil {
		t.Fatal("remote_srv not found")
	}
	for _, x := range fs.GetUserMappings().Data {
		for _, opt := range x.(*mqlPostgresdbUserMapping).GetOptions().Data {
			if strings.HasPrefix(strings.ToLower(opt.(string)), "password") {
				t.Errorf("user mapping leaked a password option: %v", opt)
			}
		}
	}
}

// TestIntegrationHbaRulesMatchServer compares hbaRules with pg_hba_file_rules
// row by row, in the server's evaluation order. Point it at a PostgreSQL 16+
// server whose pg_hba.conf includes a second file with a rule on the same line
// number as a rule in pg_hba.conf, and which also carries one invalid line
// (for example an unknown auth method). Enable with PG_TEST_HBA_INCLUDE=1.
func TestIntegrationHbaRulesMatchServer(t *testing.T) {
	if os.Getenv("PG_TEST_HBA_INCLUDE") == "" {
		t.Skip("set PG_TEST_HBA_INCLUDE=1 against a server with an included hba file and an invalid line")
	}
	runtime := newIntegrationRuntime(t)
	inst := mustInstance(t, runtime)

	pool, err := pgPool(runtime, "")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(pgContext(),
		`SELECT line_number, COALESCE(auth_method, ''), COALESCE(error, '')
		 FROM pg_hba_file_rules ORDER BY rule_number NULLS LAST, file_name, line_number`)
	if err != nil {
		t.Fatal(err)
	}
	type rule struct {
		line         int64
		method, errm string
	}
	var want []rule
	for rows.Next() {
		var r rule
		if err := rows.Scan(&r.line, &r.method, &r.errm); err != nil {
			t.Fatal(err)
		}
		want = append(want, r)
	}
	rows.Close()

	got := inst.GetHbaRules()
	if got.Error != nil {
		t.Fatalf("hbaRules errored: %v", got.Error)
	}
	if len(got.Data) != len(want) {
		t.Fatalf("hbaRules has %d rules, server has %d", len(got.Data), len(want))
	}
	sawError := false
	for i, x := range got.Data {
		r := x.(*mqlPostgresdbHbaRule)
		g := rule{r.GetLineNumber().Data, r.GetAuthMethod().Data, r.GetError().Data}
		if g != want[i] {
			t.Errorf("rule %d = %+v, server has %+v", i, g, want[i])
		}
		if g.errm != "" {
			sawError = true
		}
	}
	if !sawError {
		t.Error("fixture needs an invalid pg_hba.conf line; none reported")
	}
}

// privilegeSet returns the privileges as "grantee:TYPE" strings.
func privilegeSet(t *testing.T, label string, tv *plugin.TValue[[]any]) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, x := range resolveList(t, label, tv) {
		p := x.(*mqlPostgresdbPrivilege)
		out[p.GetGrantee().Data+":"+p.GetPrivilegeType().Data] = true
	}
	return out
}

func requirePrivileges(t *testing.T, label string, got map[string]bool, want ...string) {
	t.Helper()
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s: missing privilege %s (got %v)", label, w, got)
		}
	}
}

func requireNoPublic(t *testing.T, label string, got map[string]bool) {
	t.Helper()
	for k := range got {
		if strings.HasPrefix(k, "PUBLIC:") {
			t.Errorf("%s: unexpected PUBLIC privilege %s", label, k)
		}
	}
}

// TestIntegrationNullACLReportsDefaultGrants creates objects that were never
// GRANTed or REVOKEd on, so their ACL column is NULL. PostgreSQL then applies
// the built-in default privileges (acldefault), which for databases and
// functions include PUBLIC. A NULL ACL must not read as "no privileges".
func TestIntegrationNullACLReportsDefaultGrants(t *testing.T) {
	runtime := newIntegrationRuntime(t)
	pool, err := pgPool(runtime, "")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	var user string
	if err := pool.QueryRow(pgContext(), "SELECT current_user").Scan(&user); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(pgContext(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	cleanup := func() {
		for _, sql := range []string{
			"DROP DATABASE IF EXISTS mql_acl_db",
			"DROP SCHEMA IF EXISTS mql_acl_s CASCADE",
		} {
			_, _ = pool.Exec(pgContext(), sql)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	exec("CREATE DATABASE mql_acl_db TEMPLATE template0")
	exec("CREATE SCHEMA mql_acl_s")
	exec("CREATE TABLE mql_acl_s.t (id int)")
	exec("CREATE FUNCTION mql_acl_s.f() RETURNS int LANGUAGE sql AS 'SELECT 1'")

	inst := mustInstance(t, runtime)
	var serverDB, aclDB *mqlPostgresdbDatabase
	for _, x := range resolveList(t, "databases", inst.GetDatabases()) {
		d := x.(*mqlPostgresdbDatabase)
		switch d.GetName().Data {
		case "mql_acl_db":
			aclDB = d
		case "postgres":
			serverDB = d
		}
	}
	if aclDB == nil || serverDB == nil {
		t.Fatalf("databases mql_acl_db/postgres not found")
	}

	// acldefault('d'): PUBLIC gets CONNECT and TEMPORARY, the owner everything.
	dbPrivs := privilegeSet(t, "database privileges", aclDB.GetPrivileges())
	requirePrivileges(t, "database", dbPrivs, "PUBLIC:CONNECT", "PUBLIC:TEMPORARY", user+":CREATE")

	var schema *mqlPostgresdbSchema
	for _, x := range resolveList(t, "schemas", serverDB.GetSchemas()) {
		if s := x.(*mqlPostgresdbSchema); s.GetName().Data == "mql_acl_s" {
			schema = s
		}
	}
	if schema == nil {
		t.Fatal("schema mql_acl_s not found")
	}
	// acldefault('n'): owner only, no PUBLIC.
	schemaPrivs := privilegeSet(t, "schema privileges", schema.GetPrivileges())
	requirePrivileges(t, "schema", schemaPrivs, user+":USAGE", user+":CREATE")
	requireNoPublic(t, "schema", schemaPrivs)

	var table *mqlPostgresdbTable
	for _, x := range resolveList(t, "tables", schema.GetTables()) {
		if tb := x.(*mqlPostgresdbTable); tb.GetName().Data == "t" {
			table = tb
		}
	}
	if table == nil {
		t.Fatal("table mql_acl_s.t not found")
	}
	// acldefault('r'): owner only, no PUBLIC.
	tablePrivs := privilegeSet(t, "table privileges", table.GetPrivileges())
	requirePrivileges(t, "table", tablePrivs, user+":SELECT", user+":INSERT")
	requireNoPublic(t, "table", tablePrivs)

	var fn *mqlPostgresdbFunction
	for _, x := range resolveList(t, "functions", serverDB.GetFunctions()) {
		if f := x.(*mqlPostgresdbFunction); f.GetName().Data == "f" && f.GetSchema().Data == "mql_acl_s" {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("function mql_acl_s.f not found")
	}
	// acldefault('f'): PUBLIC gets EXECUTE.
	requirePrivileges(t, "function", privilegeSet(t, "function privileges", fn.GetPrivileges()),
		"PUBLIC:EXECUTE", user+":EXECUTE")

	// pg_default has spcacl NULL; acldefault('t') grants the owner CREATE only.
	for _, x := range resolveList(t, "tablespaces", inst.GetTablespaces()) {
		ts := x.(*mqlPostgresdbTablespace)
		if ts.GetName().Data != "pg_default" {
			continue
		}
		var owner string
		if err := pool.QueryRow(pgContext(),
			"SELECT pg_get_userbyid(spcowner) FROM pg_tablespace WHERE spcname = 'pg_default'").Scan(&owner); err != nil {
			t.Fatalf("pg_default owner: %v", err)
		}
		tsPrivs := privilegeSet(t, "tablespace privileges", ts.GetPrivileges())
		requirePrivileges(t, "tablespace", tsPrivs, owner+":CREATE")
		requireNoPublic(t, "tablespace", tsPrivs)
	}
}
