// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

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
	password := os.Getenv("PG_TEST_PASSWORD")
	user := os.Getenv("PG_TEST_USER")
	if user == "" {
		user = "postgres"
	}
	return newIntegrationRuntimeAs(t, user, password)
}

// newIntegrationRuntimeAs connects to the PG_TEST_HOST server as the given role.
func newIntegrationRuntimeAs(t *testing.T, user, password string) *plugin.Runtime {
	host := os.Getenv("PG_TEST_HOST")
	if host == "" || os.Getenv("PG_TEST_PASSWORD") == "" {
		t.Skip("set PG_TEST_HOST and PG_TEST_PASSWORD to run postgres integration tests")
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
	resolveList(t, "hbaRules", inst.GetHbaRules())
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

// integrationExec runs setup statements as the PG_TEST_USER superuser and
// registers the cleanup statements to run when the test ends.
func integrationExec(t *testing.T, runtime *plugin.Runtime, setup []string, cleanup []string) {
	t.Helper()
	pool, err := pgPool(runtime, "")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() {
		for _, stmt := range cleanup {
			if _, err := pool.Exec(pgContext(), stmt); err != nil {
				t.Logf("cleanup %q: %v", stmt, err)
			}
		}
	})
	for _, stmt := range setup {
		if _, err := pool.Exec(pgContext(), stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
}

func integrationServerVersion(t *testing.T, runtime *plugin.Runtime) int {
	t.Helper()
	pool, err := pgPool(runtime, "")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	var v int
	if err := pool.QueryRow(pgContext(), "SELECT current_setting('server_version_num')::int").Scan(&v); err != nil {
		t.Fatalf("server_version_num: %v", err)
	}
	return v
}

func findRole(t *testing.T, inst *mqlPostgresdbInstance, name string) *mqlPostgresdbRole {
	t.Helper()
	roles := inst.GetRoles()
	if roles.Error != nil {
		t.Fatalf("roles errored: %v", roles.Error)
	}
	for _, x := range roles.Data {
		if r := x.(*mqlPostgresdbRole); r.GetName().Data == name {
			return r
		}
	}
	t.Fatalf("role %s not found", name)
	return nil
}

// TestIntegrationRoleValidUntilInfinity: one role with VALID UNTIL 'infinity'
// used to fail the whole roles list ("cannot scan Infinity into *time.Time").
func TestIntegrationRoleValidUntilInfinity(t *testing.T) {
	admin := newIntegrationRuntime(t)
	integrationExec(t, admin, []string{
		"CREATE ROLE pgfix_inf VALID UNTIL 'infinity'",
		"CREATE ROLE pgfix_neginf VALID UNTIL '-infinity'",
		"CREATE ROLE pgfix_finite VALID UNTIL '2031-05-06 07:08:09+00'",
	}, []string{"DROP ROLE IF EXISTS pgfix_inf", "DROP ROLE IF EXISTS pgfix_neginf", "DROP ROLE IF EXISTS pgfix_finite"})

	inst := mustInstance(t, newIntegrationRuntime(t))
	if v := findRole(t, inst, "pgfix_inf").GetValidUntil(); v.Error != nil || v.Data != nil {
		t.Errorf("infinity validUntil = %v (err=%v), want null", v.Data, v.Error)
	}
	if v := findRole(t, inst, "pgfix_neginf").GetValidUntil(); v.Error != nil || v.Data == nil || !v.Data.Equal(llx.NeverPastTime) {
		t.Errorf("-infinity validUntil = %v (err=%v), want the earliest time", v.Data, v.Error)
	}
	want := time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC)
	if v := findRole(t, inst, "pgfix_finite").GetValidUntil(); v.Error != nil || v.Data == nil || !v.Data.Equal(want) {
		t.Errorf("finite validUntil = %v (err=%v), want %v", v.Data, v.Error, want)
	}
}

// TestIntegrationMembershipGrantors: on PostgreSQL 16+ a membership granted by
// two grantors is two pg_auth_members rows, but one membership.
func TestIntegrationMembershipGrantors(t *testing.T) {
	admin := newIntegrationRuntime(t)
	if integrationServerVersion(t, admin) < 160000 {
		t.Skip("one row per grantor needs PostgreSQL 16+")
	}
	integrationExec(t, admin, []string{
		"CREATE ROLE pgfix_grp",
		"CREATE ROLE pgfix_member",
		"CREATE ROLE pgfix_grantor",
		"GRANT pgfix_grp TO pgfix_grantor WITH ADMIN OPTION",
		"GRANT pgfix_grp TO pgfix_member",
		"GRANT pgfix_grp TO pgfix_member GRANTED BY pgfix_grantor",
	}, []string{"DROP ROLE IF EXISTS pgfix_member", "DROP ROLE IF EXISTS pgfix_grantor", "DROP ROLE IF EXISTS pgfix_grp"})

	inst := mustInstance(t, newIntegrationRuntime(t))
	memberOf := findRole(t, inst, "pgfix_member").GetMemberOf()
	if memberOf.Error != nil || len(memberOf.Data) != 1 {
		t.Errorf("memberOf = %d entries (err=%v), want 1", len(memberOf.Data), memberOf.Error)
	}
	members := findRole(t, inst, "pgfix_grp").GetMembers()
	if members.Error != nil || len(members.Data) != 2 { // pgfix_member, pgfix_grantor
		t.Errorf("members = %d entries (err=%v), want 2", len(members.Data), members.Error)
	}
}

// TestIntegrationNonSuperuserRefusals: a role that cannot read pg_authid or
// the superuser-only settings gets a refusal, not a null or a silently
// shorter list, once StructuredErrors is on.
func TestIntegrationNonSuperuserRefusals(t *testing.T) {
	admin := newIntegrationRuntime(t)
	integrationExec(t, admin, []string{
		"CREATE ROLE pgfix_plain LOGIN PASSWORD 'pgfix-plain-pw'",
	}, []string{"DROP ROLE IF EXISTS pgfix_plain"})

	t.Run("structured errors on", func(t *testing.T) {
		withStructuredErrors(t, true)
		inst := mustInstance(t, newIntegrationRuntimeAs(t, "pgfix_plain", "pgfix-plain-pw"))
		pt := findRole(t, inst, "pgfix_plain").GetPasswordType()
		if !errors.Is(pt.Error, llx.ErrForbidden) {
			t.Errorf("passwordType = %q (err=%v), want Forbidden", pt.Data, pt.Error)
		}
		if s := inst.GetSettings(); !errors.Is(s.Error, llx.ErrForbidden) {
			t.Errorf("settings = %d entries (err=%v), want Forbidden", len(s.Data), s.Error)
		}
	})

	t.Run("structured errors off keeps v13 values", func(t *testing.T) {
		withStructuredErrors(t, false)
		inst := mustInstance(t, newIntegrationRuntimeAs(t, "pgfix_plain", "pgfix-plain-pw"))
		pt := findRole(t, inst, "pgfix_plain").GetPasswordType()
		if pt.Error != nil || !pt.IsNull() {
			t.Errorf("passwordType = %q (err=%v), want null", pt.Data, pt.Error)
		}
		if s := inst.GetSettings(); s.Error != nil || len(s.Data) == 0 {
			t.Errorf("settings = %d entries (err=%v), want the visible subset", len(s.Data), s.Error)
		}
	})

	t.Run("superuser reads both", func(t *testing.T) {
		withStructuredErrors(t, true)
		inst := mustInstance(t, newIntegrationRuntime(t))
		pt := findRole(t, inst, "pgfix_plain").GetPasswordType()
		if pt.Error != nil || pt.Data != "scram-sha-256" && pt.Data != "md5" {
			t.Errorf("passwordType = %q (err=%v)", pt.Data, pt.Error)
		}
		if s := inst.GetSettings(); s.Error != nil {
			t.Errorf("settings errored: %v", s.Error)
		}
	})
}
