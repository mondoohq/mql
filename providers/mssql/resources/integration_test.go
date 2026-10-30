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
	"go.mondoo.com/mql/providers/mssql/connection"
)

// newIntegrationRuntime connects to a live SQL Server instance described by the
// MSSQL_TEST_* environment, or skips when it is not configured.
//
//	MSSQL_TEST_HOST      host or host:port (default port 1433)
//	MSSQL_TEST_USER      login name (default "sa")
//	MSSQL_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("MSSQL_TEST_HOST")
	password := os.Getenv("MSSQL_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set MSSQL_TEST_HOST and MSSQL_TEST_PASSWORD to run mssql integration tests")
	}
	user := os.Getenv("MSSQL_TEST_USER")
	if user == "" {
		user = "sa"
	}

	options := map[string]string{
		"auth":                     "sql",
		"encrypt":                  "disable",
		"trust-server-certificate": "true",
	}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid MSSQL_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:    "mssql",
		Options: options,
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential(user, password),
		},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}

	conn, err := connection.NewMssqlConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustServer(t *testing.T, runtime *plugin.Runtime) *mqlMssqlServer {
	res, err := NewResource(runtime, "mssql.server", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve mssql.server: %v", err)
	}
	return res.(*mqlMssqlServer)
}

func TestIntegrationServer(t *testing.T) {
	srv := mustServer(t, newIntegrationRuntime(t))

	if v := srv.GetName(); v.Error != nil || v.Data == "" {
		t.Errorf("server name empty (err=%v)", v.Error)
	}
	if v := srv.GetVersion(); v.Error != nil || !strings.Contains(v.Data, "SQL Server") {
		t.Errorf("version = %q (err=%v)", v.Data, v.Error)
	}
	if v := srv.GetEdition(); v.Error != nil || v.Data == "" {
		t.Errorf("edition empty (err=%v)", v.Error)
	}
	// Authenticating with a SQL login proves mixed-mode auth is on.
	if v := srv.GetIsMixedModeAuthEnabled(); v.Error != nil || !v.Data {
		t.Errorf("isMixedModeAuthEnabled = %v (err=%v)", v.Data, v.Error)
	}
	if v := srv.GetPort(); v.Error != nil || v.Data == 0 {
		t.Errorf("port = %d (err=%v)", v.Data, v.Error)
	}
}

func TestIntegrationLogins(t *testing.T) {
	srv := mustServer(t, newIntegrationRuntime(t))

	logins := srv.GetLogins()
	if logins.Error != nil {
		t.Fatalf("logins error: %v", logins.Error)
	}
	var sa *mqlMssqlLogin
	for _, x := range logins.Data {
		l := x.(*mqlMssqlLogin)
		if l.GetName().Data == "sa" {
			sa = l
		}
	}
	if sa == nil {
		t.Fatal("sa login not found")
	}
	if got := sa.GetType().Data; got != "SQL_LOGIN" {
		t.Errorf("sa type = %q, want SQL_LOGIN", got)
	}
	if got := sa.GetPrincipalId().Data; got != 1 {
		t.Errorf("sa principalId = %d, want 1", got)
	}
	// explicit permissions must resolve without error and carry a composite id
	if perms := sa.GetExplicitPermissions(); perms.Error != nil {
		t.Errorf("sa explicitPermissions error: %v", perms.Error)
	}
}

func TestIntegrationConfigurations(t *testing.T) {
	srv := mustServer(t, newIntegrationRuntime(t))

	configs := srv.GetConfigurations()
	if configs.Error != nil {
		t.Fatalf("configurations error: %v", configs.Error)
	}
	found := map[string]bool{}
	for _, x := range configs.Data {
		found[x.(*mqlMssqlServerConfiguration).GetName().Data] = true
	}
	// surface-area options the CIS benchmark asserts on
	for _, name := range []string{"clr enabled", "Ad Hoc Distributed Queries", "cross db ownership chaining"} {
		if !found[name] {
			t.Errorf("configuration %q not found", name)
		}
	}
}

// resolveList fails the test if a list field errored and returns its elements.
func resolveList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Errorf("%s errored: %v", label, tv.Error)
		return nil
	}
	return tv.Data
}

// TestIntegrationResolveAll walks every resource and field getter and asserts
// each resolves without error against a live server. It tolerates empty lists
// and null scalars (a value that legitimately does not apply), but any SQL or
// mapping error fails the test. This is the broad "every accessor works against
// real SQL Server" check and is independent of seeded data.
func TestIntegrationResolveAll(t *testing.T) {
	srv := mustServer(t, newIntegrationRuntime(t))

	// computed server scalars (registry-backed and service-account fields may be
	// null, but must never error)
	if srv.GetForceEncryption().Error != nil {
		t.Errorf("forceEncryption: %v", srv.GetForceEncryption().Error)
	}
	if srv.GetExtendedProtection().Error != nil {
		t.Errorf("extendedProtection: %v", srv.GetExtendedProtection().Error)
	}
	if srv.GetHideInstance().Error != nil {
		t.Errorf("hideInstance: %v", srv.GetHideInstance().Error)
	}
	if srv.GetServiceAccount().Error != nil {
		t.Errorf("serviceAccount: %v", srv.GetServiceAccount().Error)
	}
	if srv.GetServiceAccountSid().Error != nil {
		t.Errorf("serviceAccountSid: %v", srv.GetServiceAccountSid().Error)
	}
	if srv.GetServicePrincipalNames().Error != nil {
		t.Errorf("servicePrincipalNames: %v", srv.GetServicePrincipalNames().Error)
	}
	if srv.GetErrorLogFileCount().Error != nil {
		t.Errorf("errorLogFileCount: %v", srv.GetErrorLogFileCount().Error)
	}
	if srv.GetLoginAuditLevel().Error != nil {
		t.Errorf("loginAuditLevel: %v", srv.GetLoginAuditLevel().Error)
	}

	resolveList(t, "configurations", srv.GetConfigurations())
	resolveList(t, "server.permissions", srv.GetPermissions())
	resolveList(t, "audits", srv.GetAudits())
	resolveList(t, "serverAuditSpecifications", srv.GetServerAuditSpecifications())

	for _, x := range resolveList(t, "logins", srv.GetLogins()) {
		l := x.(*mqlMssqlLogin)
		resolveList(t, "login.explicitPermissions", l.GetExplicitPermissions())
		resolveList(t, "login.memberOfRoles", l.GetMemberOfRoles())
		resolveList(t, "login.databaseUsers", l.GetDatabaseUsers())
	}
	for _, x := range resolveList(t, "roles", srv.GetRoles()) {
		r := x.(*mqlMssqlServerRole)
		resolveList(t, "serverRole.members", r.GetMembers())
		resolveList(t, "serverRole.memberOfRoles", r.GetMemberOfRoles())
		resolveList(t, "serverRole.explicitPermissions", r.GetExplicitPermissions())
	}
	for _, x := range resolveList(t, "credentials", srv.GetCredentials()) {
		resolveList(t, "credential.mappedLogins", x.(*mqlMssqlCredential).GetMappedLogins())
	}
	for _, x := range resolveList(t, "linkedServers", srv.GetLinkedServers()) {
		resolveList(t, "linkedServer.linkedLogins", x.(*mqlMssqlLinkedServer).GetLinkedLogins())
	}
	for _, x := range resolveList(t, "proxyAccounts", srv.GetProxyAccounts()) {
		resolveList(t, "proxyAccount.authorizedLogins", x.(*mqlMssqlProxyAccount).GetAuthorizedLogins())
	}

	for _, x := range resolveList(t, "databases", srv.GetDatabases()) {
		d := x.(*mqlMssqlDatabase)
		name := d.GetName().Data
		resolveList(t, name+".permissions", d.GetPermissions())
		resolveList(t, name+".scopedCredentials", d.GetScopedCredentials())
		resolveList(t, name+".symmetricKeys", d.GetSymmetricKeys())
		resolveList(t, name+".asymmetricKeys", d.GetAsymmetricKeys())
		resolveList(t, name+".clrAssemblies", d.GetClrAssemblies())
		resolveList(t, name+".auditSpecifications", d.GetAuditSpecifications())
		resolveList(t, name+".backups", d.GetBackups())
		for _, u := range resolveList(t, name+".users", d.GetUsers()) {
			du := u.(*mqlMssqlDatabaseUser)
			if login := du.GetLogin(); login.Error != nil {
				t.Errorf("%s user %q login errored: %v", name, du.GetName().Data, login.Error)
			}
			resolveList(t, name+".user.explicitPermissions", du.GetExplicitPermissions())
			resolveList(t, name+".user.memberOfRoles", du.GetMemberOfRoles())
		}
		for _, r := range resolveList(t, name+".roles", d.GetRoles()) {
			dr := r.(*mqlMssqlDatabaseRole)
			resolveList(t, name+".role.members", dr.GetMembers())
			resolveList(t, name+".role.memberOfRoles", dr.GetMemberOfRoles())
			resolveList(t, name+".role.explicitPermissions", dr.GetExplicitPermissions())
		}
		for _, a := range resolveList(t, name+".applicationRoles", d.GetApplicationRoles()) {
			ar := a.(*mqlMssqlApplicationRole)
			resolveList(t, name+".appRole.memberOfRoles", ar.GetMemberOfRoles())
			resolveList(t, name+".appRole.explicitPermissions", ar.GetExplicitPermissions())
		}
	}
}

func TestIntegrationDatabasesAndPrincipals(t *testing.T) {
	srv := mustServer(t, newIntegrationRuntime(t))

	dbs := srv.GetDatabases()
	if dbs.Error != nil {
		t.Fatalf("databases error: %v", dbs.Error)
	}
	var master *mqlMssqlDatabase
	names := map[string]bool{}
	for _, x := range dbs.Data {
		d := x.(*mqlMssqlDatabase)
		names[d.GetName().Data] = true
		if d.GetName().Data == "master" {
			master = d
		}
	}
	for _, want := range []string{"master", "msdb", "tempdb"} {
		if !names[want] {
			t.Errorf("system database %q not discovered", want)
		}
	}
	if master == nil {
		t.Fatal("master database not found")
	}

	users := master.GetUsers()
	if users.Error != nil {
		t.Fatalf("master users error: %v", users.Error)
	}
	hasGuest := false
	for _, x := range users.Data {
		if x.(*mqlMssqlDatabaseUser).GetName().Data == "guest" {
			hasGuest = true
		}
	}
	if !hasGuest {
		t.Error("guest user not found in master")
	}

	roles := master.GetRoles()
	if roles.Error != nil {
		t.Fatalf("master roles error: %v", roles.Error)
	}
	hasPublic := false
	for _, x := range roles.Data {
		if x.(*mqlMssqlDatabaseRole).GetName().Data == "public" {
			hasPublic = true
		}
	}
	if !hasPublic {
		t.Error("public role not found in master")
	}
}
