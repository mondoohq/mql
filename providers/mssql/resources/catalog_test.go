// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"testing"

	"go.mondoo.com/mql/llx"
)

// Rows below were read live from SQL Server 2025 CU9 (sys.server_permissions,
// db4_app.sys.database_permissions and the audit specification details).

func TestPermissionIDDistinguishesSecurables(t *testing.T) {
	// GRANT IMPERSONATE ON LOGIN::sa and ON LOGIN::db4_auditor to the same
	// grantee: class 101, major_id 1 and 262
	sa := permissionResourceID("srv", "SERVER_PRINCIPAL", 1, 0, "IMPERSONATE", "GRANT", "db4_weak")
	aud := permissionResourceID("srv", "SERVER_PRINCIPAL", 262, 0, "IMPERSONATE", "GRANT", "db4_weak")
	if sa == aud {
		t.Errorf("IMPERSONATE on two logins share the id %q", sa)
	}
	// public's CONNECT on endpoints 2..5
	seen := map[string]bool{}
	for major := int64(2); major <= 5; major++ {
		id := permissionResourceID("srv", "ENDPOINT", major, 0, "CONNECT", "GRANT", "public")
		if seen[id] {
			t.Errorf("endpoint CONNECT id %q repeats", id)
		}
		seen[id] = true
	}
	// a column grant is a different securable than the table grant
	tbl := permissionResourceID("db", "OBJECT_OR_COLUMN", 1525580473, 0, "SELECT", "GRANT", "db4_nologin")
	col := permissionResourceID("db", "OBJECT_OR_COLUMN", 1525580473, 1, "SELECT", "GRANT", "db4_nologin")
	if tbl == col {
		t.Errorf("table and column grant share the id %q", tbl)
	}
}

func TestSecurableName(t *testing.T) {
	cases := []struct {
		class, database, resolved, want string
	}{
		{"SERVER", "", "", ""},
		{"SERVER_PRINCIPAL", "", "sa", "sa"},
		{"ENDPOINT", "", "TSQL Default TCP", "TSQL Default TCP"},
		{"DATABASE", "db4_app", "", "db4_app"},
		{"OBJECT_OR_COLUMN", "db4_app", "dbo.t1", "dbo.t1"},
		{"SCHEMA", "db4_app", "dbo", "dbo"},
	}
	for _, c := range cases {
		if got := securableName(c.class, c.database, c.resolved); got != c.want {
			t.Errorf("securableName(%q, %q, %q) = %q, want %q", c.class, c.database, c.resolved, got, c.want)
		}
	}
}

func TestAuditedAction(t *testing.T) {
	cases := []struct {
		name, class, securable, principal string
		isGroup                           bool
		want                              string
	}{
		{"DATABASE_ROLE_MEMBER_CHANGE_GROUP", "DATABASE", "db4_app", "public", true, "DATABASE_ROLE_MEMBER_CHANGE_GROUP"},
		{"SELECT", "OBJECT_OR_COLUMN", "dbo.t1", "public", false, "SELECT ON OBJECT::dbo.t1 BY public"},
		{"SELECT", "OBJECT_OR_COLUMN", "dbo.t2", "public", false, "SELECT ON OBJECT::dbo.t2 BY public"},
		{"EXECUTE", "SCHEMA", "dbo", "db4_dbrole", false, "EXECUTE ON SCHEMA::dbo BY db4_dbrole"},
		{"SELECT", "DATABASE", "db4_app", "public", false, "SELECT ON DATABASE::db4_app BY public"},
		{"FAILED_LOGIN_GROUP", "SERVER", "", "", true, "FAILED_LOGIN_GROUP"},
	}
	for _, c := range cases {
		if got := auditedAction(c.name, c.class, c.securable, c.principal, c.isGroup); got != c.want {
			t.Errorf("auditedAction(%q, %q, %q, %q, %v) = %q, want %q", c.name, c.class, c.securable, c.principal, c.isGroup, got, c.want)
		}
	}
	// the two object-level SELECT rows stay two entries
	a := auditedAction("SELECT", "OBJECT_OR_COLUMN", "dbo.t1", "public", false)
	b := auditedAction("SELECT", "OBJECT_OR_COLUMN", "dbo.t2", "public", false)
	if a == b {
		t.Errorf("object-level actions collapse to %q", a)
	}
}

func isNullField(fields map[string]*llx.RawData, key string) bool {
	v, ok := fields[key]
	return ok && v != nil && v.Value == nil
}

func TestLoginOptionalFieldsAreSetNull(t *testing.T) {
	// a certificate-mapped login: not AD, no sys.sql_logins row
	fields := map[string]*llx.RawData{}
	setLoginOptionalFields(fields, false, "##MS_PolicySigningCertificate##", "0x01",
		sql.NullBool{}, sql.NullBool{}, sql.NullInt64{})
	for _, key := range []string{"activeDirectoryPrincipal", "activeDirectorySid", "isPolicyChecked", "isExpirationChecked", "mustChange"} {
		if !isNullField(fields, key) {
			t.Errorf("%s = %v, want an explicit null", key, fields[key])
		}
	}

	// a SQL login with policy on and MUST_CHANGE set
	fields = map[string]*llx.RawData{}
	setLoginOptionalFields(fields, false, "db4_mustchg", "0xAB",
		sql.NullBool{Bool: true, Valid: true}, sql.NullBool{Bool: true, Valid: true}, sql.NullInt64{Int64: 1, Valid: true})
	if fields["isPolicyChecked"].Value != true || fields["isExpirationChecked"].Value != true || fields["mustChange"].Value != true {
		t.Errorf("SQL login fields = %v %v %v", fields["isPolicyChecked"], fields["isExpirationChecked"], fields["mustChange"])
	}
	if !isNullField(fields, "activeDirectoryPrincipal") {
		t.Error("a SQL login has no AD principal")
	}

	// a Windows login carries the AD identity
	fields = map[string]*llx.RawData{}
	setLoginOptionalFields(fields, true, `CONTOSO\alice`, "S-1-5-21-1-2-3-1001", sql.NullBool{}, sql.NullBool{}, sql.NullInt64{})
	if fields["activeDirectoryPrincipal"].Value != `CONTOSO\alice` || fields["activeDirectorySid"].Value != "S-1-5-21-1-2-3-1001" {
		t.Errorf("AD fields = %v %v", fields["activeDirectoryPrincipal"], fields["activeDirectorySid"])
	}
}

func TestNullableInt(t *testing.T) {
	if v := nullInt(sql.NullInt64{}); v.Value != nil {
		t.Errorf("nullInt(NULL) = %v, want null", v.Value)
	}
	if v := nullInt(sql.NullInt64{Int64: 264, Valid: true}); v.Value != int64(264) {
		t.Errorf("nullInt(264) = %v", v.Value)
	}
	if v := nullString(sql.NullString{}); v.Value != nil {
		t.Errorf("nullString(NULL) = %v, want null", v.Value)
	}
	if v := nullString(sql.NullString{String: "CU9", Valid: true}); v.Value != "CU9" {
		t.Errorf("nullString(CU9) = %v", v.Value)
	}
}
