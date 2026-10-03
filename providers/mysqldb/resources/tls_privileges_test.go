// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// Values read live: have_ssl on MySQL 8.0 and MariaDB 10.1, and
// performance_schema.tls_channel_status on MySQL 9.7 (TLS required) and
// 26.7 (TLS off, while Current_tls_cert still names server-cert.pem).
func TestSslAvailable(t *testing.T) {
	cases := []struct {
		name                       string
		haveSSL                    string
		haveSSLSet                 bool
		channelEnabled, sessionTLS string
		want                       bool
	}{
		{"have_ssl YES", "YES", true, "", "", true},
		{"have_ssl DISABLED", "DISABLED", true, "", "", false},
		// have_ssl decides where it exists, even if this session used TLS
		{"have_ssl DISABLED wins", "DISABLED", true, "Yes", "TLSv1.3", false},
		{"8.4+ channel enabled", "", false, "Yes", "", true},
		{"8.4+ channel disabled", "", false, "No", "", false},
		{"8.4+ channel disabled over a TLS session", "", false, "No", "TLSv1.3", false},
		// tls_channel_status unreadable: this session's TLS proves TLS is on
		{"8.4+ unreadable, TLS session", "", false, "", "TLSv1.3", true},
		{"8.4+ unreadable, plain session", "", false, "", "", false},
	}
	for _, tc := range cases {
		if got := sslAvailable(tc.haveSSL, tc.haveSSLSet, tc.channelEnabled, tc.sessionTLS); got != tc.want {
			t.Errorf("%s: sslAvailable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Proc_priv values from mysql.procs_priv.
func TestRoutinePrivileges(t *testing.T) {
	got := routinePrivileges("mqlapp", "p_definer", "PROCEDURE", "Execute")
	if len(got) != 1 || got[0].privilegeType != "EXECUTE" || got[0].grantable ||
		got[0].scope != "ROUTINE" || got[0].routine != "p_definer" || got[0].routineType != "PROCEDURE" || got[0].schema != "mqlapp" {
		t.Errorf("Execute = %+v", got)
	}
	got = routinePrivileges("app", "f", "FUNCTION", "Execute,Alter Routine,Grant")
	if len(got) != 2 || got[0].privilegeType != "EXECUTE" || got[1].privilegeType != "ALTER ROUTINE" {
		t.Fatalf("Execute,Alter Routine,Grant = %+v", got)
	}
	for _, p := range got {
		if !p.grantable {
			t.Errorf("Grant in Proc_priv must make %s grantable", p.privilegeType)
		}
	}
	got = routinePrivileges("app", "f", "FUNCTION", "Grant")
	if len(got) != 1 || got[0].privilegeType != "GRANT OPTION" || !got[0].grantable {
		t.Errorf("Grant alone = %+v", got)
	}
	if got = routinePrivileges("app", "f", "FUNCTION", ""); len(got) != 0 {
		t.Errorf("empty Proc_priv = %+v", got)
	}
}

func TestObjectPrivilegeIDsDistinct(t *testing.T) {
	g := "'mqlapp'@'10.0.0.1'"
	ids := map[string]objectPrivilege{}
	for _, p := range []objectPrivilege{
		// column grants captured on MySQL 8.4: SELECT (c1), UPDATE (c2)
		{scope: "COLUMN", schema: "mqlapp", table: "t_innodb", column: "c1", privilegeType: "SELECT"},
		{scope: "COLUMN", schema: "mqlapp", table: "t_innodb", column: "c2", privilegeType: "SELECT"},
		// a procedure and a function may share a name
		{scope: "ROUTINE", schema: "mqlapp", routine: "r", routineType: "PROCEDURE", privilegeType: "EXECUTE"},
		{scope: "ROUTINE", schema: "mqlapp", routine: "r", routineType: "FUNCTION", privilegeType: "EXECUTE"},
		{scope: "PROXY", proxied: "'mqlsu'@'%'", privilegeType: "PROXY"},
		{scope: "PROXY", proxied: "''@''", privilegeType: "PROXY"},
	} {
		id := objectPrivilegeID("srv/user/mqlapp@10.0.0.1", g, p)
		if prev, ok := ids[id]; ok {
			t.Errorf("%+v and %+v share id %q", prev, p, id)
		}
		ids[id] = p
	}
}

func TestKeyringComponent(t *testing.T) {
	urn, ok := keyringComponent(map[string]string{
		"Component_name":      "component_keyring_file",
		"Author":              "Oracle Corporation",
		"Implementation_name": "component_keyring_file",
		"Component_status":    "Active",
	})
	if !ok || urn != "file://component_keyring_file" {
		t.Errorf("active keyring = %q, %v", urn, ok)
	}
	if componentName(urn) != "keyring_file" {
		t.Errorf("componentName(%q) = %q", urn, componentName(urn))
	}
	if _, ok := keyringComponent(map[string]string{"Component_name": "component_keyring_file", "Component_status": "Disabled"}); ok {
		t.Error("a disabled keyring component must not be listed")
	}
	if _, ok := keyringComponent(map[string]string{}); ok {
		t.Error("no status rows must not list a component")
	}
	if componentName("file://component_validate_password") != "validate_password" {
		t.Error("componentName lost the existing naming")
	}
}

func TestObjectPrivilegeIDSlashInNames(t *testing.T) {
	// schema "a/b" table "c" vs schema "a" table "b/c"
	a := objectPrivilegeID("p", "'u'@'%'", objectPrivilege{scope: "COLUMN", schema: "a/b", table: "c", column: "x", privilegeType: "SELECT"})
	b := objectPrivilegeID("p", "'u'@'%'", objectPrivilege{scope: "COLUMN", schema: "a", table: "b/c", column: "x", privilegeType: "SELECT"})
	if a == b {
		t.Errorf("names containing / collide: %q", a)
	}
}
