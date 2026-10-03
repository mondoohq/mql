// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

// Rows below are the system.grants rows ClickHouse 26.9 holds for a user after
//
//	GRANT SELECT ON db5.* TO grantor WITH GRANT OPTION;
//	REVOKE GRANT OPTION FOR SELECT ON db5.t FROM grantor;
//
// for which SHOW GRANTS prints the two statements back.
func TestRenderGrant(t *testing.T) {
	cases := []struct {
		accessType, scope string
		partial, option   bool
		want              string
	}{
		{"SELECT", "db5.*", false, true, "SELECT ON db5.* WITH GRANT OPTION"},
		{"SELECT", "db5.t", true, true, "REVOKE GRANT OPTION FOR SELECT ON db5.t"},
		{"SELECT", "db5.t", true, false, "REVOKE SELECT ON db5.t"},
		{"ALL", "*.*", false, false, "ALL ON *.*"},
	}
	for _, c := range cases {
		if got := renderGrant(c.accessType, c.scope, c.partial, c.option); got != c.want {
			t.Errorf("renderGrant(%s, %s, partial=%v, option=%v) = %q, want %q",
				c.accessType, c.scope, c.partial, c.option, got, c.want)
		}
	}
}

// system.users rows read live from ClickHouse 26.9: an XML user with
// <password></password> and the XML default user with a real password both
// read auth_type ['plaintext_password'], storage users_xml.
func TestCredentialRequirement(t *testing.T) {
	cases := []struct {
		name      string
		authTypes []string
		storage   string
		want      bool
		known     bool
	}{
		{"xml plaintext, empty or real", []string{"plaintext_password"}, "users_xml", false, false},
		{"sql plaintext", []string{"plaintext_password"}, "local_directory", true, true},
		{"xml sha256", []string{"sha256_password"}, "users_xml", true, true},
		{"xml no_password", []string{"no_password"}, "users_xml", false, true},
		{"sql no_password", []string{"no_password"}, "local_directory", false, true},
		// a no_password method decides it whatever else the user has
		{"xml plaintext plus no_password", []string{"plaintext_password", "no_password"}, "users_xml", false, true},
		{"sql sha256", []string{"sha256_password"}, "local_directory", true, true},
	}
	for _, c := range cases {
		got, known := credentialRequirement(c.authTypes, c.storage)
		if known != c.known || (known && got != c.want) {
			t.Errorf("%s: credentialRequirement = %v, known=%v; want %v, known=%v", c.name, got, known, c.want, c.known)
		}
	}
}

// system.role_grants rows read live from ClickHouse 26.9: roleuser holds
// analyst, etl and limited; roleuser2 holds analyst and etl. A row names either
// a user or a role as the grantee.
func TestGroupRoleGrants(t *testing.T) {
	rows := []roleGrantRow{
		{user: "roleuser2", granted: "etl"},
		{user: "roleuser2", granted: "analyst"},
		{user: "roleuser", granted: "etl"},
		{user: "roleuser", granted: "analyst"},
		{user: "roleuser", granted: "limited"},
		{role: "analyst", granted: "limited"},
	}
	users, roles := groupRoleGrants(rows)
	if want := []string{"analyst", "etl", "limited"}; !reflect.DeepEqual(users["roleuser"], want) {
		t.Errorf("roleuser roles = %v, want %v", users["roleuser"], want)
	}
	if want := []string{"analyst", "etl"}; !reflect.DeepEqual(users["roleuser2"], want) {
		t.Errorf("roleuser2 roles = %v, want %v", users["roleuser2"], want)
	}
	if want := []string{"limited"}; !reflect.DeepEqual(roles["analyst"], want) {
		t.Errorf("analyst roles = %v, want %v", roles["analyst"], want)
	}
	if _, ok := users["analyst"]; ok {
		t.Error("a role grantee was filed as a user")
	}
}
