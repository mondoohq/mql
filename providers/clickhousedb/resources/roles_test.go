// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

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
