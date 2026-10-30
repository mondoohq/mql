// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"go.mondoo.com/mql/providers/zoom/connection"
)

// The zoom.user resource decodes its records by struct tag alone and derives
// the `verified` and `ssoLinked` booleans from numeric fields. A mistyped tag
// or an off-by-one in a derivation compiles, lints, and yields a confident
// wrong answer rather than an error, so these tests pin the decoding and the
// derivations against payloads shaped like the documented API response.

func TestUserRecordDecodesFields(t *testing.T) {
	const payload = `{
		"id": "z9f8abc",
		"email": "jane@example.com",
		"first_name": "Jane",
		"last_name": "Doe",
		"display_name": "Jane Doe",
		"type": 2,
		"status": "active",
		"verified": 1,
		"login_types": [101],
		"role_id": "0",
		"group_ids": ["g1", "g2"],
		"last_login_time": "2024-01-02T03:04:05Z",
		"created_at": "2023-06-07T08:09:10Z"
	}`

	var u connection.User
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		t.Fatalf("failed to decode user payload: %v", err)
	}

	if u.ID != "z9f8abc" {
		t.Errorf("id: got %q, want %q", u.ID, "z9f8abc")
	}
	if u.Email != "jane@example.com" {
		t.Errorf("email: got %q, want %q", u.Email, "jane@example.com")
	}
	if u.Type != 2 {
		t.Errorf("type: got %d, want 2", u.Type)
	}
	if u.Status != "active" {
		t.Errorf("status: got %q, want %q", u.Status, "active")
	}
	if u.Verified != 1 {
		t.Errorf("verified: got %d, want 1", u.Verified)
	}
	// Zoom returns `login_types`, an array. Decoding the singular `login_type`
	// the docs once described leaves this empty on every user, which makes
	// ssoLinked false for every user and hands an auditor looking for accounts
	// that bypass SSO the entire user list.
	if len(u.LoginTypes) != 1 || u.LoginTypes[0] != 101 {
		t.Errorf("loginTypes: got %v, want [101]", u.LoginTypes)
	}
	if u.RoleID != "0" {
		t.Errorf("roleId: got %q, want %q", u.RoleID, "0")
	}
	if len(u.GroupIDs) != 2 || u.GroupIDs[0] != "g1" || u.GroupIDs[1] != "g2" {
		t.Errorf("groupIds: got %v, want [g1 g2]", u.GroupIDs)
	}
	if u.LastLoginTime == nil {
		t.Error("lastLoginTime: got nil, want a timestamp")
	}
	if u.CreatedAt == nil {
		t.Error("createdAt: got nil, want a timestamp")
	}
}

func TestUserRecordAbsentTimestampsStayNil(t *testing.T) {
	const payload = `{"id": "u1", "email": "sam@example.com", "type": 1, "status": "pending"}`

	var u connection.User
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		t.Fatalf("failed to decode user payload: %v", err)
	}

	// An absent timestamp must stay null rather than becoming the zero time,
	// which would report 1 January year 1 as a real login/creation date.
	if u.LastLoginTime != nil {
		t.Errorf("lastLoginTime: got %v, want nil", u.LastLoginTime)
	}
	if u.CreatedAt != nil {
		t.Errorf("createdAt: got %v, want nil", u.CreatedAt)
	}
}

func TestUserVerified(t *testing.T) {
	cases := []struct {
		name     string
		verified int
		want     bool
	}{
		{"unverified zero", 0, false},
		{"verified one", 1, true},
		{"any nonzero counts as verified", 2, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &connection.User{Verified: tc.verified}
			if got := userVerified(u); got != tc.want {
				t.Errorf("userVerified(%d): got %v, want %v", tc.verified, got, tc.want)
			}
		})
	}
}

func TestUserSsoLinked(t *testing.T) {
	cases := []struct {
		name       string
		loginTypes []int64
		want       bool
	}{
		{"sso", []int64{101}, true},
		{"sso alongside another method", []int64{1, 101}, true},
		{"zoom work email is not sso", []int64{100}, false},
		{"google oauth", []int64{1}, false},
		{"facebook oauth is not the zero default", []int64{0}, false},
		{"api user", []int64{99}, false},
		{"no method reported", nil, false},
		{"empty list", []int64{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &connection.User{LoginTypes: tc.loginTypes}
			if got := userSsoLinked(u); got != tc.want {
				t.Errorf("userSsoLinked(%v): got %v, want %v", tc.loginTypes, got, tc.want)
			}
		})
	}
}

// A user record that carries the singular `login_type` key the Zoom docs once
// described must not populate loginTypes: the API does not send it, and
// accepting it would hide the array decode regressing.
func TestUserRecordIgnoresSingularLoginType(t *testing.T) {
	const payload = `{"id": "u1", "email": "sam@example.com", "type": 2, "login_type": 101}`

	var u connection.User
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		t.Fatalf("failed to decode user payload: %v", err)
	}
	if len(u.LoginTypes) != 0 {
		t.Errorf("loginTypes: got %v, want empty", u.LoginTypes)
	}
	if userSsoLinked(&u) {
		t.Error("ssoLinked: got true, want false")
	}
}

// Zoom does not return an ID for a user in the pending status, so a roster
// that includes pending users cannot key every entry on the ID alone. Two
// pending users keyed on the same empty string would collide in the resource
// cache and the second would silently take on the first one's fields.
func TestUserCacheKey(t *testing.T) {
	tests := []struct {
		name string
		user connection.User
		want string
	}{
		{
			name: "an active user is keyed on its id",
			user: connection.User{ID: "z9f8abc", Email: "jane@example.com"},
			want: "z9f8abc",
		},
		{
			name: "a pending user has no id and is keyed on its email",
			user: connection.User{Email: "new@example.com"},
			want: "email/new@example.com",
		},
		{
			// The prefix is what keeps a user keyed by email from colliding
			// with a user whose ID happens to be that same string.
			name: "the email key is namespaced away from the id space",
			user: connection.User{ID: "email/new@example.com"},
			want: "email/new@example.com",
		},
		{
			name: "a record with neither is not addressable",
			user: connection.User{},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := userCacheKey(&tc.user); got != tc.want {
				t.Errorf("userCacheKey: got %q, want %q", got, tc.want)
			}
		})
	}
}

// created_at and user_created_at are different instants: Zoom documents the
// first as when the user's most recent login type was created and the second
// as when the user was provisioned. Decoding one into the other reports the
// wrong account age.
func TestUserRecordDecodesCreationTimestampsSeparately(t *testing.T) {
	const payload = `{
		"id": "z9f8abc",
		"created_at": "2024-05-06T07:08:09Z",
		"user_created_at": "2021-01-02T03:04:05Z",
		"last_client_version": "5.17.11.31580(mac)"
	}`

	var u connection.User
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		t.Fatalf("failed to decode user payload: %v", err)
	}

	if u.CreatedAt == nil || u.CreatedAt.Year() != 2024 {
		t.Errorf("createdAt: got %v, want 2024", u.CreatedAt)
	}
	if u.UserCreatedAt == nil || u.UserCreatedAt.Year() != 2021 {
		t.Errorf("userCreatedAt: got %v, want 2021", u.UserCreatedAt)
	}
	if u.LastClientVersion != "5.17.11.31580(mac)" {
		t.Errorf("lastClientVersion: got %q", u.LastClientVersion)
	}
}

// A user who has never signed in with a Zoom client reports no version and no
// provisioning timestamp; an absent timestamp must stay null rather than
// becoming the zero time, which would report 1 January year 1 as a real date.
func TestUserRecordAbsentProvisioningFields(t *testing.T) {
	var u connection.User
	if err := json.Unmarshal([]byte(`{"id": "z9f8abc"}`), &u); err != nil {
		t.Fatalf("failed to decode user payload: %v", err)
	}

	if u.UserCreatedAt != nil {
		t.Errorf("userCreatedAt: got %v, want nil", *u.UserCreatedAt)
	}
	if u.LastClientVersion != "" {
		t.Errorf("lastClientVersion: got %q, want empty", u.LastClientVersion)
	}
}
