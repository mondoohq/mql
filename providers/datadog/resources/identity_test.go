// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"go.mondoo.com/mql/llx"
)

func testUser(id, handle, email string) datadogV2.User {
	attrs := datadogV2.NewUserAttributes()
	attrs.SetHandle(handle)
	attrs.SetEmail(email)

	u := datadogV2.NewUser()
	u.SetId(id)
	u.SetAttributes(*attrs)
	return *u
}

func TestUserIndexLookup(t *testing.T) {
	users := []datadogV2.User{
		testUser("id-1", "Alice@Example.com", "Alice@Example.com"),
		testUser("id-2", "bob", "bob@example.com"),
	}
	idx := newUserIndex(users)

	tests := []struct {
		name   string
		ref    string
		wantId string
		wantOk bool
	}{
		{"by id", "id-1", "id-1", true},
		{"by handle", "bob", "id-2", true},
		{"by email", "bob@example.com", "id-2", true},
		// Datadog echoes back whatever casing was entered, so a monitor's
		// creator email may not match the casing on the user record.
		{"by email, different casing", "ALICE@example.com", "id-1", true},
		{"by handle, different casing", "BOB", "id-2", true},
		{"unknown", "carol@example.com", "", false},
		{"empty", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := idx.lookup(tc.ref)
			if ok != tc.wantOk {
				t.Fatalf("expected ok %v, got %v", tc.wantOk, ok)
			}
			if !tc.wantOk {
				return
			}
			if got.GetId() != tc.wantId {
				t.Fatalf("expected user %q, got %q", tc.wantId, got.GetId())
			}
		})
	}
}

// A nil index must report a miss rather than panic: resolveUserRef reaches it
// through a fetch that returns nil when the users API is forbidden.
func TestUserIndexLookupNil(t *testing.T) {
	var idx *userIndex
	if _, ok := idx.lookup("id-1"); ok {
		t.Fatal("expected a miss for a nil index")
	}
}

// Users without a handle or email must not collide on the empty-string key,
// which would make an unrelated reference resolve to the wrong account.
func TestUserIndexSkipsEmptyKeys(t *testing.T) {
	idx := newUserIndex([]datadogV2.User{
		testUser("id-1", "", ""),
		testUser("id-2", "", ""),
	})
	if _, ok := idx.lookup(""); ok {
		t.Fatal("expected an empty reference to miss")
	}
	if len(idx.byHandle) != 0 || len(idx.byEmail) != 0 {
		t.Fatalf("expected no handle or email entries, got %d and %d", len(idx.byHandle), len(idx.byEmail))
	}
}

func TestUserRoleIds(t *testing.T) {
	roleData := datadogV2.NewRelationshipToRoleData()
	roleData.SetId("role-1")
	emptyRole := datadogV2.NewRelationshipToRoleData()

	roles := datadogV2.NewRelationshipToRoles()
	roles.SetData([]datadogV2.RelationshipToRoleData{*roleData, *emptyRole})

	rels := datadogV2.NewUserResponseRelationships()
	rels.SetRoles(*roles)

	u := testUser("id-1", "alice", "alice@example.com")
	u.SetRelationships(*rels)

	got := userRoleIds(u)
	if len(got) != 1 || got[0] != "role-1" {
		t.Fatalf("expected [role-1], got %v", got)
	}
}

// A user record with no relationships block must yield no role IDs rather than
// panic. The users API omits it entirely for some account types.
func TestUserRoleIdsMissingRelationships(t *testing.T) {
	if got := userRoleIds(testUser("id-1", "alice", "alice@example.com")); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}

	rels := datadogV2.NewUserResponseRelationships()
	u := testUser("id-2", "bob", "bob@example.com")
	u.SetRelationships(*rels)
	if got := userRoleIds(u); got != nil {
		t.Fatalf("expected nil for an empty relationships block, got %v", got)
	}
}

func TestUserTeamIds(t *testing.T) {
	teamData := datadogV2.NewRelationshipToUserTeamTeamData("team-1", datadogV2.USERTEAMTEAMTYPE_TEAM)
	userData := datadogV2.NewRelationshipToUserTeamUserData("user-1", datadogV2.USERTEAMUSERTYPE_USERS)

	rels := datadogV2.NewUserTeamRelationships()
	rels.SetTeam(*datadogV2.NewRelationshipToUserTeamTeam(*teamData))
	rels.SetUser(*datadogV2.NewRelationshipToUserTeamUser(*userData))

	membership := datadogV2.NewUserTeam("membership-1", datadogV2.USERTEAMTYPE_TEAM_MEMBERSHIPS)
	membership.SetRelationships(*rels)

	if got := userTeamId(*membership); got != "team-1" {
		t.Fatalf("expected team-1, got %q", got)
	}
	if got := userTeamUserId(*membership); got != "user-1" {
		t.Fatalf("expected user-1, got %q", got)
	}
}

// A membership with no relationships must return an empty ID, which the
// callers skip, rather than dereferencing a nil pointer.
func TestUserTeamIdsMissingRelationships(t *testing.T) {
	membership := datadogV2.NewUserTeam("membership-1", datadogV2.USERTEAMTYPE_TEAM_MEMBERSHIPS)
	if got := userTeamId(*membership); got != "" {
		t.Fatalf("expected an empty team ID, got %q", got)
	}
	if got := userTeamUserId(*membership); got != "" {
		t.Fatalf("expected an empty user ID, got %q", got)
	}

	membership.SetRelationships(*datadogV2.NewUserTeamRelationships())
	if got := userTeamId(*membership); got != "" {
		t.Fatalf("expected an empty team ID for an empty relationships block, got %q", got)
	}
	if got := userTeamUserId(*membership); got != "" {
		t.Fatalf("expected an empty user ID for an empty relationships block, got %q", got)
	}
}

func TestParseDatadogTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantNil bool
	}{
		{"RFC3339", "2024-01-02T03:04:05Z", time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), false},
		// The v1 organization endpoint reports a space separated timestamp
		// that time.Parse(time.RFC3339, ...) rejects outright.
		{"space separated", "2024-01-02 03:04:05", time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), false},
		{"date only", "2024-01-02", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC), false},
		{"empty", "", time.Time{}, true},
		{"unparseable", "not-a-timestamp", time.Time{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDatadogTime(tc.input)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected a non-nil time")
			}
			if !got.Equal(tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, *got)
			}
		})
	}
}

func TestStringArg(t *testing.T) {
	args := map[string]*llx.RawData{
		"id":    llx.StringData("abc"),
		"empty": llx.StringData(""),
		"count": llx.IntData(3),
		"nil":   nil,
	}

	tests := []struct {
		name   string
		key    string
		want   string
		wantOk bool
	}{
		{"present", "id", "abc", true},
		{"missing", "absent", "", false},
		{"empty value", "empty", "", false},
		{"wrong type", "count", "", false},
		{"nil entry", "nil", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := stringArg(args, tc.key)
			if ok != tc.wantOk || got != tc.want {
				t.Fatalf("expected (%q, %v), got (%q, %v)", tc.want, tc.wantOk, got, ok)
			}
		})
	}
}
