// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// TestApplicationRoleDecoding pins the JSON field names of an application role.
// defaultGroups and selectedByDefault are the pair that silently hands a product
// licence, and therefore a login, to every member of a group on invite: a
// mistyped tag on either would read as "no default groups, not selected", which
// is the answer an audit wants to see and would therefore never question.
func TestApplicationRoleDecoding(t *testing.T) {
	body := `{
	  "key": "jira-software",
	  "name": "Jira Software",
	  "groups": ["jira-software-users", "site-admins"],
	  "defaultGroups": ["jira-software-users"],
	  "selectedByDefault": true,
	  "defined": true,
	  "numberOfSeats": 250,
	  "remainingSeats": 12,
	  "userCount": 238,
	  "hasUnlimitedSeats": false,
	  "platform": false
	}`
	var role models.ApplicationRoleScheme
	require.NoError(t, json.Unmarshal([]byte(body), &role))

	assert.Equal(t, "jira-software", role.Key)
	assert.Equal(t, []string{"jira-software-users", "site-admins"}, role.Groups)
	assert.Equal(t, []string{"jira-software-users"}, role.DefaultGroups)
	assert.True(t, role.SelectedByDefault)
	assert.True(t, role.Defined)
	assert.Equal(t, 250, role.NumberOfSeats)
	assert.Equal(t, 12, role.RemainingSeats)
	assert.Equal(t, 238, role.UserCount)
	assert.False(t, role.HasUnlimitedSeats)
	assert.False(t, role.Platform)
}

// TestApplicationRoleUnlimitedSeats records what an unlimited-seat plan reports,
// so -1 is passed through rather than normalised into something that reads as a
// real seat count.
func TestApplicationRoleUnlimitedSeats(t *testing.T) {
	var role models.ApplicationRoleScheme
	require.NoError(t, json.Unmarshal(
		[]byte(`{"key":"jira-servicedesk","numberOfSeats":-1,"remainingSeats":-1,"hasUnlimitedSeats":true}`), &role))
	assert.Equal(t, -1, role.NumberOfSeats)
	assert.Equal(t, -1, role.RemainingSeats)
	assert.True(t, role.HasUnlimitedSeats)
}

// TestGroupMemberDecoding pins the fields that make a group member auditable.
// accountType is what separates a person from an app account, and active is what
// says whether a member named in a permission grant can still log in.
func TestGroupMemberDecoding(t *testing.T) {
	body := `{"values":[{
	  "accountId": "account-1",
	  "displayName": "Example Person",
	  "emailAddress": "person@example.invalid",
	  "active": true,
	  "accountType": "atlassian",
	  "timeZone": "Etc/UTC"
	},{
	  "accountId": "account-2",
	  "displayName": "Example App",
	  "active": false,
	  "accountType": "app"
	}],"isLast":true,"total":2}`
	var page models.GroupMemberPageScheme
	require.NoError(t, json.Unmarshal([]byte(body), &page))
	require.Len(t, page.Values, 2)

	assert.Equal(t, "account-1", page.Values[0].AccountID)
	assert.Equal(t, "person@example.invalid", page.Values[0].EmailAddress)
	assert.Equal(t, "atlassian", page.Values[0].AccountType)
	assert.True(t, page.Values[0].Active)
	assert.Equal(t, "Etc/UTC", page.Values[0].TimeZone)

	assert.Equal(t, "app", page.Values[1].AccountType)
	assert.False(t, page.Values[1].Active)
	assert.True(t, page.IsLast)
}

func memberPage(ids []string, isLast bool) *models.GroupMemberPageScheme {
	page := &models.GroupMemberPageScheme{IsLast: isLast}
	for _, id := range ids {
		page.Values = append(page.Values, &models.GroupUserDetailScheme{AccountID: id})
	}
	return page
}

func TestWalkJiraGroupMembers(t *testing.T) {
	// The endpoint caps its page size server-side, so a full group comes back in
	// pages shorter than the one requested. Stopping on a short page would have
	// truncated this group to its first page.
	t.Run("short pages are not the end of the list", func(t *testing.T) {
		pages := map[int]*models.GroupMemberPageScheme{
			0: memberPage([]string{"a1", "a2"}, false),
			2: memberPage([]string{"a3", "a4"}, false),
			4: memberPage([]string{"a5"}, true),
		}
		var seen []string
		var offsets []int
		err := walkJiraGroupMembers(
			func(startAt int) (*models.GroupMemberPageScheme, error) {
				offsets = append(offsets, startAt)
				return pages[startAt], nil
			},
			func(m *models.GroupUserDetailScheme) error {
				seen = append(seen, m.AccountID)
				return nil
			})
		require.NoError(t, err)
		assert.Equal(t, []string{"a1", "a2", "a3", "a4", "a5"}, seen)
		assert.Equal(t, []int{0, 2, 4}, offsets)
	})

	t.Run("an empty page ends the walk", func(t *testing.T) {
		calls := 0
		err := walkJiraGroupMembers(
			func(startAt int) (*models.GroupMemberPageScheme, error) {
				calls++
				return memberPage(nil, false), nil
			},
			func(m *models.GroupUserDetailScheme) error {
				t.Fatal("visit must not be called for an empty page")
				return nil
			})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	// A server that never sets isLast and keeps returning rows must not page
	// forever.
	t.Run("bounded when isLast never arrives", func(t *testing.T) {
		calls := 0
		err := walkJiraGroupMembers(
			func(startAt int) (*models.GroupMemberPageScheme, error) {
				calls++
				return memberPage([]string{"a" + strconv.Itoa(startAt)}, false), nil
			},
			func(m *models.GroupUserDetailScheme) error { return nil })
		require.NoError(t, err)
		assert.Equal(t, jiraGroupMemberMaxPages, calls)
	})

	t.Run("members with no account id are skipped", func(t *testing.T) {
		page := &models.GroupMemberPageScheme{IsLast: true, Values: []*models.GroupUserDetailScheme{
			nil, {AccountID: ""}, {AccountID: "a1"},
		}}
		var seen []string
		err := walkJiraGroupMembers(
			func(startAt int) (*models.GroupMemberPageScheme, error) { return page, nil },
			func(m *models.GroupUserDetailScheme) error {
				seen = append(seen, m.AccountID)
				return nil
			})
		require.NoError(t, err)
		assert.Equal(t, []string{"a1"}, seen)
	})
}

// TestSetScimUserFields covers the SCIM fields that carry the provisioning
// signal: externalId is the join key back to the identity provider, and the meta
// timestamps are how a stalled provisioning pipeline is detected.
func TestSetScimUserFields(t *testing.T) {
	t.Run("full record", func(t *testing.T) {
		body := `{
		  "id": "scim-1",
		  "externalId": "idp-0000",
		  "displayName": "Example Person",
		  "organization": "Example Org",
		  "title": "Engineer",
		  "active": true,
		  "name": {"formatted": "Example Person"},
		  "meta": {
		    "resourceType": "User",
		    "created": "2026-01-02T03:04:05.000Z",
		    "lastModified": "2026-02-03T04:05:06Z"
		  }
		}`
		var user models.SCIMUserScheme
		require.NoError(t, json.Unmarshal([]byte(body), &user))
		assert.Equal(t, "idp-0000", user.ExternalID)

		args := map[string]*llx.RawData{}
		setScimUserFields(args, &user)

		assert.Equal(t, "idp-0000", args["externalId"].Value)
		assert.Equal(t, "Example Person", args["displayName"].Value)
		assert.Equal(t, true, args["active"].Value)

		created, ok := args["created"].Value.(*time.Time)
		require.True(t, ok, "created must be a time, got %T", args["created"].Value)
		require.NotNil(t, created)
		assert.Equal(t, 2026, created.Year())
		assert.Equal(t, time.January, created.Month())

		modified, ok := args["lastModified"].Value.(*time.Time)
		require.True(t, ok)
		require.NotNil(t, modified)
		assert.Equal(t, time.February, modified.Month())
	})

	// A directory that sends no externalId and no meta must report nulls. A zero
	// time here would surface as 1 January year 1 and read as a real date, and an
	// empty externalId would look like a user the identity provider knows nothing
	// about rather than one it simply did not annotate.
	t.Run("absent optional values stay null", func(t *testing.T) {
		var user models.SCIMUserScheme
		require.NoError(t, json.Unmarshal([]byte(`{"id":"scim-2","displayName":"No Meta"}`), &user))
		require.Nil(t, user.Meta)

		args := map[string]*llx.RawData{}
		setScimUserFields(args, &user)

		assert.Nil(t, args["externalId"].Value)
		assert.Nil(t, args["created"].Value)
		assert.Nil(t, args["lastModified"].Value)
		// The name block is optional too and must not panic on absence.
		assert.Equal(t, "", args["name"].Value)
	})

	// An unparseable timestamp must stay null rather than degrade to the zero
	// time.
	t.Run("unparseable timestamps stay null", func(t *testing.T) {
		var user models.SCIMUserScheme
		require.NoError(t, json.Unmarshal(
			[]byte(`{"id":"scim-3","meta":{"created":"not-a-date","lastModified":""}}`), &user))
		args := map[string]*llx.RawData{}
		setScimUserFields(args, &user)
		assert.Nil(t, args["created"].Value)
		assert.Nil(t, args["lastModified"].Value)
	})

	// The list path and the single-user init path both go through this helper,
	// so the set of keys it writes is what keeps them from drifting apart. A
	// field one path sets and the other omits degrades to null for whichever
	// materializes the user first in a scan.
	t.Run("writes every non-id field", func(t *testing.T) {
		var user models.SCIMUserScheme
		require.NoError(t, json.Unmarshal([]byte(`{"id":"scim-4"}`), &user))
		args := map[string]*llx.RawData{}
		setScimUserFields(args, &user)
		for _, key := range []string{
			"name", "displayName", "organization", "title", "active",
			"externalId", "created", "lastModified",
		} {
			assert.Contains(t, args, key)
		}
	})
}
