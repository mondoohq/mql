// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeOktaAppLink pins the round trip through the SDK's AppLink. That
// struct types only the `login` and `logo` links, so every field this resource
// exposes reaches us through AdditionalProperties. Decoding straight off the
// SDK struct would leave all of them empty without erroring, which is why the
// tags are worth pinning against a payload shaped like the documented
// response.
func TestDecodeOktaAppLink(t *testing.T) {
	const payload = `{
		"id": "0oa1gjh63g214q0Hq0g4",
		"label": "Google Workspace",
		"linkUrl": "https://example.okta.com/home/google/0oa1gjh63g214q0Hq0g4/50",
		"logoUrl": "https://example.okta.com/img/logos/google.png",
		"appName": "google",
		"appInstanceId": "0oa1gjh63g214q0Hq0g4",
		"appAssignmentId": "0ua1gjh63g214q0Hq0g4",
		"credentialsSetup": true,
		"hidden": true,
		"sortOrder": 3,
		"_links": {"login": {"href": "https://example.okta.com/home/google/x"}}
	}`

	var src okta.AssignedAppLink
	require.NoError(t, json.Unmarshal([]byte(payload), &src))

	entry, err := decodeOktaAppLink(&src)
	require.NoError(t, err)

	assert.Equal(t, "0oa1gjh63g214q0Hq0g4", entry.Id)
	assert.Equal(t, "Google Workspace", entry.Label)
	assert.Equal(t, "https://example.okta.com/home/google/0oa1gjh63g214q0Hq0g4/50", entry.LinkUrl)
	assert.Equal(t, "https://example.okta.com/img/logos/google.png", entry.LogoUrl)
	assert.Equal(t, "google", entry.AppName)
	assert.Equal(t, "0oa1gjh63g214q0Hq0g4", entry.AppInstanceId)
	assert.Equal(t, "0ua1gjh63g214q0Hq0g4", entry.AppAssignmentId)
	assert.True(t, entry.CredentialsSetup)
	assert.True(t, entry.Hidden)
	assert.Equal(t, int64(3), entry.SortOrder)
}

// TestDecodeOktaAppLinkDefaults checks the readings an absent field produces.
// credentialsSetup and hidden must both read false when Okta omits them, since
// a hidden link that reported itself as visible, or an unconfigured one that
// reported credentials in place, would each invert what a review concludes.
func TestDecodeOktaAppLinkDefaults(t *testing.T) {
	var src okta.AssignedAppLink
	require.NoError(t, json.Unmarshal([]byte(`{"id": "0oa1", "label": "Bare"}`), &src))

	entry, err := decodeOktaAppLink(&src)
	require.NoError(t, err)

	assert.Equal(t, "0oa1", entry.Id)
	assert.False(t, entry.CredentialsSetup)
	assert.False(t, entry.Hidden)
	assert.Equal(t, int64(0), entry.SortOrder)
	assert.Empty(t, entry.AppInstanceId)
}

// TestOktaAppLinkAppInstanceId covers the fallback that keys the application
// reference. Okta repeats the application id as the link's own `id`, but only
// appInstanceId is documented to carry it, so the dedicated field wins and the
// link id stands in when it is absent. Getting this wrong resolves the
// reference against a non-existent id, which surfaces as a silently null
// application rather than an error.
func TestOktaAppLinkAppInstanceId(t *testing.T) {
	tests := []struct {
		name string
		link oktaAppLinkRaw
		want string
	}{
		{"prefers appInstanceId", oktaAppLinkRaw{Id: "0oaLink", AppInstanceId: "0oaApp"}, "0oaApp"},
		{"falls back to id", oktaAppLinkRaw{Id: "0oaLink"}, "0oaLink"},
		{"empty when neither is set", oktaAppLinkRaw{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.link.appInstanceId())
		})
	}
}

// TestOktaUserManagerId covers the profile attribute behind the manager
// reference, including the absent cases that must resolve to no reference at
// all rather than to an empty id.
func TestOktaUserManagerId(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"managerId set", `{"profile": {"login": "a@example.com", "managerId": "00uMgr"}}`, "00uMgr"},
		{"managerId absent", `{"profile": {"login": "a@example.com"}}`, ""},
		{"managerId null", `{"profile": {"login": "a@example.com", "managerId": null}}`, ""},
		{"no profile at all", `{"id": "00u1"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var user okta.User
			require.NoError(t, json.Unmarshal([]byte(tt.payload), &user))
			assert.Equal(t, tt.want, oktaUserManagerId(&user))
		})
	}
}

// TestOktaUserFromAnyKeepsRealmId guards the realm reference. realmId is read
// off the normalized user rather than from the resource fields, so a break in
// normalization would drop it without failing anything else.
func TestOktaUserFromAnyKeepsRealmId(t *testing.T) {
	const payload = `{"id": "00u1", "realmId": "guo1abc", "status": "ACTIVE"}`

	var m okta.User
	require.NoError(t, json.Unmarshal([]byte(payload), &m))

	user, err := oktaUserFromAny(&m)
	require.NoError(t, err)
	assert.Equal(t, "guo1abc", oktaStr(user.RealmId))

	// The fast path must carry it too.
	var direct okta.User
	require.NoError(t, json.Unmarshal([]byte(payload), &direct))
	same, err := oktaUserFromAny(&direct)
	require.NoError(t, err)
	assert.Equal(t, "guo1abc", oktaStr(same.RealmId))
}
