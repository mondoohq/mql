// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResolveOktaResourceTarget(t *testing.T) {
	tests := []struct {
		name     string
		orn      string
		href     string
		wantType string
		wantID   string
	}{
		{
			name:     "group ORN",
			orn:      "orn:okta:directory:00o1a2b3c4:groups:00g5d6e7f8",
			wantType: "group",
			wantID:   "00g5d6e7f8",
		},
		{
			name:     "user ORN",
			orn:      "orn:okta:directory:00o1a2b3c4:users:00u9g8h7i6",
			wantType: "user",
			wantID:   "00u9g8h7i6",
		},
		{
			name:     "app ORN with app-type segment",
			orn:      "orn:okta:idp:00o1a2b3c4:apps:oidc:0oa1b2c3d4",
			wantType: "application",
			wantID:   "0oa1b2c3d4",
		},
		{
			name:     "group URL",
			href:     "https://example.okta.com/api/v1/groups/00g5d6e7f8",
			wantType: "group",
			wantID:   "00g5d6e7f8",
		},
		{
			name:     "user URL with trailing path",
			href:     "https://example.okta.com/api/v1/users/00u9g8h7i6/roles",
			wantType: "user",
			wantID:   "00u9g8h7i6",
		},
		{
			name:     "application URL",
			href:     "https://example.okta.com/api/v1/apps/0oa1b2c3d4",
			wantType: "application",
			wantID:   "0oa1b2c3d4",
		},
		{
			name:     "ORN preferred over href",
			orn:      "orn:okta:directory:00o1a2b3c4:groups:fromORN",
			href:     "https://example.okta.com/api/v1/users/fromHREF",
			wantType: "group",
			wantID:   "fromORN",
		},
		{
			name:     "resource-set entry self-link does not false-match",
			href:     "https://example.okta.com/api/v1/iam/resource-sets/iam1/resources/ires1",
			wantType: "",
			wantID:   "",
		},
		{
			name:     "empty inputs",
			wantType: "",
			wantID:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotID := resolveOktaResourceTarget(tc.orn, tc.href)
			assert.Equal(t, tc.wantType, gotType)
			assert.Equal(t, tc.wantID, gotID)
		})
	}
}

func TestOktaRoleIdFromPermissionsHref(t *testing.T) {
	tests := []struct {
		href string
		want string
	}{
		{"https://example.okta.com/api/v1/iam/roles/cr0AbCdEf/permissions", "cr0AbCdEf"},
		{"https://example.okta.com/api/v1/iam/roles/cr0AbCdEf/permissions/okta.users.read", "cr0AbCdEf"},
		// A bare roles href (no /permissions suffix) still yields the role id.
		{"https://example.okta.com/api/v1/iam/roles/cr0AbCdEf", "cr0AbCdEf"},
		{"https://example.okta.com/api/v1/apps/0oa1", ""},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, oktaRoleIdFromPermissionsHref(tc.href))
	}
}

func TestOktaLinkHref(t *testing.T) {
	assert.Equal(t, "https://x/api/v1/groups/g1",
		oktaLinkHref(map[string]any{"href": "https://x/api/v1/groups/g1"}))
	assert.Equal(t, "", oktaLinkHref(map[string]any{"noHref": "x"}))
	assert.Equal(t, "", oktaLinkHref("not-a-map"))
	assert.Equal(t, "", oktaLinkHref(nil))
}

func TestOktaOAuthClientID(t *testing.T) {
	tests := []struct {
		name  string
		creds any
		want  string
	}{
		{
			name: "OIDC app credentials",
			creds: map[string]any{
				"oauthClient": map[string]any{"client_id": "0oa1b2c3d4"},
			},
			want: "0oa1b2c3d4",
		},
		{
			name:  "non-oauth app (no oauthClient)",
			creds: map[string]any{"userNameTemplate": map[string]any{"type": "BUILT_IN"}},
			want:  "",
		},
		{
			name:  "oauthClient without client_id",
			creds: map[string]any{"oauthClient": map[string]any{"autoKeyRotation": true}},
			want:  "",
		},
		{name: "nil credentials", creds: nil, want: ""},
		{name: "wrong type", creds: "not-a-map", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, oktaOAuthClientID(tc.creds))
		})
	}
}

func TestLastPathSegment(t *testing.T) {
	assert.Equal(t, "g1", lastPathSegment("https://x/api/v1/groups/g1"))
	assert.Equal(t, "g1", lastPathSegment("https://x/api/v1/groups/g1/"))
	assert.Equal(t, "solo", lastPathSegment("solo"))
	assert.Equal(t, "", lastPathSegment(""))
}

// TestOktaTimeFromUnixMillis pins the conversion for a timestamp the SDK
// reports as Unix milliseconds.
//
// The absent case is the one that matters: an agent that has never connected,
// or whose timestamp the org does not report, must leave the field null. Zero
// would convert to 1 January 1970, which reads as a real connection date and
// would make every such agent look catastrophically stale to a policy
// comparing timestamps.
func TestOktaTimeFromUnixMillis(t *testing.T) {
	t.Parallel()

	assert.Nil(t, oktaTimeFromUnixMillis(nil), "an absent timestamp must stay null")

	ms := int64(1767326745000) // 2026-01-02T03:25:45Z
	got := oktaTimeFromUnixMillis(&ms)
	if assert.NotNil(t, got) {
		assert.Equal(t, 2026, got.Year())
		assert.Equal(t, 45, got.Second())
		assert.Equal(t, time.UTC, got.Location())
	}

	// A genuine zero is a real reading and is reported as the epoch, not
	// dropped: only absence is null.
	zero := int64(0)
	got = oktaTimeFromUnixMillis(&zero)
	if assert.NotNil(t, got) {
		assert.Equal(t, 1970, got.Year())
	}
}

// TestOktaStrFrom covers reads of values the SDK collected into
// AdditionalProperties, which is where fields the generated model stopped
// declaring now arrive.
func TestOktaStrFrom(t *testing.T) {
	t.Parallel()

	props := map[string]any{"status": "ACTIVE", "count": float64(3), "nil": nil}
	assert.Equal(t, "ACTIVE", oktaStrFrom(props["status"]))
	assert.Equal(t, "", oktaStrFrom(props["count"]), "a non-string must not be coerced")
	assert.Equal(t, "", oktaStrFrom(props["nil"]))
	assert.Equal(t, "", oktaStrFrom(props["absent"]), "a missing key reads empty")
}

func TestOktaAnySliceFrom(t *testing.T) {
	t.Parallel()

	props := map[string]any{"key_ops": []any{"sign", "verify"}, "scalar": "sign"}
	assert.Equal(t, []any{"sign", "verify"}, oktaAnySliceFrom(props["key_ops"]))
	assert.Equal(t, []any{}, oktaAnySliceFrom(props["scalar"]),
		"a non-list must yield an empty list, never a panic")
	assert.Equal(t, []any{}, oktaAnySliceFrom(props["absent"]))
}

// TestOktaStringMapFrom covers the inline-hook metadata read. A nested value
// is serialized rather than dropped, so a hook carrying structured metadata
// still reports it instead of showing an empty map.
func TestOktaStringMapFrom(t *testing.T) {
	t.Parallel()

	assert.Equal(t, map[string]any{}, oktaStringMapFrom(nil))
	assert.Equal(t, map[string]any{}, oktaStringMapFrom("not-an-object"))

	got := oktaStringMapFrom(map[string]any{
		"owner":  "platform",
		"empty":  nil,
		"nested": map[string]any{"a": "b"},
	})
	assert.Equal(t, "platform", got["owner"])
	assert.Equal(t, "", got["empty"])
	assert.Equal(t, `{"a":"b"}`, got["nested"])
}

// TestOktaInt64 covers the widening of an optional count.
//
// The nil case is the one worth pinning: an agent pool whose disrupted count
// the API does not report must leave the field null. A zero would assert that
// nothing is disrupted, which is the opposite reading and the one a health
// check would pass on.
func TestOktaInt64(t *testing.T) {
	t.Parallel()

	assert.Nil(t, oktaInt64(nil), "an unreported count must stay null")

	for _, n := range []int32{0, 1, 4096} {
		got := oktaInt64(&n)
		if assert.NotNil(t, got) {
			assert.Equal(t, int64(n), *got)
		}
	}
}
