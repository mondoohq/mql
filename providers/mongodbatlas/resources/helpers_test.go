// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

func TestForEachPageStopsOnShortPage(t *testing.T) {
	pages := []int{pageSize, pageSize, 12}
	seen := []int{}
	err := forEachPage(func(page int) (int, error) {
		seen = append(seen, page)
		return pages[page-1], nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, seen)
}

func TestForEachPageStopsImmediatelyOnEmptyListing(t *testing.T) {
	calls := 0
	err := forEachPage(func(page int) (int, error) {
		calls++
		return 0, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

// An endpoint that ignores the page number answers with a full page forever.
// Without the bound this multiplies every record until the process dies; with
// it, the scan reports the endpoint instead.
func TestForEachPageBoundsAnEndpointThatIgnoresThePageNumber(t *testing.T) {
	calls := 0
	err := forEachPage(func(page int) (int, error) {
		calls++
		return pageSize, nil
	})
	require.Error(t, err)
	assert.Equal(t, maxPages, calls)
	assert.Contains(t, err.Error(), "did not terminate")
}

func TestForEachPagePropagatesError(t *testing.T) {
	boom := errors.New("boom")
	err := forEachPage(func(page int) (int, error) {
		return 0, boom
	})
	assert.ErrorIs(t, err, boom)
}

func TestHostOf(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"https url", "https://hooks.example.com/services/a/b", "hooks.example.com"},
		{"url with port", "https://collector.example.com:4317/v1/metrics", "collector.example.com:4317"},
		// The path and query are where a webhook token lives, so neither may
		// survive into the schema.
		{"token in path", "https://example.com/webhook/T0000/B0000/xoxbXXXXXXXXXXXX", "example.com"},
		{"token in query", "https://example.com/hook?key=abcdef123456", "example.com"},
		// Userinfo is a credential outright; url.Host excludes it.
		{"userinfo", "https://user:pass@example.com/hook", "example.com"},
		{"bare host", "collector.example.com", "collector.example.com"},
		{"bare host with port", "collector.example.com:4317", "collector.example.com:4317"},
		{"bare host with path", "collector.example.com:4317/v1/metrics", "collector.example.com:4317"},
		{"surrounding space", "  https://example.com/hook  ", "example.com"},
		{"scheme only", "https://", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hostOf(tt.in))
		})
	}
}

func TestHostPtrOf(t *testing.T) {
	assert.Nil(t, hostPtrOf(nil), "an address the API did not report stays null")

	empty := ""
	assert.Nil(t, hostPtrOf(&empty), "an empty address stays null rather than becoming an empty host")

	raw := "https://example.com/hook?key=secret"
	got := hostPtrOf(&raw)
	require.NotNil(t, got)
	assert.Equal(t, "example.com", *got)
}

func TestParseAtlasTime(t *testing.T) {
	assert.Nil(t, parseAtlasTime(nil), "an absent timestamp stays null")

	empty := "   "
	assert.Nil(t, parseAtlasTime(&empty))

	junk := "not a timestamp"
	assert.Nil(t, parseAtlasTime(&junk), "an unparseable timestamp stays null rather than becoming the zero time")

	for _, in := range []string{
		"2026-02-03T04:05:06Z",
		"2026-02-03T04:05:06.123Z",
		"2026-02-03T05:05:06+01:00",
	} {
		got := parseAtlasTime(&in)
		require.NotNil(t, got, in)
		assert.Equal(t, time.Date(2026, 2, 3, 4, 5, 6, got.Nanosecond(), time.UTC), got.UTC(), in)
	}
}

func TestIsSet(t *testing.T) {
	empty := ""
	value := "s3cr3t"
	assert.False(t, isSet(nil))
	assert.False(t, isSet(&empty))
	assert.True(t, isSet(&value))
}

func TestFirstBool(t *testing.T) {
	tr, fa := true, false
	assert.Nil(t, firstBool(nil, nil))

	got := firstBool(nil, &tr)
	require.NotNil(t, got)
	assert.True(t, *got)

	// The first reported value wins, including a reported false.
	got = firstBool(&fa, &tr)
	require.NotNil(t, got)
	assert.False(t, *got)
}

func TestSplitRoleAssignments(t *testing.T) {
	orgID := "org1"
	projectA := "proj-a"
	projectB := "proj-b"
	owner := "ORG_OWNER"
	groupOwner := "GROUP_OWNER"
	groupRead := "GROUP_READ_ONLY"
	empty := ""

	orgRoles, projectRoles, order := splitRoleAssignments([]admin.ConnectedOrgConfigRoleAssignment{
		{OrgId: &orgID, Role: &owner},
		{OrgId: &orgID, GroupId: &projectA, Role: &groupOwner},
		{OrgId: &orgID, GroupId: &projectA, Role: &groupRead},
		{OrgId: &orgID, GroupId: &projectB, Role: &groupRead},
		// An assignment with no role at all contributes nothing.
		{OrgId: &orgID, Role: &empty},
	})

	assert.Equal(t, []string{"ORG_OWNER"}, orgRoles)
	assert.Equal(t, map[string][]string{
		"proj-a": {"GROUP_OWNER", "GROUP_READ_ONLY"},
		"proj-b": {"GROUP_READ_ONLY"},
	}, projectRoles)
	assert.Equal(t, []string{"proj-a", "proj-b"}, order, "each project appears once, in the order it was first seen")
}

func TestSplitRoleAssignmentsEmpty(t *testing.T) {
	orgRoles, projectRoles, order := splitRoleAssignments(nil)
	assert.Equal(t, []string{}, orgRoles)
	assert.Empty(t, projectRoles)
	assert.Empty(t, order)
}
